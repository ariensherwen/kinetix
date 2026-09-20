//! Admin API (FR-8.4). Every dashboard action is available here; the dashboard
//! is just a client. Protected by `AdminAuth`.

use std::sync::atomic::Ordering;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::adapters::UpstreamContext;
use crate::app::AppState;
use crate::auth::{self, AdminAuth, SESSION_COOKIE};
use crate::credentials::CredentialStrategy;
use crate::crypto;
use crate::db::{self, Pool};
use crate::frontends::FrontendFormat;
use crate::limits;
use crate::pipeline;
use crate::types::{AuthScheme, Capabilities, Prices, WireFormat};

type ApiResult = Result<Json<Value>, ApiError>;

pub struct ApiError(StatusCode, String);

impl ApiError {
    fn bad(msg: impl Into<String>) -> Self {
        ApiError(StatusCode::BAD_REQUEST, msg.into())
    }
    fn not_found(msg: impl Into<String>) -> Self {
        ApiError(StatusCode::NOT_FOUND, msg.into())
    }
    fn internal(e: impl std::fmt::Display) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

// ===========================================================================
// Auth / session
// ===========================================================================

#[derive(Deserialize)]
pub struct LoginBody {
    pub username: Option<String>,
    pub password: String,
}

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<LoginBody>,
) -> Result<(CookieJar, Json<Value>), ApiError> {
    // Admin authentication is a control-plane action: if the store is
    // unavailable it must fail closed, not fall through (NFR-2.7).
    if !db_healthy(&state).await {
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "admin authentication unavailable: control plane degraded".into(),
        ));
    }
    if !auth::verify_admin_password(&state, &body.password).await {
        let _ = db::insert_audit(
            &state.pool,
            "unknown",
            "admin_login_failed",
            "system",
            "",
            "Admin Console",
            "Rejected an admin login with an incorrect password.",
        )
        .await;
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "invalid admin password".into(),
        ));
    }
    // Sessions are in-memory with a TTL: a restart drops them all, so a browser
    // must log in again rather than staying signed in forever.
    let token = state.sessions.create();
    let cookie = Cookie::build((SESSION_COOKIE, token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .build();
    let actor = body.username.unwrap_or_else(|| "admin".to_string());
    let _ = db::insert_audit(
        &state.pool,
        &actor,
        "admin_login",
        "system",
        "",
        "Admin Console",
        "Administrator session started.",
    )
    .await;
    Ok((jar.add(cookie), Json(json!({ "ok": true, "user": actor }))))
}

pub async fn logout(State(state): State<AppState>, jar: CookieJar) -> (CookieJar, Json<Value>) {
    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "admin_logout",
        "system",
        "",
        "Admin Console",
        "Administrator session ended.",
    )
    .await;
    if let Some(c) = jar.get(SESSION_COOKIE) {
        state.sessions.revoke(c.value());
    }
    let cookie = Cookie::build((SESSION_COOKIE, "")).path("/").build();
    (jar.add(cookie), Json(json!({ "ok": true })))
}

/// `POST /admin/api/password` — change the dashboard password. Requires the
/// current password (so a hijacked session cannot silently rotate it), stores a
/// hash, and revokes every session including the caller's.
#[derive(serde::Deserialize)]
pub struct PasswordBody {
    current_password: String,
    new_password: String,
}

pub async fn change_password(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Json(body): Json<PasswordBody>,
) -> Result<Json<Value>, ApiError> {
    if !auth::verify_admin_password(&state, &body.current_password).await {
        let _ = db::insert_audit(
            &state.pool,
            "admin",
            "admin_password_change_failed",
            "system",
            "",
            "Admin Console",
            "Rejected a password change: current password incorrect.",
        )
        .await;
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "current password is incorrect".into(),
        ));
    }
    if body.new_password.trim().len() < 8 {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "new password must be at least 8 characters".into(),
        ));
    }
    auth::set_admin_password(&state, &body.new_password)
        .await
        .map_err(ApiError::internal)?;
    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "admin_password_changed",
        "system",
        "",
        "Admin Console",
        "Administrator password changed; all sessions invalidated.",
    )
    .await;
    Ok(Json(
        json!({ "ok": true, "note": "all sessions invalidated; please log in again" }),
    ))
}

pub async fn me(_auth: AdminAuth) -> Json<Value> {
    Json(json!({ "authenticated": true, "user": "admin" }))
}

/// `POST /admin/api/test-stream` — run a real request through the pipeline for a
/// chosen virtual key + model and stream the encoded result back to the
/// browser. The raw virtual key never leaves the server (it is stored hashed).
pub async fn test_stream(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Json(body): Json<TestStreamBody>,
) -> Response {
    let key = match db::get_virtual_key_by_id(&state.pool, &body.key_id)
        .await
        .map_err(ApiError::internal)
    {
        Ok(Some(k)) => k,
        Ok(None) => return ApiError::not_found("key not found").into_response(),
        Err(e) => return e.into_response(),
    };

    let format = if body.format.as_deref() == Some("anthropic") {
        FrontendFormat::Anthropic
    } else {
        FrontendFormat::OpenAi
    };
    let stream = body.stream.unwrap_or(true);

    // Build a minimal internal request from the tester form.
    let mut messages = Vec::new();
    if let Some(system) = body.system.filter(|s| !s.trim().is_empty()) {
        messages.push(crate::types::Message {
            role: crate::types::Role::System,
            parts: vec![crate::types::Part::Text(system)],
        });
    }
    messages.push(crate::types::Message {
        role: crate::types::Role::User,
        parts: vec![crate::types::Part::Text(body.prompt)],
    });

    let req = crate::types::InternalRequest {
        requested_model: body.model.clone(),
        system: vec![],
        messages,
        tools: vec![],
        tool_choice: None,
        tool_choice_name: None,
        params: crate::types::SamplingParams {
            max_tokens: body.max_tokens,
            temperature: body.temperature,
            ..Default::default()
        },
        stream,
        thinking: None,
        extra: Default::default(),
        raw_body: None,
    };

    let request_id = format!("req_{}", uuid::Uuid::new_v4().simple());
    if let Err(e) = limits::enforce(&state.pool, &key, &req.requested_model).await {
        return crate::api::error_response(format, &request_id, e);
    }

    match pipeline::run(
        &state,
        format,
        Some(key),
        req,
        request_id.clone(),
        true,
        None,
    )
    .await
    {
        Ok(resp) => resp,
        Err(e) => crate::api::error_response(format, &request_id, e),
    }
}

#[derive(Deserialize)]
pub struct TestStreamBody {
    pub key_id: String,
    pub model: String,
    pub prompt: String,
    #[serde(default)]
    pub system: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub stream: Option<bool>,
    #[serde(default)]
    pub max_tokens: Option<u32>,
    #[serde(default)]
    pub temperature: Option<f64>,
}

// ===========================================================================
// Overview / metrics
// ===========================================================================

pub async fn overview(State(state): State<AppState>, _auth: AdminAuth) -> ApiResult {
    let summary = db::usage_summary(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    let keys = db::list_virtual_keys(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    let accounts = db::list_accounts(&state.pool)
        .await
        .map_err(ApiError::internal)?;

    // Active streams comes from the in-memory live view (NFR-4.2), not the
    // usage-log queue depth.
    let active_streams = state.live.live_count();
    let fallback_rate = {
        let reqs = summary["requests"].as_i64().unwrap_or(0);
        let hops = summary["fallback_hops"].as_i64().unwrap_or(0);
        if reqs > 0 {
            hops as f64 / reqs as f64
        } else {
            0.0
        }
    };

    Ok(Json(json!({
        "active_streams": active_streams,
        "live_requests": state.live.snapshot().len(),
        "live_dropped": state.live.dropped(),
        "total_requests": summary["requests"],
        "total_tokens": summary["input_tokens"].as_i64().unwrap_or(0) + summary["output_tokens"].as_i64().unwrap_or(0),
        "total_spend_usd": summary["cost_usd"],
        "cached_tokens": summary["cached_tokens"],
        "thinking_tokens": summary["thinking_tokens"],
        "fallback_rate": fallback_rate,
        "avg_latency_ms": summary["avg_latency_ms"],
        "unknown_usage_requests": summary["unknown_usage_requests"],
        "estimated_usage_requests": summary["estimated_usage_requests"],
        "unknown_cost_requests": summary["unknown_cost_requests"],
        "keys_active": keys.iter().filter(|k| k.status == "active").count(),
        "keys_total": keys.len(),
        "accounts_healthy": accounts.iter().filter(|a| a.status == "healthy").count(),
        "accounts_total": accounts.len(),
        "log_queue_depth": state.log_queue.depth(),
        "log_queue_dropped": state.log_queue.dropped(),
        "uptime_secs": state.uptime_secs(),
        "tunnel_status": "connected",
    })))
}

// ===========================================================================
// Virtual keys
// ===========================================================================

pub async fn list_keys(State(state): State<AppState>, _auth: AdminAuth) -> ApiResult {
    let keys = db::list_virtual_keys(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    let (by_key, _) = db::lifetime_totals(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    let mut out = Vec::new();
    for k in keys {
        let (daily, monthly) = limits::spend_snapshot(&state.pool, &k).await;
        let (requests, tokens) = by_key.get(&k.id).copied().unwrap_or((0, 0));
        out.push(key_json(&k, daily, monthly, requests, tokens));
    }
    Ok(Json(json!({ "keys": out })))
}

fn key_json(
    k: &db::VirtualKeyRow,
    daily_spend: f64,
    monthly_spend: f64,
    total_requests: i64,
    total_tokens: i64,
) -> Value {
    json!({
        "id": k.id,
        "name": k.name,
        "owner": k.owner,
        "tag": k.tag,
        "allowed_models": k.allowed_models(),
        "allowed_providers": k.allowed_providers(),
        "rpm_limit": k.rpm_limit,
        "tpm_limit": k.tpm_limit,
        "daily_budget": k.daily_budget,
        "monthly_budget": k.monthly_budget,
        "current_daily_spend": daily_spend,
        "current_monthly_spend": monthly_spend,
        "expires_at": k.expires_at,
        "status": k.status,
        "allowed_ips": k.allowed_ips(),
        "body_logging": k.body_logging != 0,
        "created_at": k.created_at,
        "key_mask": mask_hash(&k.key_hash),
        "total_requests": total_requests,
        "total_tokens": total_tokens,
    })
}

fn mask_hash(_hash: &str) -> String {
    "sk-kinetix-•••• (hidden)".to_string()
}

#[derive(Deserialize)]
pub struct CreateKeyBody {
    pub name: String,
    pub owner: String,
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub allowed_models: Vec<String>,
    #[serde(default)]
    pub allowed_providers: Vec<String>,
    pub rpm_limit: Option<i64>,
    pub tpm_limit: Option<i64>,
    pub daily_budget: Option<f64>,
    pub monthly_budget: Option<f64>,
    pub expires_at: Option<String>,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub body_logging: bool,
}

pub async fn create_key(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Json(body): Json<CreateKeyBody>,
) -> ApiResult {
    let full_key = crypto::generate_virtual_key();
    let hash = crypto::hash_virtual_key(&full_key);
    let allowed = if body.allowed_models.is_empty() {
        vec!["*".to_string()]
    } else {
        body.allowed_models.clone()
    };
    let row = db::VirtualKeyRow {
        id: format!("key_{}", uuid::Uuid::new_v4().simple()),
        key_hash: hash,
        name: body.name.clone(),
        owner: body.owner.clone(),
        tag: body.tag.clone(),
        allowed_models: serde_json::to_string(&allowed).unwrap(),
        allowed_providers: serde_json::to_string(&body.allowed_providers).unwrap(),
        rpm_limit: body.rpm_limit,
        tpm_limit: body.tpm_limit,
        daily_budget: body.daily_budget,
        monthly_budget: body.monthly_budget,
        expires_at: body.expires_at.clone(),
        status: "active".to_string(),
        allowed_ips: serde_json::to_string(&body.allowed_ips).unwrap(),
        body_logging: body.body_logging as i64,
        created_at: db::now_iso(),
        revoked_at: None,
    };
    db::insert_virtual_key(&state.pool, &row)
        .await
        .map_err(ApiError::internal)?;
    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "key_created",
        "key",
        &row.id,
        &row.name,
        &format!("Issued virtual key for {} (owner {})", row.name, row.owner),
    )
    .await;
    // The full key is shown exactly once (FR-3.1).
    Ok(Json(json!({
        "key": key_json(&row, 0.0, 0.0, 0, 0),
        "full_key": full_key,
    })))
}

#[derive(Deserialize)]
pub struct UpdateKeyBody {
    pub status: Option<String>,
    pub name: Option<String>,
    pub owner: Option<String>,
    pub tag: Option<String>,
    pub allowed_models: Option<Vec<String>>,
    pub allowed_providers: Option<Vec<String>>,
    pub rpm_limit: Option<i64>,
    pub tpm_limit: Option<i64>,
    pub daily_budget: Option<f64>,
    pub monthly_budget: Option<f64>,
    pub expires_at: Option<String>,
    pub body_logging: Option<bool>,
    /// Per-key IP allowlist (FR-3.4). An explicit empty list clears it.
    pub allowed_ips: Option<Vec<String>>,
}

pub async fn update_key(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
    Json(body): Json<UpdateKeyBody>,
) -> ApiResult {
    if let Some(status) = &body.status {
        db::set_virtual_key_status(&state.pool, &id, status)
            .await
            .map_err(ApiError::internal)?;
        let _ = db::insert_audit(
            &state.pool,
            "admin",
            &format!("key_status_{status}"),
            "key",
            &id,
            "",
            &format!("Changed key status to {status}."),
        )
        .await;
    }
    // Field updates (limits/budgets/etc.) rebuild the row.
    let existing = db::list_virtual_keys(&state.pool)
        .await
        .map_err(ApiError::internal)?
        .into_iter()
        .find(|k| k.id == id)
        .ok_or_else(|| ApiError::not_found("key not found"))?;

    let name = body.name.unwrap_or(existing.name.clone());
    let owner = body.owner.unwrap_or(existing.owner.clone());
    let tag = body.tag.unwrap_or(existing.tag.clone());
    let allowed_models = body
        .allowed_models
        .map(|v| serde_json::to_string(&v).unwrap())
        .unwrap_or(existing.allowed_models.clone());
    let allowed_providers = body
        .allowed_providers
        .map(|v| serde_json::to_string(&v).unwrap())
        .unwrap_or(existing.allowed_providers.clone());
    let body_logging = body
        .body_logging
        .map(|b| b as i64)
        .unwrap_or(existing.body_logging);
    // FR-3.4: persist the per-key IP allowlist. Only touch it when provided,
    // so an update that omits it leaves the existing allowlist intact.
    let allowed_ips = body
        .allowed_ips
        .map(|v| serde_json::to_string(&v).unwrap())
        .unwrap_or(existing.allowed_ips.clone());

    sqlx::query(
        "UPDATE virtual_keys SET name=?, owner=?, tag=?, allowed_models=?, allowed_providers=?,
         rpm_limit=?, tpm_limit=?, daily_budget=?, monthly_budget=?, expires_at=?, body_logging=?, allowed_ips=? WHERE id=?",
    )
    .bind(name)
    .bind(owner)
    .bind(tag)
    .bind(allowed_models)
    .bind(allowed_providers)
    .bind(body.rpm_limit.or(existing.rpm_limit))
    .bind(body.tpm_limit.or(existing.tpm_limit))
    .bind(body.daily_budget.or(existing.daily_budget))
    .bind(body.monthly_budget.or(existing.monthly_budget))
    .bind(body.expires_at.or(existing.expires_at))
    .bind(body_logging)
    .bind(allowed_ips)
    .bind(&id)
    .execute(&state.pool)
    .await
    .map_err(ApiError::internal)?;

    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "key_updated",
        "key",
        &id,
        &existing.name,
        "Updated key limits/budgets.",
    )
    .await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn delete_key(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
) -> ApiResult {
    db::delete_virtual_key_cascade(&state.pool, &id)
        .await
        .map_err(ApiError::internal)?;
    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "key_deleted",
        "key",
        &id,
        "",
        "Deleted key.",
    )
    .await;
    Ok(Json(json!({ "ok": true })))
}

// ===========================================================================
// Providers
// ===========================================================================

/// FR-8.4: return a single provider's full configuration so the dashboard can
/// populate an edit form (list_providers is intentionally summary-shaped).
pub async fn get_provider(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
) -> ApiResult {
    let p = db::get_provider(&state.pool, &id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("provider not found"))?;
    Ok(Json(provider_json(&p)))
}

pub async fn list_providers(State(state): State<AppState>, _auth: AdminAuth) -> ApiResult {
    let providers = db::list_providers(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    let accounts = db::list_accounts(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    let models = db::list_models(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    let out: Vec<Value> = providers
        .iter()
        .map(|p| {
            let mut v = provider_json(p);
            v["accounts_count"] = json!(accounts.iter().filter(|a| a.provider_id == p.id).count());
            v["models_count"] = json!(models.iter().filter(|m| m.provider_id == p.id).count());
            v["healthy_accounts"] = json!(accounts
                .iter()
                .filter(|a| a.provider_id == p.id && a.status == "healthy")
                .count());
            v
        })
        .collect();
    Ok(Json(json!({ "providers": out })))
}

/// Full provider configuration (used by both the list and single-provider
/// endpoints). The dashboard's edit form is populated from this shape, so every
/// field an admin can set must be present here (FR-8.4/8.6).
fn provider_json(p: &db::ProviderRow) -> Value {
    json!({
        "id": p.id,
        "name": p.name,
        "base_url": p.base_url,
        "wire_format": p.wire_format,
        "auth_scheme": p.auth_scheme,
        "custom_header_name": p.custom_header_name,
        "custom_param_name": p.custom_param_name,
        "extra_headers": p.extra_headers_map(),
        "timeout_ms": p.timeout_ms,
        "capability_mode": p.capability_mode,
        "models_path": p.models_path,
        "enabled": p.enabled != 0,
        "follow_redirects": p.follow_redirects != 0,
        "credential_hosts": p.credential_hosts,
        "allow_insecure_tls": p.allow_insecure_tls != 0,
        "wire_plugin": p.wire_plugin,
        "credential_plugin": p.credential_plugin,
        "model_source_plugin": p.model_source_plugin,
        "created_at": p.created_at,
    })
}

#[derive(Deserialize)]
pub struct ProviderBody {
    pub name: String,
    pub base_url: String,
    pub wire_format: String,
    #[serde(default = "default_bearer")]
    pub auth_scheme: String,
    pub custom_header_name: Option<String>,
    pub custom_param_name: Option<String>,
    #[serde(default)]
    pub extra_headers: serde_json::Map<String, Value>,
    #[serde(default = "default_timeout")]
    pub timeout_ms: i64,
    #[serde(default = "default_permissive")]
    pub capability_mode: String,
    pub models_path: Option<String>,
    /// NFR-3.10: redirects are never followed unless explicitly enabled.
    #[serde(default)]
    pub follow_redirects: bool,
    /// NFR-3.11: comma-separated authorized hosts for the credential.
    #[serde(default)]
    pub credential_hosts: String,
    /// NFR-3.12: explicit dev-mode opt-out of TLS verification.
    #[serde(default)]
    pub allow_insecure_tls: bool,
    /// §6.0: plugin capability bindings (`plugin:<id>/<cap>` or empty).
    #[serde(default)]
    pub wire_plugin: String,
    #[serde(default)]
    pub credential_plugin: String,
    #[serde(default)]
    pub model_source_plugin: String,
    /// Optional initial credential.
    pub api_key: Option<String>,
    pub account_label: Option<String>,
}

fn default_bearer() -> String {
    "bearer".into()
}
fn default_timeout() -> i64 {
    120_000
}
fn default_permissive() -> String {
    "permissive".into()
}

async fn provider_plugin_binding_problems(state: &AppState, body: &ProviderBody) -> Vec<String> {
    use crate::plugins::Capability;

    let bindings = [
        (
            "wire_plugin",
            body.wire_plugin.as_str(),
            Capability::ProviderAdapter,
        ),
        (
            "credential_plugin",
            body.credential_plugin.as_str(),
            Capability::CredentialStrategy,
        ),
        (
            "model_source_plugin",
            body.model_source_plugin.as_str(),
            Capability::ModelSource,
        ),
    ];

    let mut problems = Vec::new();
    for (field, reference, capability) in bindings {
        let reference = reference.trim();
        if reference.is_empty() {
            continue;
        }
        if crate::plugins::PluginRef::parse(reference).is_none() {
            problems.push(format!(
                "{field} must use plugin:<id>/<capability-name> syntax"
            ));
            continue;
        }
        let Some(manager) = state.plugin_manager() else {
            problems.push(format!(
                "{field} references '{reference}' but the plugin host is unavailable"
            ));
            continue;
        };
        if manager
            .resolve_binding(reference, capability)
            .await
            .is_none()
        {
            problems.push(format!(
                "{field} reference '{reference}' does not resolve to an installed, enabled, approved plugin providing {}",
                capability.manifest_key()
            ));
        }
    }
    problems
}

pub async fn create_provider(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Json(body): Json<ProviderBody>,
) -> ApiResult {
    validate_outbound_url(&state, &body.base_url)?;
    let binding_problems = provider_plugin_binding_problems(&state, &body).await;
    if !binding_problems.is_empty() {
        return Err(ApiError::bad(binding_problems.join("; ")));
    }
    let wire =
        WireFormat::parse(&body.wire_format).ok_or_else(|| ApiError::bad("invalid wire_format"))?;
    let auth =
        AuthScheme::parse(&body.auth_scheme).ok_or_else(|| ApiError::bad("invalid auth_scheme"))?;

    let id = db::insert_provider(
        &state.pool,
        &db::NewProvider {
            name: &body.name,
            base_url: &body.base_url,
            wire_format: wire,
            auth_scheme: auth,
            custom_header_name: body.custom_header_name.as_deref(),
            custom_param_name: body.custom_param_name.as_deref(),
            extra_headers: Value::Object(body.extra_headers),
            timeout_ms: body.timeout_ms,
            capability_mode: &body.capability_mode,
            models_path: body.models_path.as_deref(),
            rate_limit_rules: json!({}),
            follow_redirects: body.follow_redirects,
            credential_hosts: &body.credential_hosts,
            allow_insecure_tls: body.allow_insecure_tls,
            wire_plugin: &body.wire_plugin,
            credential_plugin: &body.credential_plugin,
            model_source_plugin: &body.model_source_plugin,
        },
    )
    .await
    .map_err(ApiError::internal)?;

    if let Some(api_key) = body.api_key.filter(|k| !k.trim().is_empty()) {
        let enc = state.crypto.encrypt(&api_key).map_err(ApiError::internal)?;
        db::insert_account(
            &state.pool,
            &id,
            &account_label_or_default(&body.name, body.account_label.as_deref()),
            &enc,
            &crypto::mask_secret(&api_key),
            1,
            1,
            None,
            "none",
        )
        .await
        .map_err(ApiError::internal)?;
    }

    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "provider_created",
        "provider",
        &id,
        &body.name,
        &format!(
            "Added {} upstream ({} wire format at {}).",
            body.name, body.wire_format, body.base_url
        ),
    )
    .await;
    state
        .registry
        .reload(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "id": id })))
}

pub async fn update_provider(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
    Json(body): Json<ProviderBody>,
) -> ApiResult {
    validate_outbound_url(&state, &body.base_url)?;
    let binding_problems = provider_plugin_binding_problems(&state, &body).await;
    if !binding_problems.is_empty() {
        return Err(ApiError::bad(binding_problems.join("; ")));
    }
    let wire =
        WireFormat::parse(&body.wire_format).ok_or_else(|| ApiError::bad("invalid wire_format"))?;
    let auth =
        AuthScheme::parse(&body.auth_scheme).ok_or_else(|| ApiError::bad("invalid auth_scheme"))?;
    db::update_provider(
        &state.pool,
        &id,
        &body.name,
        &body.base_url,
        wire,
        auth,
        body.custom_header_name.as_deref(),
        body.custom_param_name.as_deref(),
        Value::Object(body.extra_headers),
        body.timeout_ms,
        &body.capability_mode,
        body.models_path.as_deref(),
        body.follow_redirects,
        &body.credential_hosts,
        body.allow_insecure_tls,
        &body.wire_plugin,
        &body.credential_plugin,
        &body.model_source_plugin,
    )
    .await
    .map_err(ApiError::internal)?;
    if let Some(api_key) = body.api_key.filter(|k| !k.trim().is_empty()) {
        let enc = state.crypto.encrypt(&api_key).map_err(ApiError::internal)?;
        db::insert_account(
            &state.pool,
            &id,
            &account_label_or_default(&body.name, body.account_label.as_deref()),
            &enc,
            &crypto::mask_secret(&api_key),
            1,
            1,
            None,
            "none",
        )
        .await
        .map_err(ApiError::internal)?;
    }
    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "provider_updated",
        "provider",
        &id,
        &body.name,
        "Updated provider configuration.",
    )
    .await;
    state
        .registry
        .reload(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn delete_provider(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
) -> ApiResult {
    db::delete_provider(&state.pool, &id)
        .await
        .map_err(ApiError::internal)?;
    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "provider_deleted",
        "provider",
        &id,
        "",
        "Deleted provider and its models/accounts.",
    )
    .await;
    state
        .registry
        .reload(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "ok": true })))
}

/// `POST /admin/api/providers/:id/discover` — fetch the upstream model list
/// using the provider's credentials (FR-10.4).
pub async fn discover_models(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
) -> ApiResult {
    let provider = db::get_provider(&state.pool, &id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("provider not found"))?;

    // A provider bound to a plugin model source (§6.2) discovers through that
    // plugin instead of the built-in adapter. A bound-but-unavailable plugin
    // fails closed rather than silently falling back to native discovery
    // (§6.0).
    let discovered: Vec<crate::adapters::DiscoveredModel> =
        if let Some(pref) = provider.model_source_plugin_ref() {
            let manager = plugin_manager(&state)?;
            let reference = format!("plugin:{}/{}", pref.plugin_id, pref.capability);
            if manager
                .resolve_binding(&reference, crate::plugins::Capability::ModelSource)
                .await
                .is_none()
            {
                return Err(ApiError::bad(format!(
                    "provider is bound to unavailable plugin model source '{reference}'"
                )));
            }
            let models_path = provider.models_path.clone().unwrap_or_default();
            let list = manager
                .model_discover(
                    &pref.plugin_id,
                    &provider.id,
                    &provider.base_url,
                    &models_path,
                )
                .await
                .map_err(|f| {
                    ApiError::bad(format!(
                        "plugin model discovery failed: {}",
                        crate::crypto::redact(&f.message())
                    ))
                })?;
            list.into_iter()
                .map(|m| crate::adapters::DiscoveredModel {
                    id: m.id,
                    display_name: m.display_name,
                    context_window: m.context_window.map(|v| v as i64),
                    max_output_tokens: m.max_output_tokens.map(|v| v as i64),
                })
                .collect()
        } else {
            discover_models_native(&state, &provider).await?
        };

    // Mark which are already imported and record the observation (FR-10.5).
    // Discovery never overwrites admin-edited fields — only the `discovery`
    // column is written — and a model that has disappeared upstream is flagged,
    // not deleted.
    let existing = db::models_for_provider(&state.pool, &id)
        .await
        .map_err(ApiError::internal)?;
    let now = db::now_iso();
    let discovered_ids: std::collections::HashSet<String> =
        discovered.iter().map(|m| m.id.clone()).collect();
    let mut out: Vec<Value> = Vec::new();
    for m in &discovered {
        if let Some(row) = existing.iter().find(|e| e.upstream_id == m.id) {
            let _ = db::set_model_discovery(
                &state.pool,
                &row.id,
                &json!({
                    "last_seen": now,
                    "context_window": m.context_window,
                    "max_output_tokens": m.max_output_tokens,
                    "display_name": m.display_name,
                    "disappeared": false,
                }),
            )
            .await;
        }
        out.push(json!({
            "id": m.id,
            "display_name": m.display_name,
            "context_window": m.context_window,
            "max_output_tokens": m.max_output_tokens,
            "already_imported": existing.iter().any(|e| e.upstream_id == m.id),
        }));
    }
    // Flag imported models that are no longer advertised upstream.
    let mut disappeared: Vec<Value> = Vec::new();
    for row in &existing {
        if discovered_ids.contains(&row.upstream_id) {
            continue;
        }
        let prev: Value = serde_json::from_str(&row.discovery).unwrap_or(json!({}));
        let mut merged = prev.clone();
        merged["disappeared"] = json!(true);
        merged["flagged_at"] = json!(now);
        let _ = db::set_model_discovery(&state.pool, &row.id, &merged).await;
        disappeared.push(json!({
            "upstream_id": row.upstream_id,
            "display_name": row.display_name,
            "model_id": row.id,
        }));
    }
    Ok(Json(json!({ "models": out, "disappeared": disappeared })))
}

/// Built-in adapter discovery: resolve a credential, call the provider's models
/// endpoint, and parse the list. Extracted so the plugin path can share the
/// surrounding import/flag logic.
async fn discover_models_native(
    state: &AppState,
    provider: &db::ProviderRow,
) -> Result<Vec<crate::adapters::DiscoveredModel>, ApiError> {
    let accounts = db::accounts_for_provider(&state.pool, &provider.id)
        .await
        .map_err(ApiError::internal)?;
    let account = accounts
        .into_iter()
        .next()
        .ok_or_else(|| ApiError::bad("provider has no credentials to discover with"))?;
    let credential = state
        .credential_for(provider, &account)
        .await
        .map(|c| {
            crate::alerts::record_credential_success();
            c
        })
        .map_err(|e| {
            crate::alerts::record_credential_failure();
            ApiError::internal(e)
        })?
        .secret;

    let wire = provider.wire();
    let adapter = state.adapters.for_provider(provider);
    let path = provider
        .models_path
        .clone()
        .unwrap_or_else(|| adapter.default_models_path().to_string());
    let base = provider.base_url.trim_end_matches('/');
    let url = if path.starts_with('/') {
        format!("{base}{path}")
    } else {
        format!("{base}/{path}")
    };
    let _ = wire;

    let dummy_model = db::ModelRow {
        id: "discovery".into(),
        provider_id: provider.id.clone(),
        upstream_id: "discovery".into(),
        display_name: "discovery".into(),
        enabled: 1,
        context_window: None,
        max_output_tokens: None,
        capabilities: "{}".into(),
        prices: "{}".into(),
        parameters: "{}".into(),
        thinking_map: "{}".into(),
        extra_request: "{}".into(),
        discovery: "{}".into(),
        created_at: db::now_iso(),
        opaque_state_plugin: String::new(),
    };
    let ctx = UpstreamContext {
        provider,
        model: &dummy_model,
        credential,
    };
    let mut req = state
        .http
        .get(&url)
        .timeout(std::time::Duration::from_millis(provider.timeout_ms as u64));
    req = adapter.apply_auth(&ctx, req);
    for (k, v) in provider.extra_headers_map() {
        req = req.header(k, v);
    }

    let resp = req.send().await.map_err(|e| {
        ApiError::bad(format!(
            "discovery request failed: {}",
            crate::crypto::redact(&e.to_string())
        ))
    })?;
    let status = resp.status();
    let body_text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(ApiError::bad(format!(
            "upstream returned HTTP {}: {}",
            status.as_u16(),
            crate::crypto::redact(&truncate(&body_text, 400))
        )));
    }
    let parsed: Value = serde_json::from_str(&body_text)
        .map_err(|e| ApiError::bad(format!("invalid discovery response: {e}")))?;
    Ok(adapter.parse_model_list(&parsed))
}

/// `POST /admin/api/providers/:id/test` — send a minimal probe (FR-10.11).
pub async fn test_provider(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
    Json(body): Json<TestBody>,
) -> ApiResult {
    let provider = db::get_provider(&state.pool, &id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("provider not found"))?;
    let accounts = db::accounts_for_provider(&state.pool, &id)
        .await
        .map_err(ApiError::internal)?;
    let account = accounts
        .into_iter()
        .next()
        .ok_or_else(|| ApiError::bad("provider has no credentials to test with"))?;
    let credential = state
        .credentials
        .resolve(&account)
        .await
        .map(|c| {
            crate::alerts::record_credential_success();
            c
        })
        .map_err(|e| {
            crate::alerts::record_credential_failure();
            ApiError::internal(e)
        })?
        .secret;

    let upstream_id = body
        .model
        .clone()
        .ok_or_else(|| ApiError::bad("provide a model to test"))?;
    let model = db::find_model_by_upstream(&state.pool, &id, &upstream_id)
        .await
        .map_err(ApiError::internal)?
        .unwrap_or_else(|| db::ModelRow {
            id: "probe".into(),
            provider_id: id.clone(),
            upstream_id: upstream_id.clone(),
            display_name: upstream_id.clone(),
            enabled: 1,
            context_window: None,
            max_output_tokens: Some(64),
            capabilities: "{}".into(),
            prices: "{}".into(),
            parameters: "{}".into(),
            thinking_map: "{}".into(),
            extra_request: "{}".into(),
            discovery: "{}".into(),
            created_at: db::now_iso(),
            opaque_state_plugin: String::new(),
        });

    let adapter = state.adapters.for_format(provider.wire());
    let ctx = UpstreamContext {
        provider: &provider,
        model: &model,
        credential,
    };
    let mut internal = crate::types::InternalRequest {
        requested_model: upstream_id.clone(),
        system: vec![],
        messages: vec![crate::types::Message {
            role: crate::types::Role::User,
            parts: vec![crate::types::Part::Text(
                "Reply with the single word: ok".into(),
            )],
        }],
        tools: vec![],
        tool_choice: None,
        tool_choice_name: None,
        params: crate::types::SamplingParams {
            max_tokens: Some(64),
            ..Default::default()
        },
        stream: false,
        thinking: None,
        extra: Default::default(),
        raw_body: None,
    };
    internal.stream = false;

    let url = adapter
        .build_url(&ctx)
        .map_err(|e| ApiError::bad(e.message))?;
    let outbound = adapter.build_body(&ctx, &internal);
    let mut req = state
        .http
        .post(&url)
        .header("content-type", "application/json")
        .timeout(std::time::Duration::from_millis(provider.timeout_ms as u64))
        .json(&outbound);
    req = adapter.apply_auth(&ctx, req);
    for (k, v) in provider.extra_headers_map() {
        req = req.header(k, v);
    }

    let started = std::time::Instant::now();
    match req.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let latency = started.elapsed().as_millis() as i64;
            if !(200..300).contains(&status) {
                let text = resp.text().await.unwrap_or_default();
                let failure = adapter.classify_error(status, &text, &axum::http::HeaderMap::new());
                return Ok(Json(json!({
                    "ok": false, "status": status, "latency_ms": latency,
                    "error": failure.message,
                })));
            }
            // Read a bounded amount of the (possibly streaming) response so a
            // probe never hangs on a long-lived SSE connection (FR-10.11).
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let preview = read_probe_preview(resp, content_type.contains("event-stream")).await;
            Ok(Json(json!({
                "ok": true, "status": status, "latency_ms": latency,
                "response_preview": truncate(&preview, 400),
            })))
        }
        Err(e) => Ok(Json(json!({
            "ok": false, "status": 0,
            "error": crate::crypto::redact(&e.to_string()),
        }))),
    }
}

/// Read a bounded probe response. For SSE, parse the frames and return the
/// concatenated text deltas; otherwise return the (bounded) body text.
async fn read_probe_preview(resp: reqwest::Response, sse: bool) -> String {
    use futures::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    let mut framer = crate::sse::SseFramer::new();
    let mut text = String::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let next = tokio::time::timeout_at(deadline, stream.next()).await;
        let chunk = match next {
            Ok(Some(Ok(c))) => c,
            Ok(Some(Err(_))) | Ok(None) => break,
            Err(_) => break, // bounded read; a probe must not hang
        };
        if !sse {
            buf.extend_from_slice(&chunk);
            if buf.len() > 8192 {
                break;
            }
            continue;
        }
        for frame in framer.push(&chunk) {
            if let Some(data) = crate::sse::extract_data(&frame) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) {
                    // OpenAI shape (text, then reasoning as a fallback label)
                    if let Some(c) = v
                        .pointer("/choices/0/delta/content")
                        .and_then(|c| c.as_str())
                    {
                        text.push_str(c);
                    } else if let Some(r) = v
                        .pointer("/choices/0/delta/reasoning_content")
                        .and_then(|c| c.as_str())
                    {
                        if !r.is_empty() && !text.starts_with("[reasoning] ") {
                            text = format!("[reasoning] {text}");
                        }
                    }
                    // Gemini shape
                    if let Some(parts) = v
                        .pointer("/candidates/0/content/parts")
                        .and_then(|p| p.as_array())
                    {
                        for p in parts {
                            if let Some(t) = p.get("text").and_then(|t| t.as_str()) {
                                text.push_str(t);
                            }
                        }
                    }
                }
            }
        }
        if !text.trim_start_matches("[reasoning] ").is_empty() || buf.len() > 8192 {
            break;
        }
    }
    if sse {
        if text.is_empty() {
            "[streaming response: no text delta within the probe window]".to_string()
        } else {
            text
        }
    } else {
        String::from_utf8_lossy(&buf).to_string()
    }
}

#[derive(Deserialize)]
pub struct TestBody {
    pub model: Option<String>,
}

// ===========================================================================
// Models
// ===========================================================================

pub async fn list_models(State(state): State<AppState>, _auth: AdminAuth) -> ApiResult {
    let models = db::list_models(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    let providers = db::list_providers(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    let out: Vec<Value> = models.iter().map(|m| model_json(m, &providers)).collect();
    Ok(Json(json!({ "models": out })))
}

fn model_json(m: &db::ModelRow, providers: &[db::ProviderRow]) -> Value {
    let provider_name = providers
        .iter()
        .find(|p| p.id == m.provider_id)
        .map(|p| p.name.clone())
        .unwrap_or_default();
    json!({
        "id": m.id,
        "provider_id": m.provider_id,
        "provider_name": provider_name,
        "upstream_id": m.upstream_id,
        "display_name": m.display_name,
        "enabled": m.enabled != 0,
        "context_window": m.context_window,
        "max_output_tokens": m.max_output_tokens,
        "capabilities": m.caps(),
        "prices": m.prices(),
        "parameters": m.params(),
        "thinking_map": m.thinking(),
        "extra_request": m.extra_request_value(),
        // Discovery-suggested values (FR-10.5). Surfaced so an admin can see
        // what the last discovery observed, including models that have since
        // disappeared upstream (flagged, never silently deleted).
        "discovery": serde_json::from_str::<Value>(&m.discovery).unwrap_or(json!({})),
    })
}

#[derive(Deserialize)]
pub struct ModelBody {
    pub upstream_id: String,
    pub display_name: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub context_window: Option<i64>,
    pub max_output_tokens: Option<i64>,
    #[serde(default)]
    pub capabilities: Value,
    #[serde(default)]
    pub prices: Value,
    #[serde(default)]
    pub parameters: Value,
    #[serde(default)]
    pub thinking_map: Value,
    #[serde(default)]
    pub extra_request: Value,
}

fn default_true() -> bool {
    true
}

pub async fn create_model(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(provider_id): Path<String>,
    Json(body): Json<ModelBody>,
) -> ApiResult {
    let _ = db::get_provider(&state.pool, &provider_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("provider not found"))?;
    let caps: Capabilities = serde_json::from_value(body.capabilities.clone()).unwrap_or_default();
    let prices: Prices = serde_json::from_value(body.prices.clone()).unwrap_or_default();

    let id = db::insert_model(
        &state.pool,
        &db::NewModel {
            provider_id: &provider_id,
            upstream_id: &body.upstream_id,
            display_name: body.display_name.as_deref().unwrap_or(&body.upstream_id),
            enabled: body.enabled,
            context_window: body.context_window,
            max_output_tokens: body.max_output_tokens,
            capabilities: serde_json::to_value(&caps).unwrap(),
            prices: serde_json::to_value(&prices).unwrap(),
            parameters: body.parameters.clone(),
            thinking_map: body.thinking_map.clone(),
            extra_request: body.extra_request.clone(),
            discovery: json!({}),
        },
    )
    .await
    .map_err(ApiError::internal)?;
    if prices.is_configured() {
        let _ = db::insert_price_version(&state.pool, &id, &prices).await;
    }
    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "model_configured",
        "model",
        &id,
        &body.upstream_id,
        "Configured upstream model.",
    )
    .await;
    state
        .registry
        .reload(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "id": id })))
}

pub async fn update_model(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
    Json(body): Json<ModelBody>,
) -> ApiResult {
    let caps: Capabilities = serde_json::from_value(body.capabilities.clone()).unwrap_or_default();
    let prices: Prices = serde_json::from_value(body.prices.clone()).unwrap_or_default();
    db::update_model(
        &state.pool,
        &id,
        body.display_name.as_deref().unwrap_or(&body.upstream_id),
        body.enabled,
        body.context_window,
        body.max_output_tokens,
        serde_json::to_value(&caps).unwrap(),
        serde_json::to_value(&prices).unwrap(),
        body.parameters.clone(),
        body.thinking_map.clone(),
        body.extra_request.clone(),
    )
    .await
    .map_err(ApiError::internal)?;
    if prices.is_configured() {
        let _ = db::insert_price_version(&state.pool, &id, &prices).await;
    }
    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "model_updated",
        "model",
        &id,
        &body.upstream_id,
        "Updated model configuration.",
    )
    .await;
    state
        .registry
        .reload(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn delete_model(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
) -> ApiResult {
    db::delete_model(&state.pool, &id)
        .await
        .map_err(ApiError::internal)?;
    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "model_deleted",
        "model",
        &id,
        "",
        "Removed model.",
    )
    .await;
    state
        .registry
        .reload(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "ok": true })))
}

// ===========================================================================
// Accounts
// ===========================================================================

pub async fn list_accounts(State(state): State<AppState>, _auth: AdminAuth) -> ApiResult {
    let accounts = db::list_accounts(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    let providers = db::list_providers(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    let (_, by_account) = db::lifetime_totals(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    let out: Vec<Value> = accounts
        .iter()
        .map(|a| {
            let (requests, tokens) = by_account.get(&a.id).copied().unwrap_or((0, 0));
            account_json(a, &providers, requests, tokens)
        })
        .collect();
    Ok(Json(json!({ "accounts": out })))
}

fn account_json(
    a: &db::AccountRow,
    providers: &[db::ProviderRow],
    requests_count: i64,
    tokens_count: i64,
) -> Value {
    let provider_name = providers
        .iter()
        .find(|p| p.id == a.provider_id)
        .map(|p| p.name.clone())
        .unwrap_or_default();
    json!({
        "id": a.id,
        "provider_id": a.provider_id,
        "provider_name": provider_name,
        "label": a.label,
        "key_mask": a.key_mask,
        "status": a.status,
        "cooldown_until": a.cooldown_until,
        "quota_reset_at": a.quota_reset_at,
        "quota_type": a.quota_type,
        "soft_quota_usd": a.soft_quota_usd,
        "priority": a.priority,
        "weight": a.weight,
        "last_error": a.last_error,
        "created_at": a.created_at,
        "requests_count": requests_count,
        "tokens_count": tokens_count,
    })
}

#[derive(Deserialize)]
pub struct AccountBody {
    pub provider_id: String,
    pub label: String,
    pub api_key: Option<String>,
    #[serde(default = "one")]
    pub priority: i64,
    #[serde(default = "one")]
    pub weight: i64,
    pub soft_quota_usd: Option<f64>,
    #[serde(default = "default_quota_type")]
    pub quota_type: String,
    pub status: Option<String>,
}

fn one() -> i64 {
    1
}
fn default_quota_type() -> String {
    "none".into()
}

pub async fn create_account(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Json(body): Json<AccountBody>,
) -> ApiResult {
    let api_key = body
        .api_key
        .clone()
        .filter(|k| !k.trim().is_empty())
        .ok_or_else(|| ApiError::bad("api_key is required"))?;
    let enc = state.crypto.encrypt(&api_key).map_err(ApiError::internal)?;
    let id = db::insert_account(
        &state.pool,
        &body.provider_id,
        &body.label,
        &enc,
        &crypto::mask_secret(&api_key),
        body.priority,
        body.weight,
        body.soft_quota_usd,
        &body.quota_type,
    )
    .await
    .map_err(ApiError::internal)?;
    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "account_credential_added",
        "account",
        &id,
        &body.label,
        "Enrolled a new credential into the pool.",
    )
    .await;
    state
        .registry
        .reload(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "id": id })))
}

pub async fn update_account(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
    Json(body): Json<AccountBody>,
) -> ApiResult {
    db::update_account(
        &state.pool,
        &id,
        &body.label,
        body.status.as_deref().unwrap_or("healthy"),
        body.priority,
        body.weight,
        body.soft_quota_usd,
        &body.quota_type,
    )
    .await
    .map_err(ApiError::internal)?;
    // Optionally rotate the credential.
    if let Some(api_key) = body.api_key.filter(|k| !k.trim().is_empty()) {
        let enc = state.crypto.encrypt(&api_key).map_err(ApiError::internal)?;
        sqlx::query("UPDATE accounts SET secret_enc=?, key_mask=? WHERE id=?")
            .bind(enc)
            .bind(crypto::mask_secret(&api_key))
            .bind(&id)
            .execute(&state.pool)
            .await
            .map_err(ApiError::internal)?;
    }
    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "account_updated",
        "account",
        &id,
        &body.label,
        "Updated account configuration.",
    )
    .await;
    state
        .registry
        .reload(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "ok": true })))
}

/// `POST /admin/api/accounts/:id/reset` — clear cooldown/exhaustion.
pub async fn reset_account(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
) -> ApiResult {
    crate::pool::mark_healthy(&state.pool, &id)
        .await
        .map_err(ApiError::internal)?;
    let _ = crate::pool::clear_circuit(&state.pool, &id).await;
    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "account_reset",
        "account",
        &id,
        "",
        "Cleared cooldown/exhaustion/circuit state.",
    )
    .await;
    state
        .registry
        .reload(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn delete_account(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
) -> ApiResult {
    db::delete_account(&state.pool, &id)
        .await
        .map_err(ApiError::internal)?;
    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "account_credential_removed",
        "account",
        &id,
        "",
        "Removed credential from the pool.",
    )
    .await;
    state
        .registry
        .reload(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "ok": true })))
}

// ===========================================================================
// Routes
// ===========================================================================

pub async fn list_routes(State(state): State<AppState>, _auth: AdminAuth) -> ApiResult {
    let routes = db::list_routes(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    let accounts = db::list_accounts(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    let models = db::list_models(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    let mut out = Vec::new();
    for c in &routes {
        let targets = db::route_targets(&state.pool, &c.id)
            .await
            .map_err(ApiError::internal)?;
        let targets_json: Vec<Value> = targets
            .iter()
            .map(|t| {
                let model = models.iter().find(|m| m.id == t.model_id);
                let account = t.account_id.as_ref().and_then(|aid| accounts.iter().find(|a| a.id == *aid));
                json!({
                    "id": t.id,
                    "account_id": t.account_id,
                    "account_label": account.map(|a| a.label.clone()),
                    "model_id": t.model_id,
                    "model_display_name": model.map(|m| m.display_name.clone()),
                    "provider_id": model.map(|m| m.provider_id.clone()),
                    "priority": t.priority,
                    "weight": t.weight,
                    "predicate": serde_json::from_str::<Value>(&t.predicate).unwrap_or(json!({})),
                    "param_overrides": serde_json::from_str::<Value>(&t.param_overrides).unwrap_or(json!({})),
                })
            })
            .collect();
        out.push(json!({
            "id": c.id,
            "name": c.name,
            "description": c.description,
            "strategy": c.strategy,
            "fallback_triggers": serde_json::from_str::<Value>(&c.fallback_triggers).unwrap_or(json!({})),
            "continuity_policy": c.continuity_policy,
            "portability_policy": c.portability_policy,
            "sticky_routing": c.sticky_routing != 0,
            "cache_affinity": c.cache_affinity != 0,
            "max_attempts": c.max_attempts,
            "enabled": c.enabled != 0,
            "targets": targets_json,
        }));
    }
    Ok(Json(json!({ "routes": out })))
}

#[derive(Deserialize)]
pub struct RouteBody {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "priority_strategy")]
    pub strategy: String,
    #[serde(default)]
    pub fallback_triggers: Value,
    #[serde(default = "strip_policy")]
    pub continuity_policy: String,
    /// FR-2.11: reject | strip_with_warning.
    #[serde(default = "portability_default")]
    pub portability_policy: String,
    #[serde(default)]
    pub sticky_routing: bool,
    /// FR-7.3: cache-aware sticky routing.
    #[serde(default)]
    pub cache_affinity: bool,
    pub max_attempts: Option<i64>,
    #[serde(default)]
    pub targets: Vec<RouteTargetBody>,
}

fn priority_strategy() -> String {
    "priority".into()
}
fn strip_policy() -> String {
    "strip".into()
}
fn portability_default() -> String {
    "strip_with_warning".into()
}

#[derive(Deserialize)]
pub struct RouteTargetBody {
    pub account_id: Option<String>,
    pub model_id: String,
    #[serde(default = "one")]
    pub priority: i64,
    #[serde(default = "one")]
    pub weight: i64,
    /// Typed eligibility predicate (FR-12.3). Empty/absent = always eligible.
    #[serde(default)]
    pub predicate: Value,
    /// Per-target parameter overrides (FR-12.2).
    #[serde(default)]
    pub param_overrides: Value,
}

pub async fn create_route(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Json(body): Json<RouteBody>,
) -> ApiResult {
    let id = db::insert_route(
        &state.pool,
        &db::NewRoute {
            name: &body.name,
            description: &body.description,
            strategy: &body.strategy,
            fallback_triggers: if body.fallback_triggers.is_null() {
                json!({"on429": true, "onQuota": true, "on5xx": true, "onTimeout": true})
            } else {
                body.fallback_triggers.clone()
            },
            continuity_policy: &body.continuity_policy,
            portability_policy: &body.portability_policy,
            sticky_routing: body.sticky_routing,
            cache_affinity: body.cache_affinity,
            max_attempts: body.max_attempts,
        },
    )
    .await
    .map_err(ApiError::internal)?;
    write_route_targets(&state.pool, &id, &body.targets).await?;
    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "route_created",
        "route",
        &id,
        &body.name,
        &format!("Created route with {} targets.", body.targets.len()),
    )
    .await;
    state
        .registry
        .reload(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "id": id })))
}

pub async fn update_route(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
    Json(body): Json<RouteBody>,
) -> ApiResult {
    db::update_route(
        &state.pool,
        &id,
        &body.description,
        &body.strategy,
        body.fallback_triggers.clone(),
        &body.continuity_policy,
        &body.portability_policy,
        body.sticky_routing,
        body.cache_affinity,
        body.max_attempts,
    )
    .await
    .map_err(ApiError::internal)?;
    db::clear_route_targets(&state.pool, &id)
        .await
        .map_err(ApiError::internal)?;
    write_route_targets(&state.pool, &id, &body.targets).await?;
    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "route_updated",
        "route",
        &id,
        &body.name,
        "Updated route configuration.",
    )
    .await;
    state
        .registry
        .reload(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "ok": true })))
}

async fn write_route_targets(
    pool: &Pool,
    route_id: &str,
    targets: &[RouteTargetBody],
) -> Result<(), ApiError> {
    for t in targets {
        let predicate = if t.predicate.is_null() {
            "{}".to_string()
        } else {
            t.predicate.to_string()
        };
        let overrides = if t.param_overrides.is_null() {
            "{}".to_string()
        } else {
            t.param_overrides.to_string()
        };
        db::insert_route_target(
            pool,
            route_id,
            t.account_id.as_deref(),
            &t.model_id,
            t.priority,
            t.weight,
            &predicate,
            &overrides,
        )
        .await
        .map_err(ApiError::internal)?;
    }
    Ok(())
}

pub async fn delete_route(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
) -> ApiResult {
    db::delete_route(&state.pool, &id)
        .await
        .map_err(ApiError::internal)?;
    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "route_deleted",
        "route",
        &id,
        "",
        "Deleted route.",
    )
    .await;
    state
        .registry
        .reload(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "ok": true })))
}

/// `POST /admin/api/routes/dry-run` (FR-8.7): evaluate routing for a
/// representative request descriptor without mutating anything.
#[derive(Deserialize)]
pub struct DryRunBody {
    pub model: String,
    #[serde(flatten, default)]
    pub descriptor: pipeline::DryRunRequest,
}

pub async fn dry_run_route(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Json(body): Json<DryRunBody>,
) -> ApiResult {
    let out = pipeline::dry_run(&state, &body.model, &body.descriptor)
        .await
        .map_err(|e| ApiError::bad(e.message))?;
    Ok(Json(out))
}

/// `POST /admin/api/validate` (FR-8.6): validate a provider endpoint (schema,
/// TLS/SSRF, credential-host binding) and, optionally, connectivity + resolved
/// IP/ASN. Never mutates production state.
#[derive(Deserialize)]
pub struct ValidateBody {
    pub base_url: String,
    #[serde(default)]
    pub check_connectivity: bool,
}

/// `POST /admin/api/validate/provider` (FR-8.6): full schema + outbound-security
/// validation of a proposed provider, without creating it.
pub async fn validate_provider(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Json(body): Json<ProviderBody>,
) -> ApiResult {
    let mut problems = crate::validate::validate_provider_schema(
        &body.name,
        &body.base_url,
        &body.wire_format,
        &body.auth_scheme,
        body.custom_header_name.as_deref(),
        body.custom_param_name.as_deref(),
    );
    problems.extend(provider_plugin_binding_problems(&state, &body).await);
    let mut warnings: Vec<String> = Vec::new();
    let mut security: Value = Value::String("not_checked".into());
    if body.base_url.trim().is_empty() {
        // already reported as a schema problem
    } else {
        match validate_outbound_url(&state, &body.base_url) {
            Ok(()) => security = Value::String("passed".into()),
            Err(ApiError(_, msg)) => problems.push(msg),
        }
    }
    if body.wire_format == "anthropic"
        && !body
            .extra_headers
            .keys()
            .any(|k| k.eq_ignore_ascii_case("anthropic-version"))
    {
        warnings.push(
            "anthropic wire format: set an 'anthropic-version' extra header (Kinetix adds no hidden defaults)"
                .into(),
        );
    }
    // Credential-host binding (NFR-3.11): the credential is bound to the
    // provider's base host plus any explicitly authorized hosts. Flag malformed
    // entries (a scheme/path/port is not a host) so a misconfigured binding is
    // caught before Apply.
    let mut binding: Vec<String> = Vec::new();
    if let Ok(parsed) = url::Url::parse(&body.base_url) {
        if let Some(h) = parsed.host_str() {
            binding.push(h.to_string());
        }
    }
    for entry in body.credential_hosts.split(',') {
        let host = entry.trim();
        if host.is_empty() {
            continue;
        }
        if host.contains('/') || host.contains(' ') || host.contains("://") {
            problems.push(format!(
                "credential_hosts entry '{host}' is not a bare host (drop the scheme/path)"
            ));
        } else {
            binding.push(host.to_string());
        }
    }
    Ok(Json(json!({
        "valid": problems.is_empty(),
        "problems": problems,
        "warnings": warnings,
        "outbound_security": security,
        "credential_host_binding": binding,
        "note": "Validate only: no provider was created and no upstream call was made (FR-8.6).",
    })))
}

/// `POST /admin/api/validate/model` (FR-8.6): schema + metadata validation of a
/// proposed model (unknown price/capability data reported, never assumed).
pub async fn validate_model_edit(
    State(_state): State<AppState>,
    _auth: AdminAuth,
    Json(body): Json<ModelBody>,
) -> ApiResult {
    let out = crate::validate::validate_model(
        &body.upstream_id,
        body.context_window,
        body.max_output_tokens,
        &body.capabilities,
        &body.prices,
        &body.parameters,
    );
    Ok(Json(out))
}

/// `POST /admin/api/validate/account` (FR-8.6): schema validation of a proposed
/// account. The credential is not stored; only its presence is checked.
pub async fn validate_account_edit(
    State(_state): State<AppState>,
    _auth: AdminAuth,
    Json(body): Json<AccountBody>,
) -> ApiResult {
    let problems =
        crate::validate::validate_account(&body.label, body.api_key.as_deref(), &body.quota_type);
    Ok(Json(json!({
        "valid": problems.is_empty(),
        "problems": problems,
        "note": "Validate only: no account was created (FR-8.6).",
    })))
}

pub async fn validate_endpoint(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Json(body): Json<ValidateBody>,
) -> ApiResult {
    validate_outbound_url(&state, &body.base_url)?;
    let parsed =
        url::Url::parse(&body.base_url).map_err(|e| ApiError::bad(format!("invalid URL: {e}")))?;
    let host = parsed.host_str().unwrap_or("").to_string();
    let mut resolved: Vec<String> = Vec::new();
    let mut asn: Value = Value::String("unknown".into());
    let mut reachable: Value = Value::String("not_checked".into());
    if body.check_connectivity {
        let port = parsed.port_or_known_default().unwrap_or(443);
        match tokio::net::lookup_host((host.as_str(), port)).await {
            Ok(addrs) => {
                for a in addrs {
                    resolved.push(a.ip().to_string());
                }
                reachable = Value::Bool(true);
            }
            Err(e) => {
                reachable = Value::String(format!("dns_error: {e}"));
            }
        }
        // ASN lookup is not implemented; the requirement says show unknown
        // rather than guess (FR-8.8).
        asn = Value::String("unknown".into());
    }
    Ok(Json(json!({
        "valid": true,
        "scheme": parsed.scheme(),
        "host": host,
        "resolved_ips": resolved,
        "asn": asn,
        "connectivity": reachable,
        "note": "ASN is reported as unknown when it cannot be established; Kinetix never guesses (FR-8.8)."
    })))
}

// ===========================================================================
// Aliases
// ===========================================================================

pub async fn list_aliases(State(state): State<AppState>, _auth: AdminAuth) -> ApiResult {
    let aliases = db::list_aliases(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    let models = db::list_models(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    let routes = db::list_routes(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    let out: Vec<Value> = aliases
        .iter()
        .map(|a| {
            let display = if a.target_type == "route" {
                routes
                    .iter()
                    .find(|c| c.id == a.target_id)
                    .map(|c| format!("Route: {}", c.name))
            } else {
                models
                    .iter()
                    .find(|m| m.id == a.target_id)
                    .map(|m| format!("Model: {}", m.display_name))
            };
            json!({
                "id": a.id,
                "alias": a.alias,
                "target_type": a.target_type,
                "target_id": a.target_id,
                "target_display_name": display,
                "description": a.description,
            })
        })
        .collect();
    Ok(Json(json!({ "aliases": out })))
}

#[derive(Deserialize)]
pub struct AliasBody {
    pub alias: String,
    pub target_type: String,
    pub target_id: String,
    #[serde(default)]
    pub description: String,
}

pub async fn create_alias(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Json(body): Json<AliasBody>,
) -> ApiResult {
    let id = db::upsert_alias(
        &state.pool,
        &body.alias,
        &body.target_type,
        &body.target_id,
        &body.description,
    )
    .await
    .map_err(ApiError::internal)?;
    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "alias_upserted",
        "alias",
        &id,
        &body.alias,
        "Upserted model alias.",
    )
    .await;
    state
        .registry
        .reload(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "id": id })))
}

pub async fn delete_alias(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
) -> ApiResult {
    db::delete_alias(&state.pool, &id)
        .await
        .map_err(ApiError::internal)?;
    state
        .registry
        .reload(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "ok": true })))
}

// ===========================================================================
// Usage / requests / audit
// ===========================================================================

#[derive(Deserialize)]
pub struct LimitQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_limit() -> i64 {
    200
}

pub async fn usage(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Query(q): Query<LimitQuery>,
) -> ApiResult {
    let rows = db::recent_usage(&state.pool, q.limit.min(2000))
        .await
        .map_err(ApiError::internal)?;
    let summary = db::usage_summary(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    let out: Vec<Value> = rows.iter().map(usage_json).collect();
    Ok(Json(json!({ "usage": out, "summary": summary })))
}

fn usage_json(u: &db::UsageLogRow) -> Value {
    json!({
        "id": u.id,
        "request_id": u.request_id,
        "timestamp": u.ts,
        "key_id": u.key_id,
        "key_name": u.key_name,
        "client_format": u.client_format,
        "requested_model": u.requested_model,
        "effective_model": u.effective_model,
        "route_id": u.route_id,
        "route_name": u.route_name,
        "fallback_hops": u.fallback_hops,
        "fallback_path": serde_json::from_str::<Value>(&u.fallback_path).unwrap_or(json!([])),
        "status": u.status,
        "status_code": u.status_code,
        "latency_ms": u.latency_ms,
        "ttft_ms": u.ttft_ms,
        "input_tokens": u.input_tokens,
        "output_tokens": u.output_tokens,
        "cached_tokens": u.cached_tokens,
        "thinking_tokens": u.thinking_tokens,
        "cost_usd": u.cost_usd,
        "cost_known": u.cost_known != 0,
        "cache_status": u.cache_status,
        "serving_account_id": u.serving_account_id,
        "serving_account": u.serving_account,
        "serving_provider": u.serving_provider,
        "flagged": u.flagged != 0,
        "error_message": u.error_message,
        "usage_confidence": u.usage_confidence,
        "commit_state": u.commit_state,
        "retry_count": u.retry_count,
        "opaque_route_id": u.opaque_route_id,
    })
}

/// `GET /admin/api/requests/{id}/route-trace` (FR-12.14, NFR-4.3).
pub async fn request_route_trace(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(request_id): Path<String>,
) -> ApiResult {
    let trace = db::get_route_trace_by_request(&state.pool, &request_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("no route trace for that request id"))?;
    Ok(Json(route_trace_json(&trace)))
}

/// `GET /admin/api/route-traces/{opaque_id}` (FR-12.15): resolve the opaque
/// `X-Kinetix-Route-Id` a client received back to its Route Trace. Serving
/// topology is admin-only, so this never leaks to the client itself.
pub async fn route_trace_by_opaque(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(opaque_id): Path<String>,
) -> ApiResult {
    let trace = db::get_route_trace_by_opaque(&state.pool, &opaque_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("no route trace for that opaque route id"))?;
    Ok(Json(route_trace_json(&trace)))
}

/// `GET /admin/api/requests/{id}/diagnostics` (FR-13.4): correlate the Route
/// Trace with the flight-recorder events for one request.
pub async fn request_diagnostics(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(request_id): Path<String>,
) -> ApiResult {
    let trace = db::get_route_trace_by_request(&state.pool, &request_id)
        .await
        .map_err(ApiError::internal)?;
    let flight = state.flight.events(&request_id);
    let usage = db::recent_usage(&state.pool, 2000)
        .await
        .map_err(ApiError::internal)?
        .into_iter()
        .find(|u| u.request_id == request_id)
        .map(|u| usage_json(&u));
    Ok(Json(json!({
        "request_id": request_id,
        "route_trace": trace.as_ref().map(route_trace_json),
        "flight_events": flight,
        "usage": usage,
        "flight_recorder": {
            "tracked_requests": state.flight.request_count(),
            "dropped_requests": state.flight.dropped_requests(),
            "dropped_events": state.flight.dropped_events(),
        }
    })))
}

/// Live in-flight request view (FR-8.3). Control-plane only: served from an
/// in-memory registry so it never touches the data plane, and DB enrichment is
/// best-effort so a degraded store cannot fail the view (NFR-2.6/2.7).
pub async fn live_requests(State(state): State<AppState>, _auth: AdminAuth) -> ApiResult {
    let mut rows = state.live.snapshot();
    // Best-effort enrichment: for a finished request still in the tail, attach
    // the persisted commit state / status / tokens if the DB is reachable.
    if db_healthy(&state).await {
        if let Ok(recent) = db::recent_usage(&state.pool, 200).await {
            let by_id: std::collections::HashMap<&str, &db::UsageLogRow> =
                recent.iter().map(|u| (u.request_id.as_str(), u)).collect();
            for r in rows.iter_mut() {
                if let Some(u) = by_id.get(r.request_id.as_str()) {
                    if r.finished {
                        r.status = u.status.clone();
                        r.commit_state = u.commit_state.clone();
                        r.retry_count = u.retry_count.max(0) as u32;
                        r.fallback_hops = u.fallback_hops.max(0) as u32;
                        r.input_tokens = u.input_tokens.map(|v| v.max(0) as u64);
                        r.output_tokens = u.output_tokens.map(|v| v.max(0) as u64);
                    }
                }
            }
        }
    }
    Ok(Json(json!({
        "live": rows,
        "live_count": state.live.live_count(),
        "dropped": state.live.dropped(),
    })))
}

fn route_trace_json(t: &db::RouteTraceRow) -> Value {
    json!({
        "request_id": t.request_id,
        "opaque_route_id": t.opaque_route_id,
        "timestamp": t.ts,
        "requested_model": t.requested_model,
        "route_id": t.route_id,
        "route_name": t.route_name,
        "final_target": t.final_target,
        "commit_state": t.commit_state,
        "outcome": t.outcome,
        "steps": serde_json::from_str::<Value>(&t.steps).unwrap_or(json!([])),
        "warnings": serde_json::from_str::<Value>(&t.warnings).unwrap_or(json!([])),
    })
}

/// `GET /admin/api/exports` — list exported usage/log files on disk, plus the
/// per-day usage available for export.
pub async fn list_exports(State(state): State<AppState>, _auth: AdminAuth) -> ApiResult {
    let dir = state.config.paths.exports_dir();
    let files = crate::export::list_files(&dir);
    let days = db::usage_days(&state.pool)
        .await
        .map_err(ApiError::internal)?
        .into_iter()
        .map(
            |(day, requests, tokens)| json!({ "day": day, "requests": requests, "tokens": tokens }),
        )
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "dir": dir.display().to_string(),
        "retention_days": state.config.export_retention_days,
        "files": files,
        "days": days,
    })))
}

#[derive(serde::Deserialize)]
pub struct ExportDayBody {
    /// `YYYY-MM-DD`; defaults to yesterday (UTC) when omitted.
    #[serde(default)]
    day: Option<String>,
}

/// `POST /admin/api/exports` — write one day's usage to disk on demand.
pub async fn export_usage_day(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Json(body): Json<ExportDayBody>,
) -> ApiResult {
    let day = body.day.unwrap_or_else(|| {
        (chrono::Utc::now().date_naive() - chrono::Duration::days(1))
            .format("%Y-%m-%d")
            .to_string()
    });
    let dir = state.config.paths.exports_dir();
    let (jsonl, csv) = crate::export::export_day(&state.pool, &dir, &day)
        .await
        .map_err(ApiError::internal)?;
    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "usage_exported",
        "system",
        &day,
        "Usage Export",
        &format!("Exported usage for {day} to disk."),
    )
    .await;
    Ok(Json(json!({
        "ok": true,
        "day": day,
        "jsonl": jsonl.display().to_string(),
        "csv": csv.display().to_string(),
    })))
}

/// `DELETE /admin/api/exports/{name}` — remove one exported file from disk.
pub async fn delete_export(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(name): Path<String>,
) -> ApiResult {
    let dir = state.config.paths.exports_dir();
    let removed = crate::export::delete_file(&dir, &name).map_err(ApiError::internal)?;
    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "export_deleted",
        "system",
        &name,
        "Usage Export",
        "Deleted an exported usage file.",
    )
    .await;
    Ok(Json(json!({ "ok": true, "removed": removed })))
}

pub async fn audit(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Query(q): Query<LimitQuery>,
) -> ApiResult {
    let rows = db::recent_audit(&state.pool, q.limit.min(2000))
        .await
        .map_err(ApiError::internal)?;
    let out: Vec<Value> = rows
        .iter()
        .map(|a| {
            json!({
                "id": a.id,
                "timestamp": a.ts,
                "actor": a.actor,
                "action": a.action,
                "target_type": a.target_type,
                "target_id": a.target_id,
                "target_name": a.target_name,
                "details": a.details,
            })
        })
        .collect();
    Ok(Json(json!({ "audit": out })))
}

/// Prometheus-format metrics (NFR-4.2).
/// True when the control-plane database answers a trivial query.
pub async fn db_healthy(state: &AppState) -> bool {
    sqlx::query("SELECT 1").fetch_one(&state.pool).await.is_ok()
}

/// Admin-router middleware: every state-changing request (anything that is not
/// GET/HEAD) must fail closed when the control-plane store is unavailable
/// (NFR-2.7: "admin mutations fail closed"). Reads are allowed so an operator
/// can still inspect what is cached in memory while the store is degraded.
pub async fn require_control_plane(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = req.method().clone();
    if method != axum::http::Method::GET && method != axum::http::Method::HEAD {
        if !db_healthy(&state).await {
            return (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                Json(
                    json!({"error": "admin mutation unavailable: control-plane store is degraded"}),
                ),
            )
                .into_response();
        }
    }
    next.run(req).await
}

pub async fn metrics(State(state): State<AppState>, _auth: AdminAuth) -> Response {
    // Serve whatever is available from memory even when the store is down; the
    // control plane degrades, the data plane does not (NFR-2.6/2.7).
    let healthy = db_healthy(&state).await;
    let summary = if healthy {
        db::usage_summary(&state.pool).await.unwrap_or(json!({}))
    } else {
        json!({})
    };
    let accounts = if healthy {
        db::list_accounts(&state.pool).await.unwrap_or_default()
    } else {
        Vec::new()
    };
    let mut body = String::new();
    body.push_str(
        "# HELP kinetix_control_plane_degraded 1 when the control-plane store is unavailable\n",
    );
    body.push_str("# TYPE kinetix_control_plane_degraded gauge\n");
    body.push_str(&format!(
        "kinetix_control_plane_degraded {}\n",
        if healthy { 0 } else { 1 }
    ));
    body.push_str("# HELP kinetix_requests_total Total proxied requests\n");
    body.push_str("# TYPE kinetix_requests_total counter\n");
    body.push_str(&format!(
        "kinetix_requests_total {}\n",
        summary["requests"].as_i64().unwrap_or(0)
    ));
    // Allocation accounting (NFR-1.8). Zero unless built with `alloc-stats`, so
    // the value honestly reads "not measured" rather than fabricating a number.
    body.push_str("# HELP kinetix_allocations_total Allocation calls (0 unless built with --features alloc-stats)\n");
    body.push_str("# TYPE kinetix_allocations_total counter\n");
    body.push_str(&format!(
        "kinetix_allocations_total {}\n",
        crate::alloc::allocations()
    ));
    body.push_str("# HELP kinetix_alloc_bytes_total Bytes allocated (0 unless built with --features alloc-stats)\n");
    body.push_str("# TYPE kinetix_alloc_bytes_total counter\n");
    body.push_str(&format!(
        "kinetix_alloc_bytes_total {}\n",
        crate::alloc::alloc_bytes()
    ));
    // Request/error rate (NFR-4.2): errors over total requests, including
    // client disconnects, so the ratio matches the alert loop's definition.
    {
        let reqs = summary["requests"].as_i64().unwrap_or(0).max(1);
        let errs = summary["error_requests"].as_i64().unwrap_or(0);
        body.push_str("# HELP kinetix_error_rate Request error ratio (0..1)\n");
        body.push_str("# TYPE kinetix_error_rate gauge\n");
        body.push_str(&format!(
            "kinetix_error_rate {}\n",
            errs as f64 / reqs as f64
        ));
    }
    body.push_str(
        "# HELP kinetix_ip_rate_limited_total Requests rejected by the per-IP limiter (NFR-3.6)\n",
    );
    body.push_str("# TYPE kinetix_ip_rate_limited_total counter\n");
    body.push_str(&format!(
        "kinetix_ip_rate_limited_total {}\n",
        state.ip_limiter.limited_total()
    ));
    body.push_str("# HELP kinetix_cost_usd_total Total computed cost in USD\n");
    body.push_str("# TYPE kinetix_cost_usd_total counter\n");
    body.push_str(&format!(
        "kinetix_cost_usd_total {}\n",
        summary["cost_usd"].as_f64().unwrap_or(0.0)
    ));
    body.push_str("# HELP kinetix_log_queue_depth Pending usage-log rows\n");
    body.push_str("# TYPE kinetix_log_queue_depth gauge\n");
    body.push_str(&format!(
        "kinetix_log_queue_depth {}\n",
        state.log_queue.depth()
    ));
    body.push_str("# HELP kinetix_log_queue_dropped_total Dropped usage-log rows\n");
    body.push_str("# TYPE kinetix_log_queue_dropped_total counter\n");
    body.push_str(&format!(
        "kinetix_log_queue_dropped_total {}\n",
        state.log_queue.dropped()
    ));
    body.push_str("# HELP kinetix_account_status Account health by status\n");
    body.push_str("# TYPE kinetix_account_status gauge\n");
    for status in ["healthy", "cooldown", "exhausted", "disabled"] {
        let n = accounts.iter().filter(|a| a.status == status).count();
        body.push_str(&format!(
            "kinetix_account_status{{status=\"{status}\"}} {n}\n"
        ));
    }
    // Commit-point failure counters (FR-4.9, NFR-4.2).
    body.push_str("# HELP kinetix_failures_pre_commit_total Failures before the commit point\n");
    body.push_str("# TYPE kinetix_failures_pre_commit_total counter\n");
    body.push_str(&format!(
        "kinetix_failures_pre_commit_total {}\n",
        state.failures_pre_commit.load(Ordering::Relaxed)
    ));
    body.push_str("# HELP kinetix_failures_post_commit_total Failures after the commit point\n");
    body.push_str("# TYPE kinetix_failures_post_commit_total counter\n");
    body.push_str(&format!(
        "kinetix_failures_post_commit_total {}\n",
        state.failures_post_commit.load(Ordering::Relaxed)
    ));
    body.push_str("# HELP kinetix_cancellations_total Client-disconnect cancellations\n");
    body.push_str("# TYPE kinetix_cancellations_total counter\n");
    body.push_str(&format!(
        "kinetix_cancellations_total {}\n",
        state.cancellations.load(Ordering::Relaxed)
    ));
    let cancel_total = state.cancellations.load(Ordering::Relaxed);
    let cancel_ms = state.cancellation_latency_ms_total.load(Ordering::Relaxed);
    let avg_cancel = if cancel_total > 0 {
        cancel_ms as f64 / cancel_total as f64
    } else {
        0.0
    };
    body.push_str("# HELP kinetix_cancellation_latency_ms Average cancellation latency (ms)\n");
    body.push_str("# TYPE kinetix_cancellation_latency_ms gauge\n");
    body.push_str(&format!("kinetix_cancellation_latency_ms {avg_cancel}\n"));
    body.push_str("# HELP kinetix_avg_latency_ms Average end-to-end latency (ms)\n");
    body.push_str("# TYPE kinetix_avg_latency_ms gauge\n");
    body.push_str(&format!(
        "kinetix_avg_latency_ms {}\n",
        summary["avg_latency_ms"].as_f64().unwrap_or(0.0)
    ));
    body.push_str("# HELP kinetix_avg_ttft_ms Average time-to-first-token (ms)\n");
    body.push_str("# TYPE kinetix_avg_ttft_ms gauge\n");
    body.push_str(&format!(
        "kinetix_avg_ttft_ms {}\n",
        summary["avg_ttft_ms"].as_f64().unwrap_or(0.0)
    ));
    body.push_str("# HELP kinetix_cached_tokens_total Provider-reported cached prompt tokens\n");
    body.push_str("# TYPE kinetix_cached_tokens_total counter\n");
    body.push_str(&format!(
        "kinetix_cached_tokens_total {}\n",
        summary["cached_tokens"].as_i64().unwrap_or(0)
    ));
    // Accounting confidence (FR-6.8, NFR-4.2): usage rows whose tokens were not
    // provider-reported. Unknown/estimated rows must never be read as exact.
    body.push_str("# HELP kinetix_usage_unknown_total Requests whose token usage is unknown\n");
    body.push_str("# TYPE kinetix_usage_unknown_total counter\n");
    body.push_str(&format!(
        "kinetix_usage_unknown_total {}\n",
        summary["unknown_usage_requests"].as_i64().unwrap_or(0)
    ));
    body.push_str("# HELP kinetix_usage_estimated_total Requests whose token usage is estimated\n");
    body.push_str("# TYPE kinetix_usage_estimated_total counter\n");
    body.push_str(&format!(
        "kinetix_usage_estimated_total {}\n",
        summary["estimated_usage_requests"].as_i64().unwrap_or(0)
    ));
    body.push_str(
        "# HELP kinetix_usage_unknown_cost_total Requests whose cost is unknown (no prices)\n",
    );
    body.push_str("# TYPE kinetix_usage_unknown_cost_total counter\n");
    body.push_str(&format!(
        "kinetix_usage_unknown_cost_total {}\n",
        summary["unknown_cost_requests"].as_i64().unwrap_or(0)
    ));
    body.push_str("# HELP kinetix_credential_failures_total Credential-strategy failures\n");
    body.push_str("# TYPE kinetix_credential_failures_total counter\n");
    body.push_str(&format!(
        "kinetix_credential_failures_total {}\n",
        crate::alerts::credential_failures()
    ));
    body.push_str("# HELP kinetix_fallback_hops_total Total fallback hops across requests\n");
    body.push_str("# TYPE kinetix_fallback_hops_total counter\n");
    body.push_str(&format!(
        "kinetix_fallback_hops_total {}\n",
        summary["fallback_hops"].as_i64().unwrap_or(0)
    ));
    body.push_str(
        "# HELP kinetix_route_fallbacks_total Requests served after at least one fallback hop\n",
    );
    body.push_str("# TYPE kinetix_route_fallbacks_total counter\n");
    body.push_str(&format!(
        "kinetix_route_fallbacks_total {}\n",
        state
            .route_fallbacks
            .load(std::sync::atomic::Ordering::Relaxed)
    ));
    body.push_str(
        "# HELP kinetix_route_skip_total Route targets skipped during eligibility filtering\n",
    );
    body.push_str("# TYPE kinetix_route_skip_total counter\n");
    body.push_str(&format!(
        "kinetix_route_skip_total {}\n",
        state.route_skips.load(std::sync::atomic::Ordering::Relaxed)
    ));
    body.push_str(
        "# HELP kinetix_flight_recorder_requests Requests tracked by the flight recorder\n",
    );
    body.push_str("# TYPE kinetix_flight_recorder_requests gauge\n");
    body.push_str(&format!(
        "kinetix_flight_recorder_requests {}\n",
        state.flight.request_count()
    ));
    body.push_str("# HELP kinetix_active_streams Requests currently in flight (live view)\n");
    body.push_str("# TYPE kinetix_active_streams gauge\n");
    body.push_str(&format!(
        "kinetix_active_streams {}\n",
        state.live.live_count()
    ));
    body.push_str("# HELP kinetix_live_view_dropped_total Live-view entries evicted under load\n");
    body.push_str("# TYPE kinetix_live_view_dropped_total counter\n");
    body.push_str(&format!(
        "kinetix_live_view_dropped_total {}\n",
        state.live.dropped()
    ));
    body.push_str(
        "# HELP kinetix_flight_recorder_dropped_total Diagnostics dropped when saturated\n",
    );
    body.push_str("# TYPE kinetix_flight_recorder_dropped_total counter\n");
    body.push_str(&format!(
        "kinetix_flight_recorder_dropped_total {}\n",
        state.flight.dropped_requests() + state.flight.dropped_events()
    ));
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
        .into_response()
}

// ===========================================================================
// Helpers
// ===========================================================================

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

/// Label for an account auto-created alongside a provider. Uses the supplied
/// label when given; otherwise derives it from the provider name so the pool key
/// is not misleadingly called "Default key".
fn account_label_or_default(provider_name: &str, label: Option<&str>) -> String {
    match label.map(str::trim).filter(|l| !l.is_empty()) {
        Some(l) => l.to_string(),
        None => format!("{} (primary)", provider_name.trim()),
    }
}

/// Guardrail for admin-supplied endpoints (NFR-3.9): HTTPS by default, and
/// loopback/link-local/private/metadata ranges blocked unless explicitly allowed.
fn validate_outbound_url(state: &AppState, url: &str) -> Result<(), ApiError> {
    let parsed = url::Url::parse(url).map_err(|e| ApiError::bad(format!("invalid URL: {e}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| ApiError::bad("URL must have a host"))?;
    // TLS is mandatory except in the explicit, visibly-marked dev mode
    // (NFR-3.12). KINETIX_ALLOW_INSECURE_TLS is that override — the
    // private-upstreams flag must NOT silently disable TLS.
    if parsed.scheme() != "https" && !state.config.allow_insecure_tls {
        return Err(ApiError::bad(
            "endpoint must use https (set KINETIX_ALLOW_INSECURE_TLS=true to override for local development)",
        ));
    }
    // The private-upstreams flag only relaxes the blocked-host check (NFR-3.9).
    if state.config.allow_private_upstreams {
        return Ok(());
    }
    if is_blocked_host(host) {
        return Err(ApiError::bad(format!(
            "host '{host}' resolves to a blocked private/metadata range; set KINETIX_ALLOW_PRIVATE_UPSTREAMS=true to allow"
        )));
    }
    Ok(())
}

fn is_blocked_host(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") || lower.ends_with(".internal") {
        return true;
    }
    if lower == "metadata.google.internal" {
        return true;
    }
    if let Ok(ip) = lower.parse::<std::net::IpAddr>() {
        return is_blocked_ip(ip);
    }
    false
}

/// Whether an IP literal falls in a blocked private/link-local/metadata range
/// (NFR-3.9). Shared with the connect-time DNS re-check in the pipeline.
pub fn is_blocked_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.octets()[0] == 169 && v4.octets()[1] == 254
        }
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

// ===========================================================================
// Configuration export / import (FR-10.12)
//
// User-authored, secret-free by default. Export produces a portable JSON
// document; import is a two-phase Validate/Dry Run + Apply so an operator can
// see the plan before touching production (FR-8.6). Import matches by name and
// never deletes: a name that already exists is updated, a new name is created.
// Secrets are excluded unless `include_secrets` is set, in which case the
// AES-GCM encrypted `secret_enc` blobs are carried so a restore is possible
// without re-entering keys.
// ===========================================================================

#[derive(Deserialize)]
pub struct ExportQuery {
    /// Include encrypted credential blobs (still ciphertext, still keyed by the
    /// master key). Off by default so exports are safe to share.
    #[serde(default)]
    pub include_secrets: bool,
}

pub async fn export_config(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Query(q): Query<ExportQuery>,
) -> ApiResult {
    let providers = db::list_providers(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    let mut accounts = Vec::new();
    let mut models = Vec::new();
    for p in &providers {
        for a in db::accounts_for_provider(&state.pool, &p.id)
            .await
            .map_err(ApiError::internal)?
        {
            accounts.push(a);
        }
        for m in db::models_for_provider(&state.pool, &p.id)
            .await
            .map_err(ApiError::internal)?
        {
            models.push(m);
        }
    }
    let routes = db::list_routes(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    let aliases = db::list_aliases(&state.pool)
        .await
        .map_err(ApiError::internal)?;

    let provider_name = |id: &str| -> String {
        providers
            .iter()
            .find(|p| p.id == id)
            .map(|p| p.name.clone())
            .unwrap_or_default()
    };
    let model_label = |id: &str| -> String {
        models
            .iter()
            .find(|m| m.id == id)
            .map(|m| format!("{}/{}", provider_name(&m.provider_id), m.upstream_id))
            .unwrap_or_default()
    };

    let providers_json: Vec<Value> = providers
        .iter()
        .map(|p| {
            json!({
                "name": p.name,
                "base_url": p.base_url,
                "wire_format": p.wire_format,
                "auth_scheme": p.auth_scheme,
                "custom_header_name": p.custom_header_name,
                "custom_param_name": p.custom_param_name,
                "extra_headers": serde_json::from_str::<Value>(&p.extra_headers).unwrap_or(json!({})),
                "timeout_ms": p.timeout_ms,
                "capability_mode": p.capability_mode,
                "models_path": p.models_path,
                "rate_limit_rules": serde_json::from_str::<Value>(&p.rate_limit_rules).unwrap_or(json!({})),
                "follow_redirects": p.follow_redirects != 0,
                "credential_hosts": p.credential_hosts,
                "allow_insecure_tls": p.allow_insecure_tls != 0,
                "enabled": p.enabled != 0,
            })
        })
        .collect();

    let accounts_json: Vec<Value> = accounts
        .iter()
        .map(|a| {
            let mut v = json!({
                "provider": provider_name(&a.provider_id),
                "label": a.label,
                "key_mask": a.key_mask,
                "status": a.status,
                "quota_type": a.quota_type,
                "soft_quota_usd": a.soft_quota_usd,
                "priority": a.priority,
                "weight": a.weight,
            });
            if q.include_secrets {
                v["secret_enc"] = json!(a.secret_enc);
            }
            v
        })
        .collect();

    let models_json: Vec<Value> = models
        .iter()
        .map(|m| {
            json!({
                "provider": provider_name(&m.provider_id),
                "upstream_id": m.upstream_id,
                "display_name": m.display_name,
                "enabled": m.enabled != 0,
                "context_window": m.context_window,
                "max_output_tokens": m.max_output_tokens,
                "capabilities": serde_json::from_str::<Value>(&m.capabilities).unwrap_or(json!({})),
                "prices": serde_json::from_str::<Value>(&m.prices).unwrap_or(json!({})),
                "parameters": serde_json::from_str::<Value>(&m.parameters).unwrap_or(json!({})),
                "thinking_map": serde_json::from_str::<Value>(&m.thinking_map).unwrap_or(json!({})),
                "extra_request": serde_json::from_str::<Value>(&m.extra_request).unwrap_or(json!({})),
            })
        })
        .collect();

    let mut routes_json = Vec::new();
    for r in &routes {
        let targets = db::route_targets(&state.pool, &r.id)
            .await
            .map_err(ApiError::internal)?;
        let targets_json: Vec<Value> = targets
            .iter()
            .map(|t| {
                json!({
                    "model": model_label(&t.model_id),
                    "account_id": t.account_id,
                    "priority": t.priority,
                    "weight": t.weight,
                    "predicate": serde_json::from_str::<Value>(&t.predicate).unwrap_or(json!({})),
                    "param_overrides": serde_json::from_str::<Value>(&t.param_overrides).unwrap_or(json!({})),
                })
            })
            .collect();
        routes_json.push(json!({
            "name": r.name,
            "description": r.description,
            "strategy": r.strategy,
            "fallback_triggers": serde_json::from_str::<Value>(&r.fallback_triggers).unwrap_or(json!({})),
            "continuity_policy": r.continuity_policy,
            "portability_policy": r.portability_policy,
            "sticky_routing": r.sticky_routing != 0,
            "cache_affinity": r.cache_affinity != 0,
            "max_attempts": r.max_attempts,
            "enabled": r.enabled != 0,
            "targets": targets_json,
        }));
    }

    let aliases_json: Vec<Value> = aliases
        .iter()
        .map(|a| {
            json!({
                "alias": a.alias,
                "target_type": a.target_type,
                "target": if a.target_type == "route" {
                    routes.iter().find(|r| r.id == a.target_id).map(|r| r.name.clone()).unwrap_or_default()
                } else {
                    model_label(&a.target_id)
                },
                "description": a.description,
            })
        })
        .collect();

    Ok(Json(json!({
        "kinetix_config_version": 1,
        "exported_at": db::now_iso(),
        "secrets_included": q.include_secrets,
        "providers": providers_json,
        "accounts": accounts_json,
        "models": models_json,
        "routes": routes_json,
        "aliases": aliases_json,
    })))
}

#[derive(Deserialize)]
pub struct ImportBody {
    pub config: Value,
    /// When false (default) only plan the changes and return them.
    #[serde(default)]
    pub apply: bool,
}

pub async fn import_config(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Json(body): Json<ImportBody>,
) -> ApiResult {
    let cfg = &body.config;
    let mut plan: Vec<Value> = Vec::new();
    let mut problems: Vec<String> = Vec::new();

    let empty = Vec::new();
    let providers = cfg["providers"].as_array().unwrap_or(&empty);
    let accounts = cfg["accounts"].as_array().unwrap_or(&empty);
    let models = cfg["models"].as_array().unwrap_or(&empty);
    let routes = cfg["routes"].as_array().unwrap_or(&empty);
    let aliases = cfg["aliases"].as_array().unwrap_or(&empty);

    if providers.is_empty() && models.is_empty() && routes.is_empty() {
        return Err(ApiError::bad(
            "config has no providers, models, or routes to import",
        ));
    }

    // ---- Validate phase (FR-8.6): schema + outbound security, no writes ----
    for p in providers {
        let name = p["name"].as_str().unwrap_or("");
        let base_url = p["base_url"].as_str().unwrap_or("");
        if name.is_empty() || base_url.is_empty() {
            problems.push("a provider entry is missing name or base_url".into());
            continue;
        }
        if let Err(e) = validate_outbound_url(&state, base_url) {
            problems.push(format!("provider '{name}': {}", e.1));
        }
        if WireFormat::parse(p["wire_format"].as_str().unwrap_or("")).is_none() {
            problems.push(format!(
                "provider '{name}': invalid wire_format '{}'",
                p["wire_format"].as_str().unwrap_or("")
            ));
        }
        let existing = db::list_providers(&state.pool)
            .await
            .map_err(ApiError::internal)?
            .into_iter()
            .any(|x| x.name == name);
        plan.push(json!({
            "kind": "provider",
            "name": name,
            "action": if existing { "update" } else { "create" },
        }));
    }
    for m in models {
        let provider = m["provider"].as_str().unwrap_or("");
        let upstream = m["upstream_id"].as_str().unwrap_or("");
        if provider.is_empty() || upstream.is_empty() {
            problems.push("a model entry is missing provider or upstream_id".into());
        }
        plan.push(
            json!({"kind": "model", "name": format!("{provider}/{upstream}"), "action": "upsert"}),
        );
    }
    for r in routes {
        let name = r["name"].as_str().unwrap_or("");
        if name.is_empty() {
            problems.push("a route entry is missing a name".into());
        }
        let targets = r["targets"].as_array().map(|a| a.len()).unwrap_or(0);
        if targets == 0 {
            problems.push(format!("route '{name}' has no targets"));
        }
        plan.push(json!({"kind": "route", "name": name, "action": "upsert", "targets": targets}));
    }

    if !body.apply {
        return Ok(Json(json!({
            "valid": problems.is_empty(),
            "problems": problems,
            "plan": plan,
            "note": "dry run: no changes were applied",
        })));
    }
    if !problems.is_empty() {
        return Err(ApiError::bad(format!(
            "config validation failed: {}",
            problems.join("; ")
        )));
    }

    // ---- Apply phase ----
    let mut provider_ids: std::collections::HashMap<String, String> = Default::default();
    for p in &db::list_providers(&state.pool)
        .await
        .map_err(ApiError::internal)?
    {
        provider_ids.insert(p.name.clone(), p.id.clone());
    }

    for p in providers {
        let name = p["name"].as_str().unwrap_or("");
        let base_url = p["base_url"].as_str().unwrap_or("");
        let wire = WireFormat::parse(p["wire_format"].as_str().unwrap_or(""))
            .ok_or_else(|| ApiError::bad("invalid wire_format"))?;
        let auth = AuthScheme::parse(p["auth_scheme"].as_str().unwrap_or("bearer"))
            .unwrap_or(AuthScheme::Bearer);
        let extra_headers = p["extra_headers"].clone();
        let rate_limit_rules = p["rate_limit_rules"].clone();
        let timeout_ms = p["timeout_ms"].as_i64().unwrap_or(120_000);
        let capability_mode = p["capability_mode"].as_str().unwrap_or("permissive");
        let models_path = p["models_path"].as_str();
        let follow_redirects = p["follow_redirects"].as_bool().unwrap_or(false);
        let credential_hosts = p["credential_hosts"].as_str().unwrap_or("");
        let allow_insecure_tls = p["allow_insecure_tls"].as_bool().unwrap_or(false);
        let custom_header = p["custom_header_name"].as_str();
        let custom_param = p["custom_param_name"].as_str();
        if let Some(existing) = provider_ids.get(name) {
            db::update_provider(
                &state.pool,
                existing,
                name,
                base_url,
                wire,
                auth,
                custom_header,
                custom_param,
                extra_headers,
                timeout_ms,
                capability_mode,
                models_path,
                follow_redirects,
                credential_hosts,
                allow_insecure_tls,
                p["wire_plugin"].as_str().unwrap_or(""),
                p["credential_plugin"].as_str().unwrap_or(""),
                p["model_source_plugin"].as_str().unwrap_or(""),
            )
            .await
            .map_err(ApiError::internal)?;
        } else {
            let id = db::insert_provider(
                &state.pool,
                &db::NewProvider {
                    name,
                    base_url,
                    wire_format: wire,
                    auth_scheme: auth,
                    custom_header_name: custom_header,
                    custom_param_name: custom_param,
                    extra_headers,
                    timeout_ms,
                    capability_mode,
                    models_path,
                    rate_limit_rules,
                    follow_redirects,
                    credential_hosts,
                    allow_insecure_tls,
                    wire_plugin: p["wire_plugin"].as_str().unwrap_or(""),
                    credential_plugin: p["credential_plugin"].as_str().unwrap_or(""),
                    model_source_plugin: p["model_source_plugin"].as_str().unwrap_or(""),
                },
            )
            .await
            .map_err(ApiError::internal)?;
            provider_ids.insert(name.to_string(), id);
        }
    }

    // Accounts: only created when they carry an encrypted secret blob; an
    // account without a secret cannot be materialized (FR-3.4 write-only).
    for a in accounts {
        let provider = a["provider"].as_str().unwrap_or("");
        let Some(pid) = provider_ids.get(provider) else {
            continue;
        };
        let Some(secret_enc) = a["secret_enc"].as_str() else {
            continue;
        };
        let label = a["label"].as_str().unwrap_or("Default key");
        let exists = db::accounts_for_provider(&state.pool, pid)
            .await
            .map_err(ApiError::internal)?
            .into_iter()
            .any(|x| x.label == label);
        if exists {
            continue; // never overwrite an existing credential
        }
        db::insert_account(
            &state.pool,
            pid,
            label,
            secret_enc,
            a["key_mask"].as_str().unwrap_or("••••"),
            a["priority"].as_i64().unwrap_or(1),
            a["weight"].as_i64().unwrap_or(1),
            a["soft_quota_usd"].as_f64(),
            a["quota_type"].as_str().unwrap_or("none"),
        )
        .await
        .map_err(ApiError::internal)?;
    }

    let mut model_ids: std::collections::HashMap<String, String> = Default::default();
    for m in &db::list_models(&state.pool)
        .await
        .map_err(ApiError::internal)?
    {
        let pname = db::list_providers(&state.pool)
            .await
            .map_err(ApiError::internal)?
            .into_iter()
            .find(|p| p.id == m.provider_id)
            .map(|p| p.name)
            .unwrap_or_default();
        model_ids.insert(format!("{}/{}", pname, m.upstream_id), m.id.clone());
    }

    for m in models {
        let provider = m["provider"].as_str().unwrap_or("");
        let upstream = m["upstream_id"].as_str().unwrap_or("");
        let Some(pid) = provider_ids.get(provider) else {
            continue;
        };
        let caps: Capabilities =
            serde_json::from_value(m["capabilities"].clone()).unwrap_or_default();
        let prices: Prices = serde_json::from_value(m["prices"].clone()).unwrap_or_default();
        let display = m["display_name"].as_str().unwrap_or(upstream);
        let enabled = m["enabled"].as_bool().unwrap_or(true);
        let context_window = m["context_window"].as_i64();
        let max_output_tokens = m["max_output_tokens"].as_i64();
        if let Some(existing) = model_ids.get(&format!("{provider}/{upstream}")) {
            db::update_model(
                &state.pool,
                existing,
                display,
                enabled,
                context_window,
                max_output_tokens,
                serde_json::to_value(&caps).unwrap(),
                serde_json::to_value(&prices).unwrap(),
                m["parameters"].clone(),
                m["thinking_map"].clone(),
                m["extra_request"].clone(),
            )
            .await
            .map_err(ApiError::internal)?;
        } else {
            let id = db::insert_model(
                &state.pool,
                &db::NewModel {
                    provider_id: pid,
                    upstream_id: upstream,
                    display_name: display,
                    enabled,
                    context_window,
                    max_output_tokens,
                    capabilities: serde_json::to_value(&caps).unwrap(),
                    prices: serde_json::to_value(&prices).unwrap(),
                    parameters: m["parameters"].clone(),
                    thinking_map: m["thinking_map"].clone(),
                    extra_request: m["extra_request"].clone(),
                    discovery: json!({}),
                },
            )
            .await
            .map_err(ApiError::internal)?;
            model_ids.insert(format!("{provider}/{upstream}"), id);
        }
    }

    // Routes (upsert by name) + targets.
    for r in routes {
        let name = r["name"].as_str().unwrap_or("");
        let body = RouteBody {
            name: name.to_string(),
            description: r["description"].as_str().unwrap_or("").to_string(),
            strategy: r["strategy"].as_str().unwrap_or("priority").to_string(),
            fallback_triggers: r["fallback_triggers"].clone(),
            continuity_policy: r["continuity_policy"]
                .as_str()
                .unwrap_or("strip")
                .to_string(),
            portability_policy: r["portability_policy"]
                .as_str()
                .unwrap_or("strip_with_warning")
                .to_string(),
            sticky_routing: r["sticky_routing"].as_bool().unwrap_or(false),
            cache_affinity: r["cache_affinity"].as_bool().unwrap_or(false),
            max_attempts: r["max_attempts"].as_i64(),
            targets: Vec::new(),
        };
        let mut target_bodies = Vec::new();
        for t in r["targets"].as_array().unwrap_or(&empty) {
            let model_key = t["model"].as_str().unwrap_or("");
            let Some(mid) = model_ids.get(model_key) else {
                continue;
            };
            target_bodies.push(RouteTargetBody {
                account_id: t["account_id"].as_str().map(|s| s.to_string()),
                model_id: mid.clone(),
                priority: t["priority"].as_i64().unwrap_or(1),
                weight: t["weight"].as_i64().unwrap_or(1),
                predicate: t["predicate"].clone(),
                param_overrides: t["param_overrides"].clone(),
            });
        }
        let existing = db::get_route_by_name(&state.pool, name)
            .await
            .map_err(ApiError::internal)?;
        let rid = match existing {
            Some(route) => {
                let mut body = body;
                body.targets = target_bodies;
                db::update_route(
                    &state.pool,
                    &route.id,
                    &body.description,
                    &body.strategy,
                    body.fallback_triggers.clone(),
                    &body.continuity_policy,
                    &body.portability_policy,
                    body.sticky_routing,
                    body.cache_affinity,
                    body.max_attempts,
                )
                .await
                .map_err(ApiError::internal)?;
                db::clear_route_targets(&state.pool, &route.id)
                    .await
                    .map_err(ApiError::internal)?;
                write_route_targets(&state.pool, &route.id, &body.targets).await?;
                route.id
            }
            None => {
                let id = db::insert_route(
                    &state.pool,
                    &db::NewRoute {
                        name,
                        description: &body.description,
                        strategy: &body.strategy,
                        fallback_triggers: if body.fallback_triggers.is_null() {
                            json!({"on429": true, "onQuota": true, "on5xx": true, "onTimeout": true})
                        } else {
                            body.fallback_triggers.clone()
                        },
                        continuity_policy: &body.continuity_policy,
                        portability_policy: &body.portability_policy,
                        sticky_routing: body.sticky_routing,
                        cache_affinity: body.cache_affinity,
                        max_attempts: body.max_attempts,
                    },
                )
                .await
                .map_err(ApiError::internal)?;
                write_route_targets(&state.pool, &id, &target_bodies).await?;
                id
            }
        };
        let _ = rid;
    }

    // Aliases (upsert by alias name).
    for a in aliases {
        let alias = a["alias"].as_str().unwrap_or("");
        if alias.is_empty() {
            continue;
        }
        let ttype = a["target_type"].as_str().unwrap_or("model");
        let target = a["target"].as_str().unwrap_or("");
        let tid = if ttype == "route" {
            db::get_route_by_name(&state.pool, target)
                .await
                .map_err(ApiError::internal)?
                .map(|r| r.id)
        } else {
            model_ids.get(target).cloned()
        };
        let Some(tid) = tid else { continue };
        db::upsert_alias(
            &state.pool,
            alias,
            ttype,
            &tid,
            a["description"].as_str().unwrap_or(""),
        )
        .await
        .map_err(ApiError::internal)?;
    }

    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "config_imported",
        "system",
        "config",
        "config",
        &format!(
            "Imported {} providers, {} models, {} routes, {} aliases.",
            providers.len(),
            models.len(),
            routes.len(),
            aliases.len()
        ),
    )
    .await;
    state
        .registry
        .reload(&state.pool)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "ok": true, "applied": plan })))
}

// ===========================================================================
// Plugins (post-v1; docs/KINETIX-PLUGIN-ARCHITECTURE.md §11, §20, §21)
// ===========================================================================

#[derive(Deserialize)]
pub struct PluginInstallBody {
    /// Base64-encoded `.kxp` package (dashboard/API upload).
    #[serde(default)]
    pub package_base64: Option<String>,
    /// Server-side path to a `.kxp` (operator convenience).
    #[serde(default)]
    pub path: Option<String>,
    /// Expected SHA-256 for a URL/remote install (§11).
    #[serde(default)]
    pub sha256: Option<String>,
    /// Trusted Ed25519 publisher public keys, base64 (§12).
    #[serde(default)]
    pub trusted_keys: Vec<String>,
    /// Explicit override to install an untrusted signature (§12).
    #[serde(default)]
    pub allow_untrusted_signature: bool,
}

fn plugin_bad(e: anyhow::Error) -> ApiError {
    ApiError::bad(e.to_string())
}

fn plugin_manager(
    state: &AppState,
) -> Result<&std::sync::Arc<crate::plugins::PluginManager>, ApiError> {
    state.plugin_manager().ok_or_else(|| {
        ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "plugin host is not available".into(),
        )
    })
}

/// Register the runtime capability objects an enabled plugin provides (§6.0).
///
/// A plugin that declares a `credential_strategies` capability gets a
/// `PluginCredentialStrategy` so a provider bound to it resolves through the
/// plugin; a plugin that declares `provider_adapters` gets a plugin-backed
/// adapter for each declared name. Registration is idempotent — enabling an
/// already-enabled plugin simply re-registers the same object.
pub(crate) async fn register_enabled_plugin_capabilities(state: &AppState, id: &str) {
    let Some(manager) = state.plugin_manager().cloned() else {
        return;
    };
    let crypto = state.crypto.clone();
    let pool = state.pool.clone();
    // `enable` has already succeeded, so the row exists and is enabled.
    let provides = match manager.get(id).await {
        Ok(Some(row)) => row.manifest().map(|m| m.provides).unwrap_or_default(),
        _ => return,
    };
    if !provides.credential_strategies.is_empty() {
        let strategy: std::sync::Arc<dyn crate::credentials::CredentialStrategy> =
            std::sync::Arc::new(crate::plugins::credential::PluginCredentialStrategy::new(
                manager.clone(),
                pool,
                crypto,
                id,
            ));
        state.register_plugin_credential_strategy(id, strategy);
    }
    // ProviderAdapter registration (§6.3, §7.1): a plugin adapter is a pure
    // translation library — core still owns the outbound streaming send. The
    // `plugin-adapter` world imports no network capability, so registering it
    // does not widen the plugin's authority.
    if !provides.provider_adapters.is_empty() {
        match crate::plugins::adapter::PluginAdapter::new((*manager).clone(), id.to_string()).await
        {
            Ok(adapter) => {
                let adapter: std::sync::Arc<dyn crate::adapters::Adapter> =
                    std::sync::Arc::new(adapter);
                // Key by the full namespaced reference for each declared
                // capability name, plus the bare plugin id (§6.0).
                for name in &provides.provider_adapters {
                    state.register_plugin_adapter(format!("plugin:{id}/{name}"), adapter.clone());
                }
                state.register_plugin_adapter(id.to_string(), adapter);
            }
            Err(e) => {
                tracing::warn!(
                    plugin = %id,
                    error = %e,
                    "plugin declares provider_adapters but its adapter world could not be loaded; bound providers will fail closed"
                );
            }
        }
    }
}

/// `GET /admin/api/plugins/catalog` — embedded official discovery metadata.
///
/// Catalog metadata is not a package trust root. Installation continues to use
/// the normal SHA/signature/permission-review pipeline.
pub async fn plugin_catalog(_auth: AdminAuth) -> ApiResult {
    let catalog = crate::plugins::catalog::embedded_catalog().map_err(ApiError::internal)?;
    let trust = crate::plugins::catalog::embedded_trust_store().map_err(ApiError::internal)?;

    let mut plugins = Vec::with_capacity(catalog.plugins.len());
    for plugin in catalog.plugins {
        let ready =
            crate::plugins::catalog::install_ready(&plugin, &trust).map_err(ApiError::internal)?;
        let mut value = serde_json::to_value(&plugin).map_err(ApiError::internal)?;
        value["install_ready"] = json!(ready);
        value["trust_status"] = json!(if ready {
            "trusted"
        } else if plugin.installable {
            "unavailable"
        } else {
            "discovery_only"
        });
        plugins.push(value);
    }

    Ok(Json(json!({
        "schema_version": catalog.schema_version,
        "plugins": plugins,
    })))
}

async fn download_catalog_package(
    state: &AppState,
    distribution: &crate::plugins::catalog::CatalogDistribution,
) -> Result<Vec<u8>, ApiError> {
    let mut url = url::Url::parse(&distribution.url)
        .map_err(|e| ApiError::bad(format!("invalid catalog artifact URL: {e}")))?;

    for redirect_count in 0..=5 {
        crate::plugins::catalog::validate_download_url(distribution, &url)
            .map_err(plugin_bad)?;

        let mut response = state
            .http
            .get(url.clone())
            .timeout(std::time::Duration::from_secs(60))
            .send()
            .await
            .map_err(|e| ApiError::bad(format!("catalog artifact download failed: {e}")))?;

        if response.status().is_redirection() {
            if redirect_count == 5 {
                return Err(ApiError::bad("catalog artifact exceeded redirect limit"));
            }
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| ApiError::bad("catalog artifact redirect has no valid Location"))?;
            url = url
                .join(location)
                .map_err(|e| ApiError::bad(format!("invalid catalog artifact redirect: {e}")))?;
            continue;
        }

        if !response.status().is_success() {
            return Err(ApiError::bad(format!(
                "catalog artifact returned HTTP {}",
                response.status()
            )));
        }

        if response
            .content_length()
            .is_some_and(|length| length > crate::plugins::package::MAX_PACKAGE_BYTES)
        {
            return Err(ApiError::bad("catalog artifact exceeds package size limit"));
        }

        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| ApiError::bad(format!("reading catalog artifact failed: {e}")))?
        {
            if bytes.len() as u64 + chunk.len() as u64
                > crate::plugins::package::MAX_PACKAGE_BYTES
            {
                return Err(ApiError::bad("catalog artifact exceeds package size limit"));
            }
            bytes.extend_from_slice(&chunk);
        }
        return Ok(bytes);
    }

    Err(ApiError::bad("catalog artifact download failed"))
}

/// `POST /admin/api/plugins/catalog/{id}/install` — install a trusted catalog package.
pub async fn install_catalog_plugin(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
) -> ApiResult {
    let manager = plugin_manager(&state)?;
    let plugin = crate::plugins::catalog::find_plugin(&id).map_err(plugin_bad)?;
    let distribution = plugin
        .distribution
        .as_ref()
        .ok_or_else(|| ApiError::bad("catalog plugin has no installable distribution"))?;
    let trust = crate::plugins::catalog::embedded_trust_store().map_err(ApiError::internal)?;
    if !crate::plugins::catalog::install_ready(&plugin, &trust).map_err(plugin_bad)? {
        return Err(ApiError::bad(
            "catalog plugin is not install-ready: signed artifact metadata or publisher trust is unavailable",
        ));
    }
    let key = crate::plugins::catalog::trusted_key(&trust, &plugin)
        .map_err(plugin_bad)?
        .ok_or_else(|| ApiError::bad("catalog publisher key is not trusted"))?;

    let bytes = download_catalog_package(&state, distribution).await?;
    let pkg = crate::plugins::package::read_package(&bytes).map_err(plugin_bad)?;
    if !distribution
        .sha256
        .eq_ignore_ascii_case(&pkg.package_sha256)
    {
        return Err(ApiError::bad(format!(
            "catalog package hash mismatch: expected {}, computed {}",
            distribution.sha256, pkg.package_sha256
        )));
    }
    let validated =
        crate::plugins::package::validate_manifest(&pkg, manager.policy()).map_err(plugin_bad)?;
    if validated.manifest.id != plugin.id {
        return Err(ApiError::bad(format!(
            "catalog artifact id mismatch: expected '{}', package declares '{}'",
            plugin.id, validated.manifest.id
        )));
    }
    if validated.manifest.version != plugin.latest_version {
        return Err(ApiError::bad(format!(
            "catalog artifact version mismatch: expected '{}', package declares '{}'",
            plugin.latest_version, validated.manifest.version
        )));
    }
    let signature = crate::plugins::package::verify_signature(&pkg, &[key]).map_err(plugin_bad)?;
    if signature != crate::plugins::package::SignatureStatus::Verified {
        return Err(ApiError::bad(
            "catalog package is not signed by its trusted publisher key",
        ));
    }

    let source = format!("catalog:{}@{}", plugin.id, plugin.latest_version);
    let outcome = manager
        .install_from_source(
            &bytes,
            Some(&distribution.sha256),
            &[key],
            false,
            &source,
        )
        .await
        .map_err(plugin_bad)?;

    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "plugin_catalog_installed",
        "plugin",
        &outcome.id,
        &outcome.id,
        &format!(
            "Installed trusted catalog plugin {} v{} (SHA-256 {}). Installed disabled pending permission review.",
            outcome.id, outcome.version, outcome.package_sha256
        ),
    )
    .await;

    Ok(Json(json!({
        "id": outcome.id,
        "version": outcome.version,
        "sha256": outcome.package_sha256,
        "signature": outcome.signature.as_str(),
        "provides": outcome.provides,
        "enabled": false,
        "source": source,
        "note": "trusted catalog package installed disabled; review permissions before enabling",
    })))
}

/// `GET /admin/api/plugins` — list installed plugins.
pub async fn list_plugins(State(state): State<AppState>, _auth: AdminAuth) -> ApiResult {
    let manager = plugin_manager(&state)?;
    let rows = manager.list().await.map_err(ApiError::internal)?;
    let plugins: Vec<Value> = rows
        .iter()
        .map(crate::plugins::manager::manifest_summary)
        .collect();
    Ok(Json(json!({ "plugins": plugins })))
}

/// `GET /admin/api/plugins/{id}` — plugin detail (§21).
pub async fn get_plugin(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
) -> ApiResult {
    let manager = plugin_manager(&state)?;
    let row = manager
        .get(&id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("plugin not found"))?;
    let perms = crate::plugins::store::permissions(&state.pool, &id)
        .await
        .map_err(ApiError::internal)?;
    let runtime = crate::plugins::store::runtime_state(&state.pool, &id)
        .await
        .map_err(ApiError::internal)?;
    let packages = crate::plugins::store::list_packages(&state.pool, &id)
        .await
        .map_err(ApiError::internal)?;
    let mut summary = crate::plugins::manager::manifest_summary(&row);
    summary["permissions_approved"] = json!(perms);
    summary["runtime"] = json!(runtime);
    summary["packages"] = json!(packages);
    Ok(Json(summary))
}

/// `GET /admin/api/plugins/{id}/settings` — read host-owned plugin settings.
pub async fn plugin_settings(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
) -> ApiResult {
    let manager = plugin_manager(&state)?;
    let settings = manager.ui_settings(&id).await.map_err(plugin_bad)?;
    Ok(Json(settings))
}

#[derive(Deserialize)]
pub struct PluginSettingsBody {
    #[serde(default)]
    pub values: serde_json::Map<String, Value>,
}

/// `PUT /admin/api/plugins/{id}/settings` — partially update validated settings.
pub async fn update_plugin_settings(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
    Json(body): Json<PluginSettingsBody>,
) -> ApiResult {
    let manager = plugin_manager(&state)?;
    let settings = manager
        .update_ui_settings(&id, &body.values)
        .await
        .map_err(plugin_bad)?;

    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "plugin_settings_updated",
        "plugin",
        &id,
        &id,
        &format!(
            "Updated {} plugin setting(s). Values are not written to audit logs.",
            body.values.len()
        ),
    )
    .await;

    Ok(Json(settings))
}

/// `POST /admin/api/plugins/install` — install (or upgrade) a package.
pub async fn install_plugin(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Json(body): Json<PluginInstallBody>,
) -> ApiResult {
    let manager = plugin_manager(&state)?;
    let bytes = if let Some(b64) = &body.package_base64 {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|e| ApiError::bad(format!("invalid package_base64: {e}")))?
    } else if let Some(path) = &body.path {
        std::fs::read(path).map_err(|e| ApiError::bad(format!("cannot read {path}: {e}")))?
    } else {
        return Err(ApiError::bad("provide package_base64 or path"));
    };

    let trusted: Vec<[u8; 32]> = body
        .trusted_keys
        .iter()
        .filter_map(|k| decode_key(k))
        .collect();

    let outcome = manager
        .install(
            &bytes,
            body.sha256.as_deref(),
            &trusted,
            body.allow_untrusted_signature,
        )
        .await
        .map_err(plugin_bad)?;

    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "plugin_installed",
        "plugin",
        &outcome.id,
        &outcome.id,
        &format!(
            "Installed plugin {} v{} (signature: {}, provides {} capabilities). Installed disabled.",
            outcome.id,
            outcome.version,
            outcome.signature.as_str(),
            outcome.provides.len()
        ),
    )
    .await;

    Ok(Json(json!({
        "id": outcome.id,
        "version": outcome.version,
        "sha256": outcome.package_sha256,
        "signature": outcome.signature.as_str(),
        "provides": outcome.provides,
        "enabled": false,
        "note": "installed-disabled; enable is a separate operation",
    })))
}

#[derive(Deserialize)]
pub struct PluginAuthStartBody {
    pub plugin_id: String,
    pub flow_name: String,
    pub provider_id: String,
}

/// Start a one-time browser authorization session for a plugin integration.
pub async fn start_plugin_auth(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Json(body): Json<PluginAuthStartBody>,
) -> ApiResult {
    let manager = plugin_manager(&state)?;
    let row = manager
        .get(&body.plugin_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("plugin not found"))?;
    let manifest = row
        .manifest()
        .ok_or_else(|| ApiError::bad("plugin manifest is unreadable"))?;

    let integration = manifest
        .integrations
        .iter()
        .find(|integration| integration.auth_flow.as_deref() == Some(body.flow_name.as_str()))
        .ok_or_else(|| ApiError::bad("auth flow is not exposed by a plugin integration"))?;
    let credential_strategy = integration
        .credential_strategy
        .as_deref()
        .ok_or_else(|| ApiError::bad("integration has no credential strategy"))?;

    let provider = db::get_provider(&state.pool, &body.provider_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("provider not found"))?;
    let expected_binding = format!("plugin:{}/{}", body.plugin_id, credential_strategy);
    if provider.credential_plugin != expected_binding {
        return Err(ApiError::bad(format!(
            "provider '{}' is not bound to integration credential strategy '{}'",
            provider.id, expected_binding
        )));
    }

    let redirect_uri = format!(
        "{}/admin/api/plugins/auth/callback",
        state.config.public_base_url.trim_end_matches('/')
    );
    let pending = state.plugin_auth_sessions.create(
        &body.plugin_id,
        &body.flow_name,
        &body.provider_id,
        &expected_binding,
        &redirect_uri,
    );

    let authorize_url = match manager
        .auth_begin(
            &body.plugin_id,
            &body.flow_name,
            &redirect_uri,
            &pending.state,
            Some(&pending.pkce_challenge),
        )
        .await
    {
        Ok(url) => url,
        Err(error) => {
            state.plugin_auth_sessions.revoke(&pending.state);
            return Err(ApiError::bad(error.to_string()));
        }
    };

    let parsed = url::Url::parse(&authorize_url)
        .map_err(|_| ApiError::bad("plugin returned an invalid authorization URL"))?;
    if parsed.scheme() != "https" {
        state.plugin_auth_sessions.revoke(&pending.state);
        return Err(ApiError::bad("plugin authorization URL must use https"));
    }
    let auth_host = parsed
        .host_str()
        .ok_or_else(|| ApiError::bad("plugin authorization URL has no host"))?;
    if !manifest
        .permissions
        .network_hosts
        .iter()
        .any(|pattern| crate::plugins::manifest::host_matches(pattern, auth_host))
    {
        state.plugin_auth_sessions.revoke(&pending.state);
        return Err(ApiError::bad(format!(
            "authorization host '{auth_host}' is not declared in plugin network_hosts"
        )));
    }

    Ok(Json(json!({
        "authorize_url": authorize_url,
        "state": pending.state,
        "expires_in_secs": 600,
    })))
}

#[derive(Deserialize)]
pub struct PluginAuthCallbackQuery {
    pub state: String,
    pub code: Option<String>,
    pub error: Option<String>,
}

/// Browser callback. The one-time high-entropy state is the callback
/// credential and is consumed before code exchange, so replay fails closed.
pub async fn plugin_auth_callback(
    State(state): State<AppState>,
    Query(query): Query<PluginAuthCallbackQuery>,
) -> Result<Redirect, ApiError> {
    if !db_healthy(&state).await {
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "plugin account authorization unavailable: control plane degraded".into(),
        ));
    }

    let session = state
        .plugin_auth_sessions
        .take(&query.state)
        .ok_or_else(|| ApiError::bad("invalid or expired plugin auth state"))?;

    if query.error.is_some() {
        let _ = db::insert_audit(
            &state.pool,
            "admin",
            "plugin_auth_cancelled",
            "plugin",
            &session.plugin_id,
            &session.flow_name,
            "Provider authorization was cancelled or rejected.",
        )
        .await;
        return Ok(Redirect::to("/admin/plugins?plugin_auth=cancelled"));
    }

    let code = query
        .code
        .as_deref()
        .filter(|code| !code.trim().is_empty())
        .ok_or_else(|| ApiError::bad("authorization callback is missing code"))?;

    let manager = plugin_manager(&state)?;
    let result = match manager
        .auth_exchange(
            &session.plugin_id,
            &session.flow_name,
            code,
            &session.redirect_uri,
            Some(&session.pkce_verifier),
        )
        .await
    {
        Ok(result) => result,
        Err(error) => {
            tracing::warn!(
                plugin = %session.plugin_id,
                flow = %session.flow_name,
                error = %error,
                "plugin account authorization exchange failed"
            );
            let _ = db::insert_audit(
                &state.pool,
                "admin",
                "plugin_auth_failed",
                "plugin",
                &session.plugin_id,
                &session.flow_name,
                "Provider authorization code exchange failed.",
            )
            .await;
            return Ok(Redirect::to("/admin/plugins?plugin_auth=error"));
        }
    };

    if result.secret_json.len() > 256 * 1024 {
        return Err(ApiError::bad("plugin auth credential exceeds 256 KiB"));
    }
    let secret_value: Value = serde_json::from_str(&result.secret_json)
        .map_err(|_| ApiError::bad("plugin auth credential is not valid JSON"))?;
    if !secret_value.is_object() {
        return Err(ApiError::bad(
            "plugin auth credential must be a JSON object",
        ));
    }

    let provider = db::get_provider(&state.pool, &session.provider_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("provider not found"))?;
    if provider.credential_plugin != session.credential_binding {
        let _ = db::insert_audit(
            &state.pool,
            "admin",
            "plugin_auth_binding_changed",
            "provider",
            &provider.id,
            &provider.name,
            "Provider credential binding changed during browser authorization; enrollment refused.",
        )
        .await;
        return Ok(Redirect::to("/admin/plugins?plugin_auth=binding_changed"));
    }

    let encrypted = state
        .crypto
        .encrypt(&result.secret_json)
        .map_err(ApiError::internal)?;
    let label = result
        .account_label
        .as_deref()
        .map(str::trim)
        .filter(|label| !label.is_empty())
        .unwrap_or(&provider.name);
    let account_id = db::insert_account(
        &state.pool,
        &provider.id,
        label,
        &encrypted,
        "oauth:****",
        1,
        1,
        None,
        "unknown",
    )
    .await
    .map_err(ApiError::internal)?;

    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "plugin_account_authorized",
        "account",
        &account_id,
        label,
        &format!(
            "Authorized account through plugin {} flow {}.",
            session.plugin_id, session.flow_name
        ),
    )
    .await;
    state
        .registry
        .reload(&state.pool)
        .await
        .map_err(ApiError::internal)?;

    Ok(Redirect::to("/admin/plugins?plugin_auth=success"))
}

/// `POST /admin/api/plugins/{id}/enable`.
pub async fn enable_plugin(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
) -> ApiResult {
    let manager = plugin_manager(&state)?;
    manager.enable(&id).await.map_err(plugin_bad)?;
    register_enabled_plugin_capabilities(&state, &id).await;
    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "plugin_enabled",
        "plugin",
        &id,
        &id,
        "Enabled plugin.",
    )
    .await;
    Ok(Json(json!({ "ok": true, "id": id, "enabled": true })))
}

/// `POST /admin/api/plugins/{id}/disable`.
pub async fn disable_plugin(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
) -> ApiResult {
    let manager = plugin_manager(&state)?;
    manager.disable(&id).await.map_err(ApiError::internal)?;
    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "plugin_disabled",
        "plugin",
        &id,
        &id,
        "Disabled plugin.",
    )
    .await;
    Ok(Json(json!({ "ok": true, "id": id, "enabled": false })))
}

/// `DELETE /admin/api/plugins/{id}` — remove a plugin.
pub async fn remove_plugin(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
) -> ApiResult {
    let manager = plugin_manager(&state)?;
    manager.remove(&id).await.map_err(ApiError::internal)?;
    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "plugin_removed",
        "plugin",
        &id,
        &id,
        "Removed plugin and its stored state.",
    )
    .await;
    Ok(Json(json!({ "ok": true, "id": id })))
}

/// `POST /admin/api/plugins/{id}/validate` — re-instantiate and self-check.
pub async fn validate_plugin(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
) -> ApiResult {
    let manager = plugin_manager(&state)?;
    let provides = manager.validate(&id).await.map_err(plugin_bad)?;
    Ok(Json(json!({ "ok": true, "id": id, "provides": provides })))
}

/// `GET /admin/api/plugins/{id}/permissions` — approved grants (§20).
pub async fn plugin_permissions(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
) -> ApiResult {
    let row = crate::plugins::store::get_plugin(&state.pool, &id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("plugin not found"))?;
    let approved = crate::plugins::store::permissions(&state.pool, &id)
        .await
        .map_err(ApiError::internal)?;
    let requested = row.manifest().map(|m| m.permissions).unwrap_or_default();
    Ok(Json(json!({
        "id": id,
        "requested": requested,
        "approved": approved,
    })))
}

/// `POST /admin/api/plugins/{id}/permissions/approve` — re-approve the declared
/// set (all-or-nothing, §20).
pub async fn approve_plugin_permissions(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
) -> ApiResult {
    let manager = plugin_manager(&state)?;
    let grants = manager.approve_permissions(&id).await.map_err(plugin_bad)?;
    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "plugin_permissions_approved",
        "plugin",
        &id,
        &id,
        &format!("Approved {} permission grant(s).", grants.len()),
    )
    .await;
    Ok(Json(json!({ "ok": true, "id": id, "approved": grants })))
}

/// `POST /admin/api/plugins/{id}/permissions/revoke` — revoke a grant (§20).
/// Revocation is all-or-nothing: the plugin is disabled if the requested set is
/// no longer fully granted. KV state is retained.
pub async fn revoke_plugin_permissions(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> ApiResult {
    let permission = body["permission"].as_str().unwrap_or("");
    if permission.is_empty() {
        return Err(ApiError::bad("provide a permission to revoke"));
    }
    let manager = plugin_manager(&state)?;
    manager
        .revoke_permission(&id, permission)
        .await
        .map_err(plugin_bad)?;
    let _ = db::insert_audit(
        &state.pool,
        "admin",
        "plugin_permission_revoked",
        "plugin",
        &id,
        &id,
        &format!("Revoked permission '{permission}'. Plugin KV state is retained."),
    )
    .await;
    Ok(Json(json!({
        "ok": true,
        "id": id,
        "revoked": permission,
        "enabled": false
    })))
}

/// `GET /admin/api/plugins/{id}/audit` — audit entries mentioning this plugin.
pub async fn plugin_audit(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
) -> ApiResult {
    let rows = db::recent_audit(&state.pool, 500)
        .await
        .map_err(ApiError::internal)?;
    let filtered: Vec<&db::AuditLogRow> = rows
        .iter()
        .filter(|r| r.target_type == "plugin" && r.target_id == id)
        .collect();
    Ok(Json(json!({ "id": id, "entries": filtered })))
}

/// `GET /admin/api/plugins/{id}/metrics` — counters + runtime state (§18).
pub async fn plugin_metrics(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
) -> ApiResult {
    let manager = plugin_manager(&state)?;
    let c = manager.counters();
    let runtime = crate::plugins::store::runtime_state(&state.pool, &id)
        .await
        .map_err(ApiError::internal)?;
    let bytes = crate::plugins::store::kv_bytes(&state.pool, &id)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({
        "id": id,
        "host_invocations_total": c.invocations,
        "host_faults_total": c.faults,
        "host_timeouts_total": c.timeouts,
        "host_cancellations_total": c.cancellations,
        "host_http_requests_total": c.http_requests,
        "storage_bytes": bytes,
        "runtime": runtime,
    })))
}

/// Decode a base64 (or hex) Ed25519 public key into 32 bytes.
fn decode_key(k: &str) -> Option<[u8; 32]> {
    use base64::Engine;
    if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(k.trim()) {
        if let Ok(arr) = <[u8; 32]>::try_from(b.as_slice()) {
            return Some(arr);
        }
    }
    if let Ok(b) = hex::decode(k.trim()) {
        if let Ok(arr) = <[u8; 32]>::try_from(b.as_slice()) {
            return Some(arr);
        }
    }
    None
}
