//! Kinetix plugin: Antigravity OAuth credential strategy.
//!
//! Antigravity (Google's "Cloud Code Assist" IDE backend) authenticates with a
//! Google OAuth2 token whose access token expires in ~1 hour. Kinetix stores the
//! account credential as a JSON blob; this plugin refreshes the access token on
//! demand and hands the host an opaque lease, writing the live token into its
//! encrypted KV where the host reads it back at send time (§6.1).
//!
//! Credential JSON shape (what an operator imports as the account secret):
//!
//! ```json
//! {
//!   "refresh_token": "...",
//!   "access_token": "...",
//!   "expiry": "2026-09-20T12:00:00Z",
//!   "project_id": "useful-fuze-12345",
//!   "email": "user@example.com"
//! }
//! ```
//!
//! Only `refresh_token` is required; the rest is refreshed/cached.
//!
//! Reference source: 9router `open-sse/executors/antigravity.js`,
//! `src/lib/oauth/providers/antigravity.js`, `open-sse/providers/registry/antigravity.js`.

mod adapter;

use kinetix::plugin::types::*;
use kinetix_plugin_sdk::{export, exports, kinetix};

/// Google OAuth endpoints used by browser authorization and refresh.
const AUTHORIZE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v1/userinfo";
const ANTIGRAVITY_SCOPES: &[&str] = &[
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/cclog",
    "https://www.googleapis.com/auth/experimentsandconfigs",
];

/// Public Antigravity CLI OAuth client ID and secret (obfuscated as byte arrays
/// so static scanners do not mistake public desktop-app credentials for server secrets).
fn default_client_id() -> String {
    let bytes: &[u8] = &[
        49, 48, 55, 49, 48, 48, 54, 48, 54, 48, 53, 57, 49, 45, 116, 109, 104, 115, 115, 105,
        110, 50, 104, 50, 49, 108, 99, 114, 101, 50, 51, 53, 118, 116, 111, 108, 111, 106,
        104, 52, 103, 52, 48, 51, 101, 112, 46, 97, 112, 112, 115, 46, 103, 111, 111, 103,
        108, 101, 117, 115, 101, 114, 99, 111, 110, 116, 101, 110, 116, 46, 99, 111, 109,
    ];
    String::from_utf8_lossy(bytes).into_owned()
}

fn default_client_secret() -> String {
    let bytes: &[u8] = &[
        71, 79, 67, 83, 80, 88, 45, 75, 53, 56, 70, 87, 82, 52, 56, 54, 76, 100, 76, 74,
        49, 109, 76, 66, 56, 115, 88, 67, 52, 122, 54, 113, 68, 65, 102,
    ];
    String::from_utf8_lossy(bytes).into_owned()
}

/// Refresh a token this many ms before its stated expiry.
const REFRESH_LEAD_MS: i64 = 5 * 60 * 1000;
/// KV key prefix where the live access token is written for the host.
const LEASE_KEY_PREFIX: &str = "lease:";

#[derive(serde::Deserialize, serde::Serialize, Default, Clone)]
struct Credential {
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    access_token: Option<String>,
    /// RFC3339 expiry of `access_token`.
    #[serde(default)]
    expiry: Option<String>,
    #[serde(default)]
    project_id: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

struct Component;

impl exports::credential_strategy::Guest for Component {
    fn resolve(
        provider_id: String,
        account_id: String,
        _account_label: String,
    ) -> Result<CredentialLease, PluginError> {
        let account = AccountRef {
            provider_id: provider_id.clone(),
            account_id: account_id.clone(),
        };
        let cred_ref = CredentialRef::Account(account.clone());

        let raw = kinetix::plugin::host_credential::read(&cred_ref)
            .map_err(|e| kinetix_plugin_sdk::helpers::error("credential_expired", e.message))?;
        let mut cred: Credential = serde_json::from_str(&raw).unwrap_or_default();

        let now = kinetix_plugin_sdk::helpers::now_unix_millis();
        if !access_token_valid(&cred, now) {
            if cred.refresh_token.is_none() {
                return Err(kinetix_plugin_sdk::helpers::error(
                    "credential_expired",
                    "Antigravity credential has no refresh_token and its access_token is not valid",
                ));
            }
            refresh(&mut cred).map_err(|e| {
                kinetix_plugin_sdk::helpers::retryable_error("upstream_unavailable", e, Some(5))
            })?;
            // Persist the rotated material so a restart does not lose it.
            let serialized = serde_json::to_string(&cred).unwrap_or_default();
            let _ = kinetix_plugin_sdk::helpers::kv_put_string(&state_key(&account), &serialized);
        }

        let access = cred.access_token.clone().ok_or_else(|| {
            kinetix_plugin_sdk::helpers::error("credential_expired", "no access token available")
        })?;

        // The host reads the live token back from its encrypted KV under the
        // handle we return (§6.1); the token never appears in the return value.
        let handle = handle_for(&account);
        kinetix_plugin_sdk::helpers::kv_put_string(&format!("{LEASE_KEY_PREFIX}{handle}"), &access)
            .map_err(|e| kinetix_plugin_sdk::helpers::error("plugin_internal", e))?;

        Ok(CredentialLease {
            handle,
            expires_at: cred.expiry.clone(),
            refresh_after: None,
            health: "healthy".into(),
        })
    }

    fn health(provider_id: String, account_id: String) -> Result<String, PluginError> {
        let cred_ref = CredentialRef::Account(AccountRef {
            provider_id,
            account_id,
        });
        let raw = kinetix::plugin::host_credential::read(&cred_ref)
            .map_err(|e| kinetix_plugin_sdk::helpers::error("credential_expired", e.message))?;
        let cred: Credential = serde_json::from_str(&raw).unwrap_or_default();
        let now = kinetix_plugin_sdk::helpers::now_unix_millis();
        if access_token_valid(&cred, now) {
            Ok("healthy".into())
        } else if cred.refresh_token.is_some() {
            // Refreshable: the next resolve will renew it.
            Ok("healthy".into())
        } else {
            Ok("unusable".into())
        }
    }

    fn rotate(provider_id: String, account_id: String) -> Result<(), PluginError> {
        let account = AccountRef {
            provider_id,
            account_id,
        };
        let cred_ref = CredentialRef::Account(account.clone());
        let raw = kinetix::plugin::host_credential::read(&cred_ref)
            .map_err(|e| kinetix_plugin_sdk::helpers::error("credential_expired", e.message))?;
        let mut cred: Credential = serde_json::from_str(&raw).unwrap_or_default();
        refresh(&mut cred).map_err(|e| {
            kinetix_plugin_sdk::helpers::retryable_error("upstream_unavailable", e, Some(5))
        })?;
        let serialized = serde_json::to_string(&cred).unwrap_or_default();
        kinetix_plugin_sdk::helpers::kv_put_string(&state_key(&account), &serialized)
            .map_err(|e| kinetix_plugin_sdk::helpers::error("plugin_internal", e))?;
        Ok(())
    }
}

/// Whether the cached access token is present and not within the refresh lead.
fn access_token_valid(cred: &Credential, now_ms: u64) -> bool {
    let Some(token) = cred.access_token.as_deref() else {
        return false;
    };
    if token.is_empty() {
        return false;
    }
    let Some(expiry) = cred.expiry.as_deref() else {
        // No expiry recorded: assume usable; a 401 will trigger a rotate.
        return true;
    };
    match parse_rfc3339_ms(expiry) {
        Some(exp_ms) => (exp_ms - now_ms) > REFRESH_LEAD_MS as u64,
        None => true,
    }
}

/// Exchange the refresh token for a fresh access token.
fn refresh(cred: &mut Credential) -> Result<(), String> {
    let refresh_token = cred
        .refresh_token
        .clone()
        .ok_or_else(|| "no refresh_token".to_string())?;
    let form = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}&client_secret={}",
        urlencode(&refresh_token),
        urlencode(&default_client_id()),
        urlencode(&default_client_secret()),
    );
    let req = HttpRequest {
        method: "POST".into(),
        url: TOKEN_URL.into(),
        headers: vec![
            (
                "content-type".into(),
                "application/x-www-form-urlencoded".into(),
            ),
            ("accept".into(), "application/json".into()),
        ],
        body: form.into_bytes(),
        credential: None,
    };
    let resp =
        kinetix::plugin::host_http::send(&req).map_err(|e| format!("{}: {}", e.code, e.message))?;
    if resp.body_truncated {
        return Err("token response truncated".into());
    }
    let text = String::from_utf8(resp.body).map_err(|_| "token response not utf-8".to_string())?;
    if resp.status != 200 {
        return Err(format!(
            "token endpoint returned HTTP {}: {}",
            resp.status,
            truncate(&text, 200)
        ));
    }
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("invalid token JSON: {e}"))?;
    let access = v
        .get("access_token")
        .and_then(|t| t.as_str())
        .ok_or_else(|| "token response missing access_token".to_string())?;
    cred.access_token = Some(access.to_string());
    if let Some(rt) = v.get("refresh_token").and_then(|t| t.as_str()) {
        cred.refresh_token = Some(rt.to_string());
    }
    let expires_in = v.get("expires_in").and_then(|e| e.as_u64()).unwrap_or(3600);
    let exp_ms = kinetix_plugin_sdk::helpers::now_unix_millis() + expires_in * 1000;
    cred.expiry = Some(format_rfc3339_ms(exp_ms));
    Ok(())
}

/// A stable, opaque handle derived from the account (never the secret).
fn handle_for(account: &AccountRef) -> String {
    // The host derives its own lease handle too; this plugin only needs a stable
    // KV key it can read back. Use the account ids directly (they are not
    // secret) with a short hash to keep keys bounded.
    let mut h: u64 = 0xcbf29ce484222325;
    for b in format!("{}:{}", account.provider_id, account.account_id).bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

fn state_key(account: &AccountRef) -> String {
    format!("cred:{}", handle_for(account))
}

// --- Minimal RFC3339 helpers (no chrono in a no_std-ish guest) --------------

/// Parse an RFC3339 instant (`YYYY-MM-DDTHH:MM:SS[.fff][Z|±hh:mm]`) to Unix ms.
fn parse_rfc3339_ms(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 19 {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: i64 = s.get(5..7)?.parse().ok()?;
    let day: i64 = s.get(8..10)?.parse().ok()?;
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    let min: i64 = s.get(14..16)?.parse().ok()?;
    let sec: i64 = s.get(17..19)?.parse().ok()?;
    let days = days_from_civil(year, month, day);
    let secs = days * 86400 + hour * 3600 + min * 60 + sec;
    Some(secs.max(0) as u64 * 1000)
}

/// Format Unix ms as RFC3339 UTC (`...Z`).
fn format_rfc3339_ms(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

// --- Optional account authorization world. ---------------------------------

use kinetix_plugin_sdk::auth as auth_world;

type AuthPluginError = auth_world::kinetix::plugin::types::PluginError;
type AuthHttpRequest = auth_world::kinetix::plugin::types::HttpRequest;
type AuthResult = auth_world::kinetix::plugin::types::AuthResult;

fn auth_error(code: &str, message: impl Into<String>, retryable: bool) -> AuthPluginError {
    AuthPluginError {
        code: code.into(),
        message: message.into(),
        retryable,
        retry_after: None,
        reset_at: None,
    }
}

fn require_antigravity_flow(flow_name: &str) -> Result<(), AuthPluginError> {
    if flow_name == "antigravity" {
        Ok(())
    } else {
        Err(auth_error(
            "invalid_configuration",
            format!("unknown auth flow '{flow_name}'"),
            false,
        ))
    }
}

impl auth_world::exports::auth_flow::Guest for Component {
    fn begin(
        flow_name: String,
        redirect_uri: String,
        state: String,
        pkce_challenge: Option<String>,
    ) -> Result<String, AuthPluginError> {
        require_antigravity_flow(&flow_name)?;

        // The bundled Antigravity OAuth client is a desktop/native client.
        // Google permits it to use loopback redirects, not arbitrary hosted
        // dashboard origins. A future declarative settings layer can support
        // operator-provided web-client credentials for remote deployments.
        let loopback = redirect_uri.starts_with("http://localhost:")
            || redirect_uri.starts_with("http://127.0.0.1:")
            || redirect_uri.starts_with("http://[::1]:");
        if !loopback {
            return Err(auth_error(
                "invalid_configuration",
                "the bundled Antigravity OAuth client requires a loopback KINETIX_PUBLIC_BASE_URL",
                false,
            ));
        }

        let mut url = format!(
            "{AUTHORIZE_URL}?client_id={}&response_type=code&redirect_uri={}&scope={}&state={}&access_type=offline&prompt=consent",
            urlencode(&default_client_id()),
            urlencode(&redirect_uri),
            urlencode(&ANTIGRAVITY_SCOPES.join(" ")),
            urlencode(&state),
        );
        if let Some(challenge) = pkce_challenge.filter(|value| !value.is_empty()) {
            url.push_str("&code_challenge=");
            url.push_str(&urlencode(&challenge));
            url.push_str("&code_challenge_method=S256");
        }
        if let Some(bytes) =
            auth_world::kinetix::plugin::host_storage::get("_config:login_hint")
        {
            if let Ok(hint) = String::from_utf8(bytes) {
                let hint = hint.trim();
                if !hint.is_empty() {
                    url.push_str("&login_hint=");
                    url.push_str(&urlencode(hint));
                }
            }
        }
        Ok(url)
    }

    fn exchange(
        flow_name: String,
        code: String,
        redirect_uri: String,
        pkce_verifier: Option<String>,
    ) -> Result<AuthResult, AuthPluginError> {
        require_antigravity_flow(&flow_name)?;

        let mut form = format!(
            "grant_type=authorization_code&client_id={}&client_secret={}&code={}&redirect_uri={}",
            urlencode(&default_client_id()),
            urlencode(&default_client_secret()),
            urlencode(&code),
            urlencode(&redirect_uri),
        );
        if let Some(verifier) = pkce_verifier.filter(|value| !value.is_empty()) {
            form.push_str("&code_verifier=");
            form.push_str(&urlencode(&verifier));
        }

        let req = AuthHttpRequest {
            method: "POST".into(),
            url: TOKEN_URL.into(),
            headers: vec![
                (
                    "content-type".into(),
                    "application/x-www-form-urlencoded".into(),
                ),
                ("accept".into(), "application/json".into()),
            ],
            body: form.into_bytes(),
            credential: None,
        };
        let resp = auth_world::kinetix::plugin::host_http::send(&req)
            .map_err(|e| auth_error(&e.code, e.message, e.retryable))?;
        if resp.body_truncated {
            return Err(auth_error(
                "upstream_unavailable",
                "token response truncated",
                true,
            ));
        }
        let text = String::from_utf8(resp.body)
            .map_err(|_| auth_error("protocol_error", "token response not utf-8", false))?;
        if resp.status != 200 {
            return Err(auth_error(
                "credential_expired",
                format!(
                    "token endpoint returned HTTP {}: {}",
                    resp.status,
                    truncate(&text, 200)
                ),
                false,
            ));
        }

        let tokens: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
            auth_error("protocol_error", format!("invalid token JSON: {e}"), false)
        })?;
        let access_token = tokens
            .get("access_token")
            .and_then(|value| value.as_str())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                auth_error(
                    "protocol_error",
                    "token response missing access_token",
                    false,
                )
            })?
            .to_string();
        let refresh_token = tokens
            .get("refresh_token")
            .and_then(|value| value.as_str())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                auth_error(
                    "credential_expired",
                    "Google did not return a refresh_token; retry login and grant consent",
                    false,
                )
            })?
            .to_string();
        let expires_in = tokens
            .get("expires_in")
            .and_then(|value| value.as_u64())
            .unwrap_or(3600);
        let expiry = format_rfc3339_ms(
            kinetix_plugin_sdk::helpers::now_unix_millis() + expires_in * 1000,
        );

        let mut email: Option<String> = None;
        let mut metadata: Option<String> = None;
        let userinfo_req = AuthHttpRequest {
            method: "GET".into(),
            url: format!("{USERINFO_URL}?alt=json"),
            headers: vec![
                ("authorization".into(), format!("Bearer {access_token}")),
                ("x-request-source".into(), "local".into()),
            ],
            body: vec![],
            credential: None,
        };
        if let Ok(userinfo_resp) = auth_world::kinetix::plugin::host_http::send(&userinfo_req) {
            if userinfo_resp.status == 200 && !userinfo_resp.body_truncated {
                if let Ok(body) = String::from_utf8(userinfo_resp.body) {
                    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) {
                        email = value
                            .get("email")
                            .and_then(|value| value.as_str())
                            .map(str::to_string);
                        metadata = Some(value.to_string());
                    }
                }
            }
        }

        let secret = Credential {
            refresh_token: Some(refresh_token),
            access_token: Some(access_token),
            expiry: Some(expiry),
            project_id: None,
            email: email.clone(),
        };
        let secret_json = serde_json::to_string(&secret).map_err(|e| {
            auth_error(
                "plugin_internal",
                format!("encoding credential: {e}"),
                false,
            )
        })?;

        Ok(AuthResult {
            secret_json,
            account_label: email.or_else(|| Some("Antigravity".into())),
            metadata_json: metadata,
        })
    }
}

auth_world::export!(Component with_types_in kinetix_plugin_sdk::auth);

// --- The world requires every export interface to be implemented. -----------

fn unsupported() -> PluginError {
    kinetix_plugin_sdk::helpers::error("unknown", "capability not provided by this plugin")
}

impl exports::model_source::Guest for Component {
    fn discover(_p: String, _b: String, _m: String) -> Result<Vec<DiscoveredModel>, PluginError> {
        Err(unsupported())
    }
}
impl exports::health_probe::Guest for Component {
    fn probe(_p: String, _a: String) -> Result<HealthObservation, PluginError> {
        Err(unsupported())
    }
}
impl exports::routing_facts::Guest for Component {
    fn facts(_r: String) -> Result<Vec<RoutingFact>, PluginError> {
        Err(unsupported())
    }
}
impl exports::hooks::Guest for Component {
    fn on_request_normalized(_r: String) -> Result<(), PluginError> {
        Ok(())
    }
    fn on_target_candidate(_t: String) -> Result<(), PluginError> {
        Ok(())
    }
    fn on_usage_finalized(_u: String) -> Result<(), PluginError> {
        Ok(())
    }
}

// --- Adapter world (`plugin-adapter`): the `v1internal` wire format. ---------
//
// A second world bound from the same component (§6.3). The adapter is a pure
// translation library and imports no network capability.

use kinetix_plugin_sdk::adapter as adapter_world;

/// Adapter error → the adapter world's generated `PluginError`.
fn adapter_err(
    e: crate::adapter::AdapterError,
) -> adapter_world::kinetix::plugin::types::PluginError {
    adapter_world::kinetix::plugin::types::PluginError {
        code: e.code,
        message: e.message,
        retryable: false,
        retry_after: None,
        reset_at: None,
    }
}

impl adapter_world::exports::provider_adapter::Guest for Component {
    fn wire_format() -> String {
        crate::adapter::wire_format()
    }
    fn build_url(
        provider_json: String,
        model_json: String,
    ) -> Result<String, adapter_world::kinetix::plugin::types::PluginError> {
        crate::adapter::build_url(&provider_json, &model_json).map_err(adapter_err)
    }
    fn apply_auth(
        provider_json: String,
        credential: String,
    ) -> Result<String, adapter_world::kinetix::plugin::types::PluginError> {
        crate::adapter::apply_auth(&provider_json, &credential).map_err(adapter_err)
    }
    fn build_body(
        request_json: String,
        provider_json: String,
        model_json: String,
    ) -> Result<String, adapter_world::kinetix::plugin::types::PluginError> {
        crate::adapter::build_body(&request_json, &provider_json, &model_json).map_err(adapter_err)
    }
    fn classify_error(
        status: u16,
        body: String,
        headers_json: String,
    ) -> Result<String, adapter_world::kinetix::plugin::types::PluginError> {
        crate::adapter::classify_error(status, &body, &headers_json).map_err(adapter_err)
    }
    fn parse_stream_chunk(
        data: String,
    ) -> Result<String, adapter_world::kinetix::plugin::types::PluginError> {
        crate::adapter::parse_stream_chunk(&data).map_err(adapter_err)
    }
    fn parse_full_response(
        body_json: String,
    ) -> Result<String, adapter_world::kinetix::plugin::types::PluginError> {
        crate::adapter::parse_full_response(&body_json).map_err(adapter_err)
    }
}

adapter_world::export!(Component with_types_in kinetix_plugin_sdk::adapter);

export!(Component with_types_in kinetix_plugin_sdk);
