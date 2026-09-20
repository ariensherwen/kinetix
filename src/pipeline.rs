//! Request pipeline: auth -> limits -> route resolution (predicates) -> account
//! selection (health, circuit breaker, sticky affinity) -> adapter call ->
//! pre-commit failover -> streaming encode -> async usage logging + Route Trace.
//!
//! Commit semantics (FR-4.5, NFR-2.9): retry/fallback happens **only before**
//! the commit point (the first client response bytes). A failure after commit
//! terminates the stream with a format-correct error and is never spliced.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::response::Response;
use bytes::Bytes;
use serde_json::Value;
use tokio::sync::mpsc;

use crate::adapters::{Adapter, UpstreamContext};
use crate::app::AppState;
use crate::cost;
use crate::db::{self, UsageLogRow};
use crate::frontends::{self, Encoder, EncoderCtx, FrontendFormat};
use crate::passthrough;
use crate::pool;
use crate::predicate::{self, PluginFacts, RequestFacts, TargetFacts, TargetPredicate};
use crate::registry::{Resolved, ResolvedTarget};
use crate::trace::RouteTrace;
use crate::types::{
    FailureKind, InternalRequest, ProxyError, StreamEvent, TokenUsage, UpstreamFailure,
};

const STICKY_TTL: Duration = Duration::from_secs(30 * 60);
const MAX_PRE_COMMIT_DEADLINE: Duration = Duration::from_secs(30);
const CIRCUIT_THRESHOLD: i64 = 4;
/// SSE keepalive cadence. Cloudflare drops proxied connections that are idle
/// for ~100s (HTTP 524), so a silent thinking phase must be kept alive well
/// within that window (NFR-1 / FR-9.4). Exposed for tests.
pub const KEEPALIVE_INTERVAL_SECS: u64 = 15;
const CIRCUIT_OPEN_SECS: i64 = 30;
/// Bounded exponential backoff between pre-commit retry attempts (FR-4.4):
/// 100ms, 200ms, 400ms, capped at 1s, so a failing pool cannot be hot-looped.
const BACKOFF_BASE_MS: u64 = 100;
const BACKOFF_CAP_MS: u64 = 1000;

/// Request-scoped metadata carried into the usage log and Route Trace.
pub struct RequestMeta {
    pub request_id: String,
    pub key_id: Option<String>,
    pub key_name: Option<String>,
    pub key_tag: Option<String>,
    pub client_format: &'static str,
    pub requested_model: String,
    pub route_id: Option<String>,
    pub route_name: Option<String>,
    pub fallback_hops: i64,
    pub retry_count: i64,
    pub fallback_path: Vec<String>,
    pub cache_status: &'static str,
    pub commit_state: &'static str,
    pub session: Option<String>,
    /// Set by a watchdog when the client disconnects, so an in-flight upstream
    /// response can be aborted even if the write channel still looks open.
    pub disconnected: Arc<std::sync::atomic::AtomicBool>,
    /// When the client was first observed to have disconnected (for NFR-1.10
    /// cancellation-latency measurement, distinct from request start).
    pub disconnect_at: Arc<parking_lot::Mutex<Option<Instant>>>,
}

impl RequestMeta {
    pub fn new(request_id: String, format: FrontendFormat, requested_model: String) -> Self {
        RequestMeta {
            request_id,
            key_id: None,
            key_name: None,
            key_tag: None,
            client_format: format.as_str(),
            requested_model,
            route_id: None,
            route_name: None,
            fallback_hops: 0,
            retry_count: 0,
            fallback_path: Vec::new(),
            cache_status: "bypass",
            commit_state: "",
            session: None,
            disconnected: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            disconnect_at: Arc::new(parking_lot::Mutex::new(None)),
        }
    }
}

/// The result of a successful upstream connection.
struct Attempt {
    target: ResolvedTarget,
    upstream_request_id: Option<String>,
    stream: Option<reqwest::Response>,
    adapter: Arc<dyn Adapter>,
    /// Whether this attempt uses same-format passthrough (FR-2.7).
    passthrough: bool,
}

/// Run the full pipeline and produce a client response.
///
/// A single immutable snapshot is taken at entry and used for the whole
/// request, so a concurrent configuration change never alters an in-flight
/// request (NFR-2.10).
///
/// Cancellation note (FR-2.9): the client-disconnect watchdog is the response
/// body's drop-guard, which only exists once a response is produced. During the
/// pre-commit selection/connect window there is no body to observe, so a client
/// that goes away then is noticed only when the upstream responds or the
/// provider timeout elapses. That window is bounded by `provider.timeout_ms`.
/// Post-commit cancellation is immediate (the guard flips the flag and wakes the
/// driver).
pub async fn run(
    state: &AppState,
    format: FrontendFormat,
    key: Option<db::VirtualKeyRow>,
    mut req: InternalRequest,
    request_id: String,
    allow_fallback: bool,
    session: Option<String>,
) -> Result<Response, ProxyError> {
    let started = Instant::now();
    let snap = state.registry.snapshot();
    let mut trace = RouteTrace::new(request_id.clone(), req.requested_model.clone());
    let mut meta = RequestMeta::new(request_id.clone(), format, req.requested_model.clone());
    meta.session = session.clone();
    if let Some(k) = &key {
        meta.key_id = Some(k.id.clone());
        meta.key_name = Some(k.name.clone());
        if !k.tag.is_empty() {
            meta.key_tag = Some(k.tag.clone());
        }
    }
    state.total_requests.fetch_add(1, Ordering::Relaxed);
    state.live.start(
        &request_id,
        &format!("{format:?}").to_lowercase(),
        &req.requested_model,
        meta.key_name.clone(),
        None,
    );
    state
        .flight
        .record(&request_id, 0, "request_accepted", format!("{format:?}"));
    state.flight.record(
        &request_id,
        started.elapsed().as_millis() as u64,
        "auth_complete",
        meta.key_name.clone().unwrap_or_else(|| "anonymous".into()),
    );

    // 1. Resolve the route against the request's snapshot.
    let resolved =
        crate::registry::Registry::resolve_in(&snap, &req.requested_model).ok_or_else(|| {
            ProxyError::not_found(format!(
                "model '{}' is not configured. Use GET /v1/models to list available models.",
                req.requested_model
            ))
        })?;
    trace.step(
        "resolve",
        None,
        format!("resolved '{}'", req.requested_model),
    );

    // 2. Build the ordered attempt list, evaluating target predicates.
    let needs = req.capability_needs();
    let request_facts = RequestFacts {
        frontend: format.as_str(),
        requested_model: &req.requested_model,
        requested_route: None,
        key_tag: meta.key_tag.as_deref(),
        has_tools: needs.tools,
        has_images: needs.vision,
        has_reasoning: needs.reasoning,
        input_tokens: req.approx_input_tokens(),
    };

    // 2b. Read-only request hook (§6.6): observe the normalized request before
    // routing. Fire-and-forget on the bounded async queue; it can never block,
    // fail, or slow a client request.
    if let Some(manager) = state.plugin_manager().cloned() {
        let json = serde_json::json!({
            "request_id": meta.request_id,
            "frontend": format.as_str(),
            "requested_model": req.requested_model,
            "has_tools": needs.tools,
            "has_images": needs.vision,
            "has_reasoning": needs.reasoning,
            "input_tokens": req.approx_input_tokens(),
        })
        .to_string();
        state.spawn_hook(move || async move {
            let mut hooks = tokio::task::JoinSet::new();
            for id in manager.plugins_with_hook("on_request_normalized").await {
                let manager = manager.clone();
                let json = json.clone();
                hooks.spawn(async move {
                    let _ = manager.hook_request_normalized(&id, &json).await;
                });
            }
            while hooks.join_next().await.is_some() {}
        });
    }

    let (mut targets, route) = match resolved {
        Resolved::Single {
            provider_id,
            model_id,
        } => {
            let model = snap
                .models
                .get(&model_id)
                .cloned()
                .ok_or_else(|| ProxyError::not_found("model not found"))?;
            let provider = snap
                .providers
                .get(&provider_id)
                .cloned()
                .ok_or_else(|| ProxyError::not_found("provider not found"))?;
            let accounts = select_accounts(&snap, &provider_id, None)?;
            let targets: Vec<ResolvedTarget> = accounts
                .into_iter()
                .map(|account| ResolvedTarget {
                    account,
                    model: model.clone(),
                    provider: provider.clone(),
                    priority: 1,
                    weight: 1,
                    predicate: TargetPredicate::default(),
                    param_overrides: Value::Null,
                })
                .collect();
            (targets, None)
        }
        Resolved::Route { route, targets } => {
            meta.route_id = Some(route.id.clone());
            meta.route_name = Some(route.name.clone());
            trace.route_id = Some(route.id.clone());
            trace.route_name = Some(route.name.clone());
            // Request facts now know the route name.
            let request_facts = RequestFacts {
                requested_route: Some(&route.name),
                ..request_facts
            };
            let ordered = order_route_targets(state, &route, targets).await;
            // Read-only target hook (§6.6): observe each candidate target before
            // eligibility filtering. Fire-and-forget; never blocks routing.
            if let Some(manager) = state.plugin_manager().cloned() {
                let req_id = meta.request_id.clone();
                for t in &ordered {
                    let json = serde_json::json!({
                        "request_id": req_id,
                        "route": route.name,
                        "model_id": t.model.id,
                        "provider_id": t.provider.id,
                        "provider": t.provider.name,
                        "account": t.account.label,
                        "priority": t.priority,
                    })
                    .to_string();
                    let manager = manager.clone();
                    state.spawn_hook(move || async move {
                        let mut hooks = tokio::task::JoinSet::new();
                        for id in manager.plugins_with_hook("on_target_candidate").await {
                            let manager = manager.clone();
                            let json = json.clone();
                            hooks.spawn(async move {
                                let _ = manager.hook_target_candidate(&id, &json).await;
                            });
                        }
                        while hooks.join_next().await.is_some() {}
                    });
                }
            }
            // Evaluate predicates for the trace and eligibility filtering.
            // Plugin routing facts (§6.4) are gathered once, before evaluation,
            // and exposed as `plugin.<id>.<name>` facts. A missing, failed, or
            // stale fact is left absent so it evaluates as `unknown`.
            let plugin_facts =
                gather_plugin_facts(state, &request_facts, Some(&meta.disconnected)).await;
            // Surface plugin facts and failures once, not per target (§19).
            for (name, value, source) in plugin_facts.iter_trace() {
                trace.plugin_fact(name, value, source);
            }
            for (plugin_id, reason) in &plugin_facts.failures {
                trace.plugin_fact_failure(plugin_id, reason);
            }
            let mut kept = Vec::new();
            for t in ordered {
                let tgt_facts = TargetFacts {
                    model_id: &t.model.id,
                    model_display: &t.model.display_name,
                    provider_id: &t.provider.id,
                    provider_name: &t.provider.name,
                    capabilities: &t.model.caps(),
                    capabilities_raw: &serde_json::from_str::<Value>(&t.model.capabilities)
                        .unwrap_or(Value::Null),
                    context_window: t.model.context_window,
                    max_output_tokens: t.model.max_output_tokens,
                };
                let elig = predicate::eligibility_with_facts(
                    &t.predicate,
                    &request_facts,
                    &tgt_facts,
                    &plugin_facts,
                );
                trace.candidate(
                    format!("{} @ {}", t.model.display_name, t.account.label),
                    elig.eligible,
                    Some(elig.result.as_str().to_string()),
                    elig.explanation.clone(),
                );
                if elig.eligible {
                    kept.push(t);
                }
            }
            (kept, Some(route))
        }
    };

    if let Some(route) = &route {
        meta.fallback_path.push(format!("route:{}", route.name));
        state.live.set_fallback_hops(&meta.request_id, 0, 0);
    }

    // Filter by key provider restrictions (FR-12.19) and compatibility (FR-12.11).
    let allowed_providers = key
        .as_ref()
        .map(|k| k.allowed_providers())
        .unwrap_or_default();
    let before = targets.len();
    targets.retain(|t| {
        if !allowed_providers.is_empty() && !allowed_providers.contains(&t.provider.id) {
            trace.step(
                "skip",
                Some(t.account.label.clone()),
                "provider not permitted by virtual key",
            );
            return false;
        }
        if !t.model.caps().satisfies(&needs) && t.provider.strict() {
            trace.step(
                "skip",
                Some(t.model.display_name.clone()),
                "capabilities unsatisfied (strict provider)",
            );
            return false;
        }
        if let Some(ctx) = t.model.context_window {
            if ctx > 0 && req.approx_input_tokens() > ctx as u64 {
                trace.step(
                    "skip",
                    Some(t.model.display_name.clone()),
                    format!("input exceeds context window ({ctx})"),
                );
                return false;
            }
        }
        true
    });
    let _ = before;

    // Circuit-open deferral (FR-4.2/FR-4.7): a target whose circuit is open and
    // is not yet due for a probe is moved behind all other candidates, but is
    // NOT removed — if every alternative fails it is still attempted and can
    // recover the account (half-open probing still applies in the loop).
    let (mut probeable, mut deferred): (Vec<_>, Vec<_>) = (Vec::new(), Vec::new());
    for t in targets.drain(..) {
        let status = pool::effective_status(&t.account);
        if matches!(status, pool::AccountStatus::CircuitOpen) && !pool::should_probe(&t.account) {
            deferred.push(t);
        } else {
            probeable.push(t);
        }
    }
    if !probeable.is_empty() && !deferred.is_empty() {
        trace.step(
            "candidate",
            None,
            format!(
                "{} circuit-open target(s) deferred behind healthy candidates",
                deferred.len()
            ),
        );
    }
    probeable.append(&mut deferred);
    let mut targets = probeable;

    if targets.is_empty() {
        trace.finish("no_eligible_target");
        state
            .live
            .finish(&meta.request_id, "no_eligible_target", 0, None, None);
        let _ = db::insert_route_trace(&state.pool, &trace).await;
        return Err(ProxyError::unsupported(
            "no configured target can satisfy this request (predicates, capabilities, or limits mismatch)",
        ));
    }

    let max_attempts = route
        .as_ref()
        .and_then(|c| c.max_attempts)
        .map(|m| m as usize)
        .unwrap_or(targets.len())
        .min(5)
        .max(1);

    // Prompt-cache affinity: reorder so a previously-served target leads.
    if let (Some(route), Some(session)) = (&route, &session) {
        if route.cache_affinity != 0 {
            if let Some(sticky_key) = state.sticky_lookup(session, STICKY_TTL) {
                if let Some(pos) = targets
                    .iter()
                    .position(|t| target_key(route, t) == sticky_key)
                {
                    targets.rotate_left(pos);
                    trace.step(
                        "candidate",
                        Some(targets[0].account.label.clone()),
                        "cache-affinity: session sticky target promoted (FR-7.3)",
                    );
                }
            }
        }
    }

    // 3. Attempt loop: all fallback happens before any client bytes.
    let mut last_error: Option<ProxyError> = None;
    let mut all_accounts: Vec<db::AccountRow> = Vec::new();
    let mut attempts_done = 0usize;
    let deadline = started + MAX_PRE_COMMIT_DEADLINE;

    for target in targets.iter() {
        if attempts_done >= max_attempts || Instant::now() >= deadline {
            if Instant::now() >= deadline {
                trace.step("skip", None, "pre-commit deadline exceeded");
            }
            break;
        }
        all_accounts.push(target.account.clone());

        // Health check (disabled/cooldown/exhausted/circuit-open).
        let status = pool::effective_status(&target.account);
        let mut probing = false;
        if !matches!(status, pool::AccountStatus::Healthy) {
            // Half-open recovery probe (FR-4.7): an account whose circuit has
            // opened may be retried once per bounded interval so it can recover
            // without an operator action. Success clears the circuit; failure
            // re-arms it. The probe is a normal attempt (so it refreshes account
            // state) rather than a synthetic one.
            if pool::should_probe(&target.account) {
                probing = true;
                trace.step(
                    "candidate",
                    Some(target.account.label.clone()),
                    format!("half-open recovery probe ({})", status.as_str()),
                );
            } else {
                let why = format!("{}:skipped({})", target.account.label, status.as_str());
                meta.fallback_path.push(why.clone());
                trace.step("skip", Some(target.account.label.clone()), why);
                state.record_skip();
                continue;
            }
        }

        // Soft quota check (FR-12.8).
        if let Ok(true) = pool::soft_quota_reached(&state.pool, &target.account).await {
            let _ = pool::mark_exhausted(
                &state.pool,
                &target.account.id,
                None,
                default_quota_window(&target.account),
                "soft quota reached",
            )
            .await;
            meta.fallback_path
                .push(format!("{}:soft_quota", target.account.label));
            trace.step(
                "skip",
                Some(target.account.label.clone()),
                "soft quota reached",
            );
            state.record_skip();
            continue;
        }

        // Credential. A provider bound to a plugin credential strategy
        // (§6.0) resolves through the plugin; otherwise the built-in static
        // strategy is used. A disabled/unavailable plugin fails closed.
        let credential = match state
            .credential_for(&target.provider, &target.account)
            .await
        {
            Ok(c) => {
                crate::alerts::record_credential_success();
                c.secret
            }
            Err(e) => {
                tracing::error!(account = %target.account.id, error = %e, "credential resolution failed");
                crate::alerts::record_credential_failure();
                last_error = Some(ProxyError::internal("credential unavailable"));
                trace.step(
                    "skip",
                    Some(target.account.label.clone()),
                    "credential unavailable",
                );
                continue;
            }
        };

        // Adapter selection honours a plugin wire-format binding (§6.0); a
        // bound-but-unavailable plugin adapter fails closed.
        let adapter = state.adapters.for_provider(&target.provider);

        // Continuity / portability policy on cross-provider fallback (FR-2.11).
        if attempts_done > 0 {
            if let Some(route) = &route {
                match apply_continuity(&mut req, route, target, &mut trace) {
                    Ok(()) => {}
                    Err(e) => return Err(e),
                }
            }
        }

        let ctx = UpstreamContext {
            provider: &target.provider,
            model: &target.model,
            credential,
        };

        // Parameter policy reject (FR-10.6): a request-level failure, never retried.
        if let Err(e) = check_param_policy(&target, &req) {
            trace.finish("rejected");
            state
                .live
                .finish(&meta.request_id, "rejected", 0, None, None);
            let _ = db::insert_route_trace(&state.pool, &trace).await;
            return Err(e);
        }

        // Same-format passthrough (FR-2.7).
        let use_passthrough =
            req.raw_body.is_some() && passthrough::is_passthrough(format, target.provider.wire());

        // Never silently drop behaviorally significant client fields on a
        // translating path (FR-2.8). A request-level failure; never retried.
        if !use_passthrough {
            if let Some(msg) = crate::frontends::translation_unsupported(&req.extra) {
                trace.finish("rejected");
                state
                    .live
                    .finish(&meta.request_id, "rejected", 0, None, None);
                let _ = db::insert_route_trace(&state.pool, &trace).await;
                return Err(ProxyError::new(
                    crate::types::ErrorKind::Unsupported,
                    format!("request uses a feature that cannot be translated: {msg}"),
                ));
            }
        }

        // Bounded exponential backoff between attempts (FR-4.4). Never applied
        // before the first attempt, and capped so a healthy pool is not slowed.
        if attempts_done > 0 {
            let exp = BACKOFF_BASE_MS.saturating_mul(1u64 << (attempts_done - 1).min(4));
            tokio::time::sleep(Duration::from_millis(exp.min(BACKOFF_CAP_MS))).await;
        }
        attempts_done += 1;
        state.live.set_fallback_hops(
            &meta.request_id,
            (attempts_done - 1) as u32,
            (attempts_done - 1) as u32,
        );
        state.flight.record(
            &meta.request_id,
            started.elapsed().as_millis() as u64,
            "upstream_connect",
            format!(
                "{} via {}{}",
                target.model.upstream_id,
                target.provider.wire_format,
                if use_passthrough {
                    " (passthrough)"
                } else {
                    ""
                }
            ),
        );

        if probing {
            // Record that we are actively probing this account (FR-4.7).
            let _ = db::touch_probe_at(&state.pool, &target.account.id).await;
        }

        // Kinetix-attributable dispatch overhead (auth, limits, routing,
        // predicates, body build) — recorded for the p95 added-latency alert
        // (Monitoring). Excludes upstream network time.
        crate::alerts::record_added_latency(started.elapsed().as_millis() as u64);

        match send_upstream(
            state,
            &adapter,
            &ctx,
            &req,
            use_passthrough,
            &meta.request_id,
        )
        .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    meta.fallback_hops = (attempts_done - 1) as i64;
                    meta.retry_count = (attempts_done - 1) as i64;
                    if attempts_done > 1 {
                        state.record_fallback();
                    }
                    meta.fallback_path
                        .push(format!("{}:200", target.account.label));
                    trace.step(
                        "attempt",
                        Some(target.account.label.clone()),
                        format!("HTTP 200 (attempt {attempts_done})"),
                    );
                    trace.final_target = Some(format!(
                        "{} @ {}",
                        target.model.display_name, target.account.label
                    ));
                    state.flight.record(
                        &meta.request_id,
                        started.elapsed().as_millis() as u64,
                        "upstream_headers",
                        "200",
                    );
                    // A successful attempt clears the circuit-breaker counter.
                    let _ = pool::clear_circuit(&state.pool, &target.account.id).await;
                    let upstream_request_id = extract_upstream_request_id(&resp);
                    let attempt = Attempt {
                        target: target.clone(),
                        upstream_request_id,
                        stream: Some(resp),
                        adapter: adapter.clone(),
                        passthrough: use_passthrough,
                    };
                    return Ok(stream_response(
                        state, snap, format, meta, req, attempt, started, key, trace,
                    ));
                }

                // Classify and maybe fail over.
                let status = resp.status().as_u16();
                let headers = resp.headers().clone();
                let body = resp.text().await.unwrap_or_default();
                let failure = adapter.classify_error(status, &body, &headers);
                state.flight.record(
                    &meta.request_id,
                    started.elapsed().as_millis() as u64,
                    "upstream_error",
                    format!("HTTP {status} {:?}", failure.kind),
                );

                if !failure.kind.is_key_level() || !allow_fallback {
                    trace.step(
                        "attempt",
                        Some(target.account.label.clone()),
                        format!("HTTP {status} (not retryable)"),
                    );
                    trace.finish("failed");
                    state.live.finish(
                        &meta.request_id,
                        "failed",
                        started.elapsed().as_millis() as u64,
                        None,
                        None,
                    );
                    let _ = db::insert_route_trace(&state.pool, &trace).await;
                    return Err(failure_to_error(&failure, &target));
                }

                handle_key_failure(state, &target, &failure, &mut meta, &mut trace).await;
                last_error = Some(failure_to_error(&failure, &target));
                continue;
            }
            Err(failure) => {
                state.flight.record(
                    &meta.request_id,
                    started.elapsed().as_millis() as u64,
                    "upstream_connect_failed",
                    format!("{:?}", failure.kind),
                );
                if !allow_fallback {
                    trace.finish("failed");
                    state.live.finish(
                        &meta.request_id,
                        "failed",
                        started.elapsed().as_millis() as u64,
                        None,
                        None,
                    );
                    let _ = db::insert_route_trace(&state.pool, &trace).await;
                    return Err(failure_to_error(&failure, &target));
                }
                handle_key_failure(state, &target, &failure, &mut meta, &mut trace).await;
                last_error = Some(failure_to_error(&failure, &target));
                continue;
            }
        }
    }

    // 4. Every target unavailable (FR-12.12).
    state.failures_pre_commit.fetch_add(1, Ordering::Relaxed);
    let retry_after = pool::soonest_recovery(&all_accounts)
        .map(|t| ((t - chrono::Utc::now()).num_seconds().max(1)) as u64);
    let name = route
        .as_ref()
        .map(|c| format!("route '{}'", c.name))
        .unwrap_or_else(|| req.requested_model.clone());
    let msg = last_error
        .map(|e| e.message)
        .unwrap_or_else(|| format!("all targets of {name} are currently unavailable"));
    trace.finish("all_targets_unavailable");
    state.live.finish(
        &meta.request_id,
        "all_targets_unavailable",
        started.elapsed().as_millis() as u64,
        None,
        None,
    );
    let _ = db::insert_route_trace(&state.pool, &trace).await;
    Err(ProxyError::all_unavailable(
        format!("{name}: {msg}"),
        retry_after,
    ))
}

fn target_key(route: &db::RouteRow, t: &ResolvedTarget) -> String {
    format!("{}|{}|{}", route.id, t.account.id, t.model.id)
}

fn default_quota_window(account: &db::AccountRow) -> i64 {
    match account.quota_type.as_str() {
        "daily" => 86_400,
        "monthly" => 30 * 86_400,
        "rolling" => account.quota_window_s.unwrap_or(86_400),
        _ => 86_400,
    }
}

/// Send the upstream request. Returns the raw response or a classified failure.
///
/// Applies outbound security controls before sending: credential host binding
/// (NFR-3.11) and connect-time DNS re-validation (NFR-3.9).
async fn send_upstream(
    state: &AppState,
    adapter: &Arc<dyn Adapter>,
    ctx: &UpstreamContext<'_>,
    req: &InternalRequest,
    use_passthrough: bool,
    request_id: &str,
) -> Result<reqwest::Response, UpstreamFailure> {
    let url = adapter.build_url(ctx).map_err(|e| UpstreamFailure {
        kind: FailureKind::BadRequest,
        status: None,
        retry_after_secs: None,
        message: e.message,
        quota_reset_at: None,
    })?;

    // Credential host binding (NFR-3.11): never send the credential elsewhere.
    if let Ok(parsed) = url::Url::parse(&url) {
        if let Some(host) = parsed.host_str() {
            if !ctx.provider.host_authorized(host) {
                return Err(UpstreamFailure {
                    kind: FailureKind::ConnectionError,
                    status: None,
                    retry_after_secs: None,
                    message: format!(
                        "credential host binding: '{host}' is not an authorized host for provider '{}'",
                        ctx.provider.name
                    ),
                    quota_reset_at: None,
                });
            }
            // TLS is mandatory except in the explicit dev mode (NFR-3.12).
            if parsed.scheme() != "https"
                && !state.config.allow_insecure_tls
                && !ctx.provider.insecure_tls()
            {
                return Err(UpstreamFailure {
                    kind: FailureKind::ConnectionError,
                    status: None,
                    retry_after_secs: None,
                    message: format!(
                        "plain-HTTP upstream '{url}' refused: TLS is mandatory \
                         (set KINETIX_ALLOW_INSECURE_TLS=true for local development)"
                    ),
                    quota_reset_at: None,
                });
            }
            // Connect-time DNS re-check against the SSRF policy (NFR-3.9).
            if !state.config.allow_private_upstreams && !host.parse::<std::net::IpAddr>().is_ok() {
                match resolve_and_check(host).await {
                    // Record the resolved destinations in redacted diagnostics
                    // (NFR-3.13). These are provider hosts, never secrets.
                    Ok(ips) => tracing::debug!(
                        target = %host,
                        resolved_ips = ?ips,
                        "outbound DNS resolved"
                    ),
                    Err(e) => {
                        return Err(UpstreamFailure {
                            kind: FailureKind::ConnectionError,
                            status: None,
                            retry_after_secs: None,
                            message: e,
                            quota_reset_at: None,
                        });
                    }
                }
            }
        }
    }

    // Passthrough forwards the client's raw body (model field rewritten);
    // translation builds a fresh body from the internal model.
    let body: Value = if use_passthrough {
        let raw = req.raw_body.as_deref().unwrap_or("{}");
        match passthrough::rewrite_model(raw, &ctx.model.upstream_id, !req.stream) {
            Some(s) => serde_json::from_str(&s).unwrap_or(Value::Null),
            None => adapter.build_body(ctx, req),
        }
    } else {
        adapter.build_body(ctx, req)
    };

    let client = if ctx.provider.follows_redirects() {
        &state.http_redirect
    } else {
        &state.http
    };

    let mut builder = client
        .post(&url)
        .header("content-type", "application/json")
        .header("accept", "text/event-stream")
        // Propagate the request id upstream (NFR-4.1).
        .header("x-request-id", request_id)
        .timeout(Duration::from_millis(ctx.provider.timeout_ms as u64))
        .json(&body);

    builder = adapter.apply_auth(ctx, builder);
    for (k, v) in ctx.provider.extra_headers_map() {
        builder = builder.header(k, v);
    }

    match builder.send().await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            let kind = if e.is_timeout() {
                FailureKind::Timeout
            } else {
                FailureKind::ConnectionError
            };
            Err(UpstreamFailure {
                kind,
                status: None,
                retry_after_secs: None,
                message: format!("connection to upstream failed: {}", classify_reqwest(&e)),
                quota_reset_at: None,
            })
        }
    }
}

/// Resolve a host and reject blocked ranges (connect-time rebinding guard).
/// Resolve a host and reject blocked destinations (NFR-3.9), returning the
/// resolved IPs so the caller can record them in redacted diagnostics
/// (NFR-3.13).
async fn resolve_and_check(host: &str) -> Result<Vec<String>, String> {
    let addrs = tokio::net::lookup_host((host, 443))
        .await
        .map_err(|e| format!("DNS resolution for '{host}' failed: {e}"))?;
    let mut ips = Vec::new();
    for addr in addrs {
        if crate::admin::is_blocked_ip(addr.ip()) {
            return Err(format!(
                "host '{host}' resolves to a blocked private/metadata address ({})",
                addr.ip()
            ));
        }
        ips.push(addr.ip().to_string());
    }
    Ok(ips)
}

fn classify_reqwest(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "timeout".to_string()
    } else if e.is_connect() {
        "connect error".to_string()
    } else {
        crate::crypto::redact(&e.to_string())
    }
}

fn extract_upstream_request_id(resp: &reqwest::Response) -> Option<String> {
    resp.headers()
        .get("x-request-id")
        .or_else(|| resp.headers().get("request-id"))
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

/// React to a key-level failure: cooldown / exhaustion / disable / circuit.
async fn handle_key_failure(
    state: &AppState,
    target: &ResolvedTarget,
    failure: &UpstreamFailure,
    meta: &mut RequestMeta,
    trace: &mut RouteTrace,
) {
    let account_id = &target.account.id;
    let label = target.account.label.clone();
    let detail = match failure.kind {
        FailureKind::RateLimit => {
            let cooldown = failure.retry_after_secs.unwrap_or(30).min(3600);
            let _ =
                pool::mark_rate_limited(&state.pool, account_id, cooldown, &failure.message).await;
            let d = format!("{label}:429(cooldown {cooldown}s)");
            meta.fallback_path.push(d.clone());
            d
        }
        FailureKind::QuotaExhausted => {
            let _ = pool::mark_exhausted(
                &state.pool,
                account_id,
                failure.quota_reset_at,
                default_quota_window(&target.account),
                &failure.message,
            )
            .await;
            let d = format!("{label}:quota_exhausted");
            meta.fallback_path.push(d.clone());
            d
        }
        FailureKind::AuthError => {
            let _ = db::set_account_status(
                &state.pool,
                account_id,
                "disabled",
                None,
                None,
                Some(&failure.message),
            )
            .await;
            let d = format!("{label}:auth_error(disabled)");
            meta.fallback_path.push(d.clone());
            d
        }
        FailureKind::ServerError | FailureKind::ConnectionError | FailureKind::Timeout => {
            let _ = db::set_account_status(
                &state.pool,
                account_id,
                "cooldown",
                Some(&(chrono::Utc::now() + chrono::Duration::seconds(10)).to_rfc3339()),
                None,
                Some(&failure.message),
            )
            .await;
            let d = format!("{label}:5xx(cooldown 10s)");
            meta.fallback_path.push(d.clone());
            d
        }
        FailureKind::BadRequest => format!("{label}:bad_request"),
    };
    // Circuit breaker (FR-4.7).
    let n = pool::record_failure(
        &state.pool,
        account_id,
        CIRCUIT_THRESHOLD,
        CIRCUIT_OPEN_SECS,
    )
    .await
    .unwrap_or(0);
    trace.step("attempt", Some(label), detail);
    if n >= CIRCUIT_THRESHOLD {
        trace.step(
            "skip",
            None,
            format!("circuit opened for account after {n} consecutive failures"),
        );
    }
    // Refresh the registry snapshot so later requests see the new status.
    let _ = state.registry.reload(&state.pool).await;
}

fn failure_to_error(failure: &UpstreamFailure, target: &ResolvedTarget) -> ProxyError {
    match failure.kind {
        FailureKind::RateLimit | FailureKind::QuotaExhausted => {
            ProxyError::rate_limited(failure.message.clone(), failure.retry_after_secs)
        }
        FailureKind::BadRequest => ProxyError::bad_request(failure.message.clone()),
        FailureKind::AuthError => ProxyError::upstream(format!(
            "upstream authentication failed for provider '{}'",
            target.provider.name
        )),
        FailureKind::Timeout => ProxyError::upstream("upstream request timed out".to_string()),
        FailureKind::ConnectionError | FailureKind::ServerError => {
            ProxyError::upstream(failure.message.clone())
        }
    }
}

/// Select healthy accounts for a provider's pool (single-model route).
/// Select candidate accounts for a provider from the request's snapshot.
///
/// Health state is refreshed into the snapshot by the background reload loop,
/// so no database I/O happens on the request path here (NFR-1.7).
fn select_accounts(
    snap: &crate::registry::Snapshot,
    provider_id: &str,
    preferred: Option<&str>,
) -> Result<Vec<db::AccountRow>, ProxyError> {
    let accounts: Vec<db::AccountRow> = snap
        .accounts
        .values()
        .filter(|a| a.provider_id == provider_id)
        .cloned()
        .collect();
    let mut available: Vec<db::AccountRow> = accounts
        .iter()
        .filter(|a| matches!(pool::effective_status(a), pool::AccountStatus::Healthy))
        .cloned()
        .collect();

    if available.is_empty() {
        // Fall back to the whole pool so the caller can report a proper error.
        return Ok(accounts);
    }

    if let Some(pref) = preferred {
        available.sort_by_key(|a| if a.id == pref { 0 } else { 1 });
    } else {
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        available.shuffle(&mut rng);
        available.sort_by_key(|a| a.priority);
    }
    Ok(available)
}

/// Gather plugin routing facts for a request (§6.4).
///
/// Every enabled plugin that declares a `routing_facts` capability is invoked
/// once, within its 25 ms budget. Facts are namespaced `plugin.<id>.<name>` and
/// are treated as `unknown` when absent. A provider that fails or times out
/// contributes no facts and is recorded as a failure so the Route Trace can
/// explain the `unknown`.
///
/// Determinism (§6.4): the manifest is required to be `pure` (no `host-http`
/// import; the host refuses buffered HTTP to routing-fact worlds) or `cached`
/// (the guest returns precomputed values with `observed_at`/`max_age_ms`).
/// Stale cached facts are dropped here and therefore evaluate as `unknown`.
async fn gather_plugin_facts(
    state: &AppState,
    req: &RequestFacts<'_>,
    disconnected: Option<&Arc<std::sync::atomic::AtomicBool>>,
) -> PluginFacts {
    let mut facts = PluginFacts::default();
    let Some(manager) = state.plugin_manager() else {
        return facts;
    };
    let plugins = match manager.list().await {
        Ok(p) => p,
        Err(_) => return facts,
    };
    // Only request/config facts core already knows are exposed to the plugin.
    let request_json = serde_json::json!({
        "frontend": req.frontend,
        "requested_model": req.requested_model,
        "requested_route": req.requested_route,
        "key_tag": req.key_tag,
        "has_tools": req.has_tools,
        "has_images": req.has_images,
        "has_reasoning": req.has_reasoning,
        "input_tokens": req.input_tokens,
    })
    .to_string();

    for row in plugins {
        if !row.status().is_enabled() {
            continue;
        }
        let Some(manifest) = row.manifest() else {
            continue;
        };
        if manifest.provides.routing_facts.is_empty() {
            continue;
        }
        // §6.4 `cached` mode: read the host-stamped snapshot the plugin published
        // on its background schedule. No guest call, no network, no wall time on
        // the request path — the determinism guarantee.
        if manifest.routing_facts_mode == "cached" {
            match manager.cached_facts(&row.id).await {
                Ok(entries) => {
                    for (name, value, observed, max_age) in entries {
                        let full = format!("plugin.{}.{}", row.id, name);
                        if let (Some(observed), Some(max_age)) = (&observed, max_age) {
                            if let Some(ts) = db::parse_dt(observed) {
                                let age = chrono::Utc::now().signed_duration_since(ts);
                                if age.num_milliseconds() > max_age as i64 {
                                    continue; // stale => absent => unknown
                                }
                            }
                        }
                        let source = serde_json::json!({
                            "plugin": row.id,
                            "version": row.version,
                            "capability": "routing-facts",
                            "mode": "cached",
                            "observed_at": observed,
                        });
                        facts.insert(full, value, source);
                    }
                }
                Err(e) => {
                    facts.failures.push((row.id.clone(), e.to_string()));
                }
            }
            continue;
        }
        let call = match disconnected {
            Some(flag) => {
                manager
                    .routing_facts_cancellable(&row.id, &request_json, flag.clone())
                    .await
            }
            None => manager.routing_facts(&row.id, &request_json).await,
        };
        match call {
            Ok(list) => {
                for f in list {
                    // Staleness: a cached fact past its max_age is `unknown`.
                    if let (Some(observed), Some(max_age)) = (&f.observed_at, f.max_age_ms) {
                        if let Some(ts) = db::parse_dt(observed) {
                            let age = chrono::Utc::now().signed_duration_since(ts);
                            if age.num_milliseconds() > max_age as i64 {
                                continue; // stale => absent => unknown
                            }
                        }
                    }
                    let value: Value = serde_json::from_str(&f.value_json)
                        .unwrap_or(Value::String(f.value_json.clone()));
                    let source = serde_json::json!({
                        "plugin": row.id,
                        "version": row.version,
                        "capability": "routing-facts",
                    });
                    facts.insert(f.name, value, source);
                }
            }
            Err(fault) => {
                // A client-driven cancellation is not a fact-provider failure
                // (§7.2); it simply yields no facts, which evaluate as unknown.
                if fault.code() != "cancelled" {
                    facts.failures.push((row.id.clone(), fault.message()));
                }
            }
        }
    }
    facts
}

/// Order route targets according to the route strategy (FR-12.5).
async fn order_route_targets(
    state: &AppState,
    route: &db::RouteRow,
    mut targets: Vec<ResolvedTarget>,
) -> Vec<ResolvedTarget> {
    match route.strategy.as_str() {
        "round-robin" => {
            let counter = state.rr_counter(&route.id);
            let n = counter.fetch_add(1, Ordering::Relaxed) as usize;
            if !targets.is_empty() {
                let offset = n % targets.len();
                targets.rotate_left(offset);
            }
        }
        "weighted" => {
            use rand::Rng;
            let total: i64 = targets.iter().map(|t| t.weight.max(1)).sum();
            if total > 0 {
                let mut pick = rand::thread_rng().gen_range(0..total);
                let mut idx = 0;
                for (i, t) in targets.iter().enumerate() {
                    pick -= t.weight.max(1);
                    if pick < 0 {
                        idx = i;
                        break;
                    }
                }
                targets.rotate_left(idx);
            }
        }
        "least-used" => {
            // Order by lifetime request count ascending (priority tiebreak).
            let (_, by_account) = db::lifetime_totals(&state.pool).await.unwrap_or_default();
            targets.sort_by_key(|t| {
                (
                    by_account.get(&t.account.id).map(|(n, _)| *n).unwrap_or(0),
                    t.priority,
                )
            });
        }
        _ => {
            // priority (default): lowest priority number first, keep insertion order.
            targets.sort_by_key(|t| t.priority);
        }
    }
    targets
}

/// Apply a route's continuity/portability policy when falling back across
/// providers (FR-2.11, FR-12.13).
///
/// * `reject` — refuse to fall back to a target that cannot carry the
///   non-portable opaque state; the client gets a clear error.
/// * `strip_with_warning` — remove the non-portable state, record it in the
///   Route Trace, and emit a client-visible warning. Silent stripping is
///   forbidden.
fn apply_continuity(
    req: &mut InternalRequest,
    route: &db::RouteRow,
    target: &ResolvedTarget,
    trace: &mut RouteTrace,
) -> Result<(), ProxyError> {
    // Identify non-portable opaque state: vendor thinking signatures and
    // provider-specific reasoning blocks (FR-2.1).
    let mut has_opaque = false;
    for msg in &req.messages {
        for p in &msg.parts {
            match p {
                crate::types::Part::Thinking { .. } => has_opaque = true,
                crate::types::Part::ToolCall { signature, .. } if signature.is_some() => {
                    has_opaque = true
                }
                _ => {}
            }
        }
    }
    if !has_opaque {
        return Ok(());
    }

    if route.portability() == "reject" {
        return Err(ProxyError::unsupported(format!(
            "route '{}' uses portability policy 'reject': the conversation carries provider-specific state that target '{}' cannot accept",
            route.name, target.model.display_name
        )));
    }

    // strip_with_warning
    for msg in &mut req.messages {
        msg.parts
            .retain(|p| !matches!(p, crate::types::Part::Thinking { .. }));
        for part in &mut msg.parts {
            if let crate::types::Part::ToolCall { signature, .. } = part {
                *signature = None;
            }
        }
    }
    let warning = format!(
        "non-portable provider state (reasoning/thinking signatures) was removed to fall back to '{}'",
        target.model.display_name
    );
    trace.warn(warning.clone());
    tracing::warn!(route = %route.name, "{}", warning);
    Ok(())
}

/// Check the admin's parameter policy; reject when a value is unsupported and
/// the policy is `reject` (FR-10.6).
fn check_param_policy(target: &ResolvedTarget, req: &InternalRequest) -> Result<(), ProxyError> {
    let params = target.model.params();
    let checks: [(&str, Option<f64>); 3] = [
        ("temperature", req.params.temperature),
        ("top_p", req.params.top_p),
        ("top_k", req.params.top_k),
    ];
    for (name, value) in checks {
        let Some(v) = value else { continue };
        let Some(spec) = params.get(name) else {
            continue;
        };
        if !spec.supported && spec.policy == crate::types::ParamPolicy::Reject {
            return Err(ProxyError::unsupported(format!(
                "parameter '{name}' is not supported by model '{}'",
                target.model.display_name
            )));
        }
        if spec.policy == crate::types::ParamPolicy::Reject {
            if let Some(min) = spec.min {
                if v < min {
                    return Err(ProxyError::bad_request(format!(
                        "parameter '{name}' below minimum {min}"
                    )));
                }
            }
            if let Some(max) = spec.max {
                if v > max {
                    return Err(ProxyError::bad_request(format!(
                        "parameter '{name}' above maximum {max}"
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Build the client response: streaming or aggregated non-streaming.
#[allow(clippy::too_many_arguments)]
fn stream_response(
    state: &AppState,
    snap: Arc<crate::registry::Snapshot>,
    format: FrontendFormat,
    meta: RequestMeta,
    req: InternalRequest,
    attempt: Attempt,
    started: Instant,
    key: Option<db::VirtualKeyRow>,
    trace: RouteTrace,
) -> Response {
    let stream = req.stream;
    let state = state.clone();
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(64);

    let model_display = attempt.target.model.display_name.clone();
    let request_id = meta.request_id.clone();
    let encoder_ctx = EncoderCtx {
        model_name: req.requested_model.clone(),
        request_id: request_id.clone(),
        created: chrono::Utc::now().timestamp(),
    };

    // Response headers injected by Kinetix (FR-12.15). Serving topology is
    // hidden by default; the opaque route id is resolvable by an admin only.
    let mut builder = Response::builder()
        .header("x-request-id", &request_id)
        .header("x-kinetix-route-id", &trace.opaque_route_id)
        .header("x-kinetix-cache", meta.cache_status);
    if meta.fallback_hops > 0 {
        // r4 specifies the literal value '1' (present only when a fallback
        // occurred). The hop count and hop trace are internal routing detail and
        // are not exposed on the ordinary response; the full trace is
        // admin-resolvable through the opaque route id.
        builder = builder.header("x-kinetix-fallback", "1");
    }
    if !trace.warnings.is_empty() {
        if let Ok(w) = serde_json::to_string(&trace.warnings) {
            builder = builder.header("x-kinetix-warning", w);
        }
    }

    let notify = Arc::new(tokio::sync::Notify::new());

    if stream {
        builder = builder
            .header("content-type", "text/event-stream")
            .header("cache-control", "no-cache")
            .header("connection", "keep-alive")
            .header("x-accel-buffering", "no");

        // Watchdog (FR-2.9, NFR-1.10): the response body is dropped the instant
        // the client goes away, so a drop-guard flips `meta.disconnected` and
        // wakes the driver immediately. Without this a cancellation could wait up
        // to a keepalive interval, because a broken client socket is otherwise
        // only detected on the next write.
        let guard = DisconnectGuard {
            flag: meta.disconnected.clone(),
            notify: notify.clone(),
            at: meta.disconnect_at.clone(),
        };
        let mut body_stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        let watched = async_stream::stream! {
            use tokio_stream::StreamExt as _;
            let _guard = guard;
            while let Some(v) = body_stream.next().await {
                yield v;
            }
        };

        let passthrough = attempt.passthrough;
        tokio::spawn(async move {
            if passthrough {
                drive_stream_passthrough(
                    state,
                    snap,
                    format,
                    meta,
                    req,
                    attempt,
                    encoder_ctx,
                    started,
                    key,
                    tx,
                    model_display,
                    trace,
                    notify,
                )
                .await;
            } else {
                drive_stream(
                    state,
                    snap,
                    format,
                    meta,
                    req,
                    attempt,
                    encoder_ctx,
                    started,
                    key,
                    tx,
                    model_display,
                    trace,
                    notify,
                )
                .await;
            }
        });

        let body = Body::from_stream(watched);
        builder.body(body).unwrap_or_else(|_| {
            Response::builder()
                .status(500)
                .body(Body::from("internal error"))
                .unwrap()
        })
    } else {
        // Non-streaming: aggregate the whole stream, then return JSON (FR-1.4).
        let (agg_tx, agg_rx) = tokio::sync::oneshot::channel::<Value>();
        let model_name = req.requested_model.clone();
        // Ensure the aggregate driver sees stream=true so usage is delivered
        // (OpenAI-compatible upstreams only emit the usage chunk when
        // streaming). The client-visible response is still a single JSON body.
        let mut req = req;
        req.stream = true;
        tokio::spawn(async move {
            let result = drive_aggregate(
                state,
                snap,
                format,
                meta,
                req,
                attempt,
                encoder_ctx,
                started,
                key,
                model_name,
                trace,
            )
            .await;
            let _ = agg_tx.send(result);
        });
        let body = Body::from_stream(async_stream::stream! {
            match agg_rx.await {
                Ok(v) => yield Ok::<Bytes, std::io::Error>(Bytes::from(v.to_string())),
                Err(_) => yield Ok(Bytes::from("{\"error\":{\"message\":\"internal error\"}}")),
            }
        });
        builder
            .header("content-type", "application/json")
            .body(body)
            .unwrap_or_else(|_| Response::new(Body::empty()))
    }
}

/// The async streaming driver: reads upstream SSE, encodes to the client
/// format, emits keepalives, and logs usage when done.
#[allow(clippy::too_many_arguments)]
async fn drive_stream(
    state: AppState,
    snap: Arc<crate::registry::Snapshot>,
    format: FrontendFormat,
    mut meta: RequestMeta,
    req: InternalRequest,
    mut attempt: Attempt,
    encoder_ctx: EncoderCtx,
    started: Instant,
    key: Option<db::VirtualKeyRow>,
    tx: mpsc::Sender<Result<Bytes, std::io::Error>>,
    model_display: String,
    mut trace: RouteTrace,
    notify: Arc<tokio::sync::Notify>,
) {
    let mut encoder = Encoder::new(format, encoder_ctx);
    let mut usage = TokenUsage::default();
    let mut ttft_ms: Option<i64> = None;
    let mut status = "success";
    let mut status_code = 200i64;
    let mut error_message: Option<String> = None;
    let mut committed = false;
    let mut saw_reasoning = false;
    let mut saw_tool = false;
    let mut upstream = attempt.stream.take().expect("stream present");
    let adapter = attempt.adapter.clone();
    let mut framer = crate::sse::SseFramer::new();
    let mut keepalive = tokio::time::interval(Duration::from_secs(KEEPALIVE_INTERVAL_SECS));
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        // Abort promptly on client disconnect, even between upstream chunks
        // (NFR-1.10: cancellation signal within ~100ms).
        if meta.disconnected.load(Ordering::Relaxed) {
            record_cancel(&state, &meta, started);
            status = "client_disconnect";
            status_code = 499;
            break;
        }
        tokio::select! {
            _ = notify.notified() => {
                if meta.disconnected.load(Ordering::Relaxed) {
                    record_cancel(&state, &meta, started);
                    status = "client_disconnect";
                    status_code = 499;
                    break;
                }
            }
            _ = keepalive.tick() => {
                // Keepalive comment (FR-9.4): keeps Cloudflare's ~100s idle
                // timeout from dropping a long silent thinking phase.
                if tx.send(Ok(frontends::sse_comment("keepalive"))).await.is_err() {
                    // Client disconnected: cancel upstream (FR-2.9).
                    record_cancel(&state, &meta, started);
                    status = "client_disconnect";
                    status_code = 499;
                    break;
                }
            }
            chunk = upstream.chunk() => {
                match chunk {
                    Ok(Some(bytes)) => {
                        for frame in framer.push(&bytes) {
                            let payload = crate::sse::extract_data(&frame);
                            let Some(payload) = payload else { continue };
                            if payload.trim() == "[DONE]" { continue; }
                            match adapter.parse_stream_chunk(&payload) {
                                Ok(events) => {
                                    for ev in events {
                                        if let StreamEvent::Usage(u) = &ev {
                                            usage.merge(u);
                                        }
                                        // Flight recorder: event classes, metadata
                                        // only (FR-13.1, FR-13.2).
                                        match &ev {
                                            StreamEvent::ThinkingDelta { .. } if !saw_reasoning => {
                                                saw_reasoning = true;
                                                state.flight.record(
                                                    &meta.request_id,
                                                    started.elapsed().as_millis() as u64,
                                                    "reasoning_event",
                                                    "first thinking delta",
                                                );
                                            }
                                            StreamEvent::ToolCallStart { .. } if !saw_tool => {
                                                saw_tool = true;
                                                state.flight.record(
                                                    &meta.request_id,
                                                    started.elapsed().as_millis() as u64,
                                                    "tool_call_event",
                                                    "first tool call",
                                                );
                                            }
                                            _ => {}
                                        }
                                        let frames = encoder.encode(ev);
                                        if ttft_ms.is_none() && !frames.is_empty() {
                                            ttft_ms = Some(started.elapsed().as_millis() as i64);
                                            state.live.set_ttft(&meta.request_id, ttft_ms.unwrap());
                                            state.live.mark_streaming(&meta.request_id);
                                            state.flight.record(
                                                &meta.request_id,
                                                started.elapsed().as_millis() as u64,
                                                "upstream_first_frame",
                                                "first upstream frame",
                                            );
                                        }
                                        for f in frames {
                                            if !committed {
                                                committed = true;
                                                trace.commit();
                                                state.live.mark_committed(&meta.request_id);
                                                state.flight.record(&meta.request_id, started.elapsed().as_millis() as u64, "commit", "first client bytes");
                                            }
                                            if tx.send(Ok(f)).await.is_err() {
                                                record_cancel(&state, &meta, started);
                                                status = "client_disconnect";
                                                status_code = 499;
                                                return finalize_log(
                                                    &state, &snap, &mut meta, &req, &attempt, &model_display,
                                                    started, ttft_ms, status, status_code, usage,
                                                    error_message, key, trace, committed,
                                                ).await;
                                            }
                                        }
                                    }
                                }
                                Err(f) => {
                                    status = "stream_error";
                                    status_code = 502;
                                    error_message = Some(f.message.clone());
                                    if committed {
                                        state.failures_post_commit.fetch_add(1, Ordering::Relaxed);
                                    }
                                    for f in encoder.error_frame(&f.message) {
                                        let _ = tx.send(Ok(f)).await;
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        status = "stream_error";
                        status_code = 502;
                        error_message = Some(classify_reqwest(&e));
                        if committed {
                            state.failures_post_commit.fetch_add(1, Ordering::Relaxed);
                        }
                        for f in encoder.error_frame("upstream stream interrupted") {
                            let _ = tx.send(Ok(f)).await;
                        }
                        break;
                    }
                }
            }
        }
    }

    if status == "success" {
        for f in encoder.finalize() {
            if tx.send(Ok(f)).await.is_err() {
                record_cancel(&state, &meta, started);
                status = "client_disconnect";
                status_code = 499;
                break;
            }
        }
    }

    finalize_log(
        &state,
        &snap,
        &mut meta,
        &req,
        &attempt,
        &model_display,
        started,
        ttft_ms,
        status,
        status_code,
        usage,
        error_message,
        key,
        trace,
        committed,
    )
    .await;
}

/// Same-format passthrough streaming (FR-2.7, FR-2.10): forward the upstream's
/// SSE `data:` payloads verbatim (preserving unknown/provider-specific fields)
/// while extracting usage metadata for accounting.
#[allow(clippy::too_many_arguments)]
async fn drive_stream_passthrough(
    state: AppState,
    snap: Arc<crate::registry::Snapshot>,
    format: FrontendFormat,
    mut meta: RequestMeta,
    req: InternalRequest,
    mut attempt: Attempt,
    _encoder_ctx: EncoderCtx,
    started: Instant,
    key: Option<db::VirtualKeyRow>,
    tx: mpsc::Sender<Result<Bytes, std::io::Error>>,
    model_display: String,
    mut trace: RouteTrace,
    notify: Arc<tokio::sync::Notify>,
) {
    let mut usage = TokenUsage::default();
    let mut ttft_ms: Option<i64> = None;
    let mut status = "success";
    let mut status_code = 200i64;
    let mut error_message: Option<String> = None;
    let mut committed = false;
    let mut saw_reasoning = false;
    let mut saw_tool = false;
    let mut upstream = attempt.stream.take().expect("stream present");
    let adapter = attempt.adapter.clone();
    let mut framer = crate::sse::SseFramer::new();
    let mut keepalive = tokio::time::interval(Duration::from_secs(KEEPALIVE_INTERVAL_SECS));
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if meta.disconnected.load(Ordering::Relaxed) {
            record_cancel(&state, &meta, started);
            status = "client_disconnect";
            status_code = 499;
            break;
        }
        tokio::select! {
            _ = notify.notified() => {
                if meta.disconnected.load(Ordering::Relaxed) {
                    record_cancel(&state, &meta, started);
                    status = "client_disconnect";
                    status_code = 499;
                    break;
                }
            }
            _ = keepalive.tick() => {
                // Keepalive comment (FR-9.4): keeps Cloudflare's ~100s idle
                // timeout from dropping a long silent thinking phase.
                if tx.send(Ok(frontends::sse_comment("keepalive"))).await.is_err() {
                    record_cancel(&state, &meta, started);
                    status = "client_disconnect";
                    status_code = 499;
                    break;
                }
            }
            chunk = upstream.chunk() => {
                match chunk {
                    Ok(Some(bytes)) => {
                        // Forward each complete frame verbatim (CRLF already
                        // normalized by the framer); extract usage metadata only.
                        for frame in framer.push(&bytes) {
                            if let Some(payload) = crate::sse::extract_data(&frame) {
                                if payload.trim() != "[DONE]" {
                                    if let Ok(evs) = adapter.parse_stream_chunk(&payload) {
                                        for ev in evs {
                                            if let StreamEvent::Usage(u) = &ev {
                                                usage.merge(u);
                                            }
                                            match &ev {
                                                StreamEvent::ThinkingDelta { .. } if !saw_reasoning => {
                                                    saw_reasoning = true;
                                                    state.flight.record(
                                                        &meta.request_id,
                                                        started.elapsed().as_millis() as u64,
                                                        "reasoning_event",
                                                        "first thinking delta",
                                                    );
                                                }
                                                StreamEvent::ToolCallStart { .. } if !saw_tool => {
                                                    saw_tool = true;
                                                    state.flight.record(
                                                        &meta.request_id,
                                                        started.elapsed().as_millis() as u64,
                                                        "tool_call_event",
                                                        "first tool call",
                                                    );
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                }
                            }
                            if ttft_ms.is_none() {
                                ttft_ms = Some(started.elapsed().as_millis() as i64);
                                state.live.set_ttft(&meta.request_id, ttft_ms.unwrap());
                                state.live.mark_streaming(&meta.request_id);
                                state.flight.record(
                                    &meta.request_id,
                                    started.elapsed().as_millis() as u64,
                                    "upstream_first_frame",
                                    "first upstream frame",
                                );
                            }
                            if !committed {
                                committed = true;
                                trace.commit();
                                state.live.mark_committed(&meta.request_id);
                            }
                            let out = Bytes::from(format!("{frame}\n\n"));
                            if tx.send(Ok(out)).await.is_err() {
                                record_cancel(&state, &meta, started);
                                status = "client_disconnect";
                                status_code = 499;
                                return finalize_log(
                                    &state, &snap, &mut meta, &req, &attempt, &model_display,
                                    started, ttft_ms, status, status_code, usage,
                                    error_message, key, trace, committed,
                                ).await;
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        status = "stream_error";
                        status_code = 502;
                        error_message = Some(classify_reqwest(&e));
                        if committed {
                            state.failures_post_commit.fetch_add(1, Ordering::Relaxed);
                        }
                        break;
                    }
                }
            }
        }
    }

    let _ = format;
    finalize_log(
        &state,
        &snap,
        &mut meta,
        &req,
        &attempt,
        &model_display,
        started,
        ttft_ms,
        status,
        status_code,
        usage,
        error_message,
        key,
        trace,
        committed,
    )
    .await;
}

/// Flips a disconnect flag (and wakes waiters) when the response body is
/// dropped, i.e. when the client stops reading (FR-2.9, NFR-1.10).
struct DisconnectGuard {
    flag: Arc<std::sync::atomic::AtomicBool>,
    notify: Arc<tokio::sync::Notify>,
    at: Arc<parking_lot::Mutex<Option<Instant>>>,
}

impl Drop for DisconnectGuard {
    fn drop(&mut self) {
        *self.at.lock() = Some(Instant::now());
        self.flag.store(true, Ordering::Relaxed);
        self.notify.notify_waiters();
    }
}

fn record_cancel(state: &AppState, meta: &RequestMeta, started: Instant) {
    state.cancellations.fetch_add(1, Ordering::Relaxed);
    // Cancellation latency is the delay between the client actually going away
    // and Kinetix acting on it (NFR-1.10). Fall back to time-since-start only
    // when the disconnect instant was never observed.
    let signal_ms = match *meta.disconnect_at.lock() {
        Some(at) => at.elapsed().as_millis() as u64,
        None => 0,
    };
    state
        .cancellation_latency_ms_total
        .fetch_add(signal_ms, Ordering::Relaxed);
    state.flight.record(
        &meta.request_id,
        started.elapsed().as_millis() as u64,
        "cancellation_issued",
        format!("client disconnected; signal latency {signal_ms}ms"),
    );
}

#[allow(clippy::too_many_arguments)]
async fn drive_aggregate(
    state: AppState,
    snap: Arc<crate::registry::Snapshot>,
    format: FrontendFormat,
    mut meta: RequestMeta,
    req: InternalRequest,
    mut attempt: Attempt,
    encoder_ctx: EncoderCtx,
    started: Instant,
    key: Option<db::VirtualKeyRow>,
    model_name: String,
    mut trace: RouteTrace,
) -> Value {
    let mut upstream = attempt.stream.take().expect("stream present");
    let adapter = attempt.adapter.clone();
    let mut framer = crate::sse::SseFramer::new();
    let mut events: Vec<StreamEvent> = Vec::new();
    let mut usage = TokenUsage::default();
    let mut status = "success";
    let mut status_code = 200i64;
    let mut error_message: Option<String> = None;
    let mut committed = false;

    'outer: while let Some(chunk) = upstream.chunk().await.transpose() {
        match chunk {
            Ok(bytes) => {
                for frame in framer.push(&bytes) {
                    let Some(payload) = crate::sse::extract_data(&frame) else {
                        continue;
                    };
                    if payload.trim() == "[DONE]" {
                        continue;
                    }
                    match adapter.parse_stream_chunk(&payload) {
                        Ok(evs) => {
                            for ev in evs {
                                if let StreamEvent::Usage(u) = &ev {
                                    usage.merge(u);
                                }
                                events.push(ev);
                            }
                        }
                        Err(f) => {
                            status = "stream_error";
                            status_code = 502;
                            error_message = Some(f.message);
                            break 'outer;
                        }
                    }
                }
            }
            Err(e) => {
                status = "stream_error";
                status_code = 502;
                error_message = Some(classify_reqwest(&e));
                break;
            }
        }
    }

    // The aggregated response is committed as a whole (no streaming).
    if status == "success" {
        committed = true;
        trace.commit();
    }

    finalize_log(
        &state,
        &snap,
        &mut meta,
        &req,
        &attempt,
        &model_name,
        started,
        None,
        status,
        status_code,
        usage.clone(),
        error_message.clone(),
        key.clone(),
        trace,
        committed,
    )
    .await;

    if status != "success" {
        return serde_json::json!({
            "error": {
                "message": error_message.unwrap_or_else(|| "upstream stream interrupted".into()),
                "type": "upstream_error"
            }
        });
    }

    let body = frontends::aggregate(format, &model_name, &encoder_ctx.request_id, events, &usage);
    // Non-streaming responses are fully materialized here, so they can be
    // logged (redacted, short retention) when the key opts in (FR-6.5).
    if let Some(k) = &key {
        if k.body_logging != 0 {
            let _ = db::insert_body_log(
                &state.pool,
                &meta.request_id,
                &k.id,
                "response",
                &crate::crypto::redact(&body.to_string()),
                7,
            )
            .await;
        }
    }
    body
}

/// Compute cost and enqueue the usage row (never blocks the request path),
/// persist the Route Trace, and record the flight-recorder terminal event.
#[allow(clippy::too_many_arguments)]
async fn finalize_log(
    state: &AppState,
    snap: &crate::registry::Snapshot,
    meta: &mut RequestMeta,
    req: &InternalRequest,
    attempt: &Attempt,
    model_display: &str,
    started: Instant,
    ttft_ms: Option<i64>,
    status: &str,
    status_code: i64,
    usage: TokenUsage,
    error_message: Option<String>,
    key: Option<db::VirtualKeyRow>,
    mut trace: RouteTrace,
    committed: bool,
) {
    let prices = attempt.target.model.prices();
    let cost = cost::compute_cost(&prices, &usage);
    let cost_known = cost.is_some();

    // Accounting truthfulness (FR-6.8): provider-reported vs unknown.
    let usage_confidence = if usage.input.is_some() || usage.output.is_some() {
        "provider_reported"
    } else {
        "unknown"
    };

    // Persist prompt-cache-affinity mapping for the next turn (FR-7.3).
    if let (Some(session), Some(route_id)) = (&meta.session, &meta.route_id) {
        if let Some(route) = snap.routes.get(route_id) {
            if route.cache_affinity != 0 && status == "success" {
                state.sticky_remember(
                    session,
                    format!(
                        "{}|{}|{}",
                        route_id, attempt.target.account.id, attempt.target.model.id
                    ),
                );
            }
        }
    }

    meta.commit_state = if committed {
        "post_commit"
    } else {
        "pre_commit"
    };
    trace.finish(match status {
        "success" => "success",
        "client_disconnect" => "cancelled",
        _ => "failed",
    });

    let row = UsageLogRow {
        id: format!("usage_{}", uuid::Uuid::new_v4().simple()),
        request_id: meta.request_id.clone(),
        ts: db::now_iso(),
        key_id: key.as_ref().map(|k| k.id.clone()),
        key_name: key.as_ref().map(|k| k.name.clone()),
        client_format: meta.client_format.to_string(),
        requested_model: req.requested_model.clone(),
        effective_model: Some(model_display.to_string()),
        route_id: meta.route_id.clone(),
        route_name: meta.route_name.clone(),
        fallback_hops: meta.fallback_hops,
        fallback_path: serde_json::to_string(&meta.fallback_path).unwrap_or_else(|_| "[]".into()),
        status: status.to_string(),
        status_code,
        latency_ms: Some(started.elapsed().as_millis() as i64),
        ttft_ms,
        input_tokens: usage.input.map(|v| v as i64),
        output_tokens: usage.output.map(|v| v as i64),
        cached_tokens: usage.cached.map(|v| v as i64),
        thinking_tokens: usage.thinking.map(|v| v as i64),
        cost_usd: cost,
        cost_known: cost_known as i64,
        price_version_id: None,
        cache_status: meta.cache_status.to_string(),
        serving_account_id: Some(attempt.target.account.id.clone()),
        serving_account: Some(attempt.target.account.label.clone()),
        serving_provider: Some(attempt.target.provider.name.clone()),
        upstream_request_id: attempt.upstream_request_id.clone(),
        flagged: (usage.input.is_none() && status == "success") as i64,
        error_message,
        usage_confidence: usage_confidence.to_string(),
        commit_state: meta.commit_state.to_string(),
        retry_count: meta.retry_count,
        route_trace_id: Some(trace.opaque_route_id.clone()),
        opaque_route_id: Some(trace.opaque_route_id.clone()),
    };
    state.log_queue.enqueue(row);

    // Read-only usage hook (§6.6): fire-and-forget on the bounded async queue,
    // after accounting is recorded, so it can never block or fail the request.
    if let Some(manager) = state.plugin_manager().cloned() {
        let json = serde_json::json!({
            "request_id": meta.request_id,
            "model": model_display,
            "provider": attempt.target.provider.name,
            "account": attempt.target.account.label,
            "route": meta.route_name,
            "status": status,
            "commit_state": meta.commit_state,
            "retry_count": meta.retry_count,
            "input_tokens": usage.input,
            "output_tokens": usage.output,
            "cached_tokens": usage.cached,
            "thinking_tokens": usage.thinking,
            "cost_usd": cost,
            "latency_ms": started.elapsed().as_millis() as i64,
        })
        .to_string();
        state.spawn_hook(move || async move {
            let mut hooks = tokio::task::JoinSet::new();
            for id in manager.plugins_with_hook("on_usage_finalized").await {
                let manager = manager.clone();
                let json = json.clone();
                hooks.spawn(async move {
                    let _ = manager.hook_usage_finalized(&id, &json).await;
                });
            }
            while hooks.join_next().await.is_some() {}
        });
    }

    // Route Trace (metadata only, FR-12.14).
    let _ = db::insert_route_trace(&state.pool, &trace).await;

    state.flight.record(
        &meta.request_id,
        started.elapsed().as_millis() as u64,
        "usage_finalized",
        format!("status={status} tokens={:?}", usage.input),
    );
    state.live.finish(
        &meta.request_id,
        status,
        started.elapsed().as_millis() as u64,
        usage.input,
        usage.output,
    );

    // Optional per-key body logging (FR-6.5): off unless the key opts in, the
    // body is redacted, and retention is short (7 days). Request bodies are
    // logged here for every path; non-streaming responses are additionally
    // logged by drive_aggregate. Streaming responses are not buffered (NFR-1.3),
    // so only their request is retained.
    if let Some(k) = &key {
        if k.body_logging != 0 {
            let request_body = match &req.raw_body {
                Some(raw) => crate::crypto::redact(raw),
                None => serde_json::json!({
                    "model": model_display,
                    "messages": req.messages.len(),
                })
                .to_string(),
            };
            let _ = db::insert_body_log(
                &state.pool,
                &meta.request_id,
                &k.id,
                "request",
                &request_body,
                7,
            )
            .await;
        }
    }
}

/// A Route Dry Run (FR-8.7): compute candidate ordering, predicate outcomes,
/// capability/limit eligibility, account state, and the would-be-selected
/// target **without mutating production state and without calling upstream**.
///
/// `descriptor` mirrors the fields a representative request would carry.
#[derive(Debug, Default, serde::Deserialize)]
pub struct DryRunRequest {
    #[serde(default)]
    pub frontend: Option<String>,
    #[serde(default)]
    pub key_tag: Option<String>,
    #[serde(default)]
    pub has_tools: bool,
    #[serde(default)]
    pub has_images: bool,
    #[serde(default)]
    pub has_reasoning: bool,
    #[serde(default)]
    pub input_tokens: Option<u64>,
    /// Providers the calling key is restricted to (FR-12.19); empty = no
    /// restriction. The dashboard passes the selected key's allowlist so the
    /// dry run reflects access restrictions, not just predicate/capability.
    #[serde(default)]
    pub allowed_providers: Vec<String>,
    /// Whether the descriptor's key/account soft quota is already reached
    /// (FR-12.8). When true, candidates are marked ineligible for the same
    /// reason the data path would skip them.
    #[serde(default)]
    pub soft_quota_reached: bool,
}

pub async fn dry_run(
    state: &AppState,
    requested_model: &str,
    descriptor: &DryRunRequest,
) -> Result<serde_json::Value, ProxyError> {
    let snap = state.registry.snapshot();
    let resolved =
        crate::registry::Registry::resolve_in(&snap, requested_model).ok_or_else(|| {
            ProxyError::not_found(format!("model '{requested_model}' is not configured"))
        })?;

    let frontend = descriptor.frontend.as_deref().unwrap_or("openai");
    let needs = crate::types::CapabilityNeeds {
        vision: descriptor.has_images,
        tools: descriptor.has_tools,
        reasoning: descriptor.has_reasoning,
    };

    let (targets, route) = match resolved {
        Resolved::Single {
            provider_id,
            model_id,
        } => {
            let model = snap
                .models
                .get(&model_id)
                .cloned()
                .ok_or_else(|| ProxyError::not_found("model not found"))?;
            let provider = snap
                .providers
                .get(&provider_id)
                .cloned()
                .ok_or_else(|| ProxyError::not_found("provider not found"))?;
            let accounts = select_accounts(&snap, &provider_id, None)?;
            (
                accounts
                    .into_iter()
                    .map(|account| ResolvedTarget {
                        account,
                        model: model.clone(),
                        provider: provider.clone(),
                        priority: 1,
                        weight: 1,
                        predicate: TargetPredicate::default(),
                        param_overrides: Value::Null,
                    })
                    .collect::<Vec<_>>(),
                None,
            )
        }
        Resolved::Route { route, targets } => {
            let ordered = order_route_targets(state, &route, targets).await;
            (ordered, Some(route))
        }
    };

    let request_facts = RequestFacts {
        frontend,
        requested_model,
        requested_route: route.as_ref().map(|r| r.name.as_str()),
        key_tag: descriptor.key_tag.as_deref(),
        has_tools: descriptor.has_tools,
        has_images: descriptor.has_images,
        has_reasoning: descriptor.has_reasoning,
        input_tokens: descriptor.input_tokens.unwrap_or(0),
    };

    let mut candidates = Vec::new();
    let mut selected: Option<String> = None;
    for t in &targets {
        let tgt_facts = TargetFacts {
            model_id: &t.model.id,
            model_display: &t.model.display_name,
            provider_id: &t.provider.id,
            provider_name: &t.provider.name,
            capabilities: &t.model.caps(),
            capabilities_raw: &serde_json::from_str::<Value>(&t.model.capabilities)
                .unwrap_or(Value::Null),
            context_window: t.model.context_window,
            max_output_tokens: t.model.max_output_tokens,
        };
        let elig = predicate::eligibility(&t.predicate, &request_facts, &tgt_facts);
        let status = pool::effective_status(&t.account);
        let healthy = matches!(status, pool::AccountStatus::Healthy);
        let caps_ok = t.model.caps().satisfies(&needs) || !t.provider.strict();
        let ctx_ok = t
            .model
            .context_window
            .map(|c| c <= 0 || request_facts.input_tokens <= c as u64)
            .unwrap_or(true);
        let provider_allowed = descriptor.allowed_providers.is_empty()
            || descriptor.allowed_providers.contains(&t.provider.id);
        let quota_ok = !descriptor.soft_quota_reached;
        let would_select =
            elig.eligible && healthy && caps_ok && ctx_ok && provider_allowed && quota_ok;
        if would_select && selected.is_none() {
            selected = Some(format!("{} @ {}", t.model.display_name, t.account.label));
        }
        // Enumerate the reasons a candidate is not selected so the dry run is
        // explainable (FR-8.7), not just a boolean.
        let mut reasons: Vec<&str> = Vec::new();
        if !elig.eligible {
            reasons.push("predicate");
        }
        if !healthy {
            reasons.push("account_state");
        }
        if !caps_ok {
            reasons.push("capabilities");
        }
        if !ctx_ok {
            reasons.push("context_window");
        }
        if !provider_allowed {
            reasons.push("provider_not_permitted");
        }
        if !quota_ok {
            reasons.push("soft_quota");
        }
        candidates.push(serde_json::json!({
            "target": format!("{} @ {}", t.model.display_name, t.account.label),
            "model": t.model.display_name,
            "model_id": t.model.id,
            "provider": t.provider.name,
            "provider_id": t.provider.id,
            "account": t.account.label,
            "account_id": t.account.id,
            "account_status": status.as_str(),
            "priority": t.priority,
            "weight": t.weight,
            "predicate_result": elig.result.as_str(),
            "predicate_explanation": elig.explanation,
            "predicate_eligible": elig.eligible,
            "capability_eligible": caps_ok,
            "context_eligible": ctx_ok,
            "provider_permitted": provider_allowed,
            "quota_available": quota_ok,
            "eligible": would_select,
            "not_selected_reasons": reasons,
        }));
    }

    Ok(serde_json::json!({
        "requested_model": requested_model,
        "route": route.as_ref().map(|r| r.name.clone()),
        "route_id": route.as_ref().map(|r| r.id.clone()),
        "strategy": route.as_ref().map(|r| r.strategy.clone()),
        "candidates": candidates,
        "would_select": selected,
        "note": "Dry run only: no production state was mutated and no upstream call was made.",
    }))
}
