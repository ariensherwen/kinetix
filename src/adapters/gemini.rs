//! Gemini `generateContent` outbound adapter.
//!
//! Chosen purely by the provider's configured `wire_format = "gemini"`; nothing
//! vendor-specific leaks into the core. URLs, auth scheme, and headers all come
//! from the provider config the admin entered.

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::adapters::{Adapter, DiscoveredModel, UpstreamContext};
use crate::types::{
    FailureKind, FinishReason, ImageData, InternalRequest, Message, Part, ProxyError, Role,
    SamplingParams, StreamEvent, TokenUsage, ToolChoice, UpstreamFailure,
};

pub struct GeminiAdapter;

impl GeminiAdapter {
    pub fn new() -> Self {
        GeminiAdapter
    }

    fn role_str(role: Role) -> &'static str {
        match role {
            Role::Assistant => "model",
            // System is hoisted to systemInstruction; tool results ride as user parts.
            Role::System | Role::User | Role::Tool => "user",
        }
    }

    fn encode_parts(parts: &[Part], out: &mut Vec<Value>) {
        for p in parts {
            match p {
                Part::Text(t) => out.push(json!({ "text": t })),
                Part::Thinking { text, .. } => {
                    // Preserve thinking as a thought part so multi-turn history
                    // stays valid for the same provider (FR-12.10).
                    if !text.is_empty() {
                        out.push(json!({ "text": text, "thought": true }));
                    }
                }
                Part::Image(img) => match img {
                    ImageData::Base64 { mime, data } => {
                        out.push(json!({ "inlineData": { "mimeType": mime, "data": data } }));
                    }
                    ImageData::Url(url) => {
                        out.push(json!({ "fileData": { "fileUri": url } }));
                    }
                },
                Part::ToolCall {
                    name,
                    arguments,
                    signature,
                    ..
                } => {
                    let args: Value = serde_json::from_str(arguments).unwrap_or(json!({}));
                    let mut part = json!({ "functionCall": { "name": name, "args": args } });
                    if let Some(sig) = signature {
                        part["thoughtSignature"] = json!(sig);
                    }
                    out.push(part);
                }
                Part::ToolResult {
                    name,
                    content,
                    is_error,
                    ..
                } => {
                    let name = name.clone().unwrap_or_else(|| "tool".to_string());
                    // Gemini expects a structured response object.
                    let response = if *is_error {
                        json!({ "error": content })
                    } else {
                        match serde_json::from_str::<Value>(content) {
                            Ok(Value::Object(_)) => serde_json::from_str(content).unwrap(),
                            _ => json!({ "result": content }),
                        }
                    };
                    out.push(json!({
                        "functionResponse": { "name": name, "response": response }
                    }));
                }
            }
        }
    }

    fn build_contents(req: &InternalRequest) -> Vec<Value> {
        let mut contents = Vec::new();
        for m in &req.messages {
            let mut parts = Vec::new();
            Self::encode_parts(&m.parts, &mut parts);
            if parts.is_empty() {
                continue;
            }
            contents.push(json!({ "role": Self::role_str(m.role), "parts": parts }));
        }
        contents
    }

    fn build_generation_config(ctx: &UpstreamContext<'_>, req: &InternalRequest) -> Value {
        let model = ctx.model;
        let params = model.params();
        let mut cfg = serde_json::Map::new();

        let put_number =
            |key: &str, client_val: Option<f64>, cfg: &mut serde_json::Map<String, Value>| {
                let spec = params.get(key);
                if let Some(v) = client_val {
                    let (value, keep) = apply_param_spec(spec, v);
                    if keep {
                        cfg.insert(key.to_string(), json!(value));
                    }
                } else if let Some(spec) = spec {
                    // FR-10.6: a configured default applies when the client
                    // omits the field (only for a supported parameter).
                    if spec.supported {
                        if let Some(d) = spec.default {
                            cfg.insert(key.to_string(), json!(d));
                        }
                    }
                }
            };

        put_number("temperature", req.params.temperature, &mut cfg);
        put_number("topP", req.params.top_p, &mut cfg);
        put_number("topK", req.params.top_k, &mut cfg);

        // max output tokens: clamp to model max if configured.
        if let Some(mt) = req.params.max_tokens {
            let mut v = mt as f64;
            if let Some(max) = model.max_output_tokens {
                v = v.min(max as f64);
            }
            cfg.insert("maxOutputTokens".to_string(), json!(v as i64));
        }
        if !req.params.stop.is_empty() {
            cfg.insert("stopSequences".to_string(), json!(req.params.stop));
        }
        if let Some(seed) = req.params.seed {
            cfg.insert("seed".to_string(), json!(seed));
        }

        // Thinking mapping (FR-10.7): canonical level -> upstream fields.
        if let Some(level) = req.thinking {
            let tmap = model.thinking();
            let key = match level {
                crate::types::ThinkingLevel::Off => "off",
                crate::types::ThinkingLevel::Low => "low",
                crate::types::ThinkingLevel::Medium => "medium",
                crate::types::ThinkingLevel::High => "high",
            };
            if let Some(v) = tmap.levels.get(key) {
                // Value may be a full object to merge, or a scalar under budget_field.
                if let Some(obj) = v.as_object() {
                    for (k, val) in obj {
                        insert_dotted(&mut cfg, k, val.clone());
                    }
                } else if let Some(field) = &tmap.budget_field {
                    insert_dotted(&mut cfg, field, v.clone());
                }
            }
        }

        Value::Object(cfg)
    }

    fn build_tools(req: &InternalRequest) -> Option<Value> {
        if req.tools.is_empty() {
            return None;
        }
        let decls: Vec<Value> = req
            .tools
            .iter()
            .map(|t| {
                let mut d = json!({ "name": t.name });
                if let Some(desc) = &t.description {
                    d["description"] = json!(desc);
                }
                if !t.parameters.is_null() {
                    d["parameters"] = sanitize_schema(&t.parameters);
                }
                d
            })
            .collect();
        Some(json!([{ "functionDeclarations": decls }]))
    }

    fn build_tool_config(req: &InternalRequest) -> Option<Value> {
        let mode = match req.tool_choice {
            Some(ToolChoice::Auto) | None => {
                if req.tools.is_empty() {
                    return None;
                }
                "AUTO"
            }
            Some(ToolChoice::None) => "NONE",
            Some(ToolChoice::Required) => "ANY",
            Some(ToolChoice::Specific) => "ANY",
        };
        let mut cfg = json!({ "mode": mode });
        if let Some(name) = &req.tool_choice_name {
            cfg["allowedFunctionNames"] = json!([name]);
        }
        Some(json!({ "functionCallingConfig": cfg }))
    }
}

impl Default for GeminiAdapter {
    fn default() -> Self {
        Self::new()
    }
}

/// Apply the admin's parameter policy (FR-10.6).
/// Returns (value, keep). `drop`/out-of-range reject handled by caller via error.
fn apply_param_spec(spec: Option<&crate::types::ParamSpec>, v: f64) -> (f64, bool) {
    let Some(spec) = spec else {
        // Unconfigured parameter: forward unchanged.
        return (v, true);
    };
    if !spec.supported {
        return (v, false); // drop
    }
    let mut value = v;
    if let Some(min) = spec.min {
        if value < min {
            value = min;
        }
    }
    if let Some(max) = spec.max {
        if value > max {
            value = max;
        }
    }
    (value, true)
}

/// Insert a value at a dotted path (`a.b.c`) inside a JSON object, creating
/// intermediate objects as needed.
fn insert_dotted(obj: &mut serde_json::Map<String, Value>, path: &str, value: Value) {
    let parts: Vec<&str> = path.split('.').collect();
    insert_rec(obj, &parts, value);
}

fn insert_rec(obj: &mut serde_json::Map<String, Value>, path: &[&str], value: Value) {
    if path.is_empty() {
        return;
    }
    if path.len() == 1 {
        obj.insert(path[0].to_string(), value);
        return;
    }
    let entry = obj.entry(path[0].to_string()).or_insert_with(|| json!({}));
    if !entry.is_object() {
        *entry = json!({});
    }
    if let Some(map) = entry.as_object_mut() {
        insert_rec(map, &path[1..], value);
    }
}

/// Gemini rejects some JSON-schema keywords; strip the common offenders.
fn sanitize_schema(schema: &Value) -> Value {
    match schema {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                match k.as_str() {
                    "additionalProperties" | "$schema" | "definitions" | "$defs" | "strict" => {}
                    "properties" | "items" | "anyOf" | "allOf" | "oneOf" => {
                        out.insert(k.clone(), sanitize_schema(v));
                    }
                    _ => {
                        out.insert(k.clone(), v.clone());
                    }
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(sanitize_schema).collect()),
        other => other.clone(),
    }
}

#[async_trait]
impl Adapter for GeminiAdapter {
    fn wire_format(&self) -> &'static str {
        "gemini"
    }

    fn build_url(&self, ctx: &UpstreamContext<'_>) -> Result<String, ProxyError> {
        let base = ctx.provider.base_url.trim_end_matches('/');
        // Streaming-first: Kinetix always consumes an upstream stream (the
        // non-streaming path aggregates it), so always use the streaming method.
        Ok(format!(
            "{base}/models/{}:streamGenerateContent?alt=sse",
            ctx.model.upstream_id
        ))
    }

    fn apply_auth(
        &self,
        ctx: &UpstreamContext<'_>,
        req: reqwest::RequestBuilder,
    ) -> reqwest::RequestBuilder {
        use crate::types::AuthScheme;
        match ctx.provider.auth() {
            AuthScheme::Bearer => req.bearer_auth(&ctx.credential),
            AuthScheme::CustomHeader => {
                let name = ctx
                    .provider
                    .custom_header_name
                    .clone()
                    .unwrap_or_else(|| "x-goog-api-key".to_string());
                req.header(name, &ctx.credential)
            }
            AuthScheme::QueryParam => {
                let param = ctx
                    .provider
                    .custom_param_name
                    .clone()
                    .unwrap_or_else(|| "key".to_string());
                req.query(&[(param, &ctx.credential)])
            }
        }
    }

    fn build_body(&self, ctx: &UpstreamContext<'_>, req: &InternalRequest) -> Value {
        let mut body = serde_json::Map::new();

        // System instruction.
        if !req.system.is_empty() {
            let text = req.system.join("\n\n");
            body.insert(
                "systemInstruction".to_string(),
                json!({ "parts": [{ "text": text }] }),
            );
        }

        body.insert("contents".to_string(), json!(Self::build_contents(req)));

        let gen_cfg = Self::build_generation_config(ctx, req);
        if gen_cfg.as_object().map(|o| !o.is_empty()).unwrap_or(false) {
            body.insert("generationConfig".to_string(), gen_cfg);
        }

        if let Some(tools) = Self::build_tools(req) {
            body.insert("tools".to_string(), tools);
        }
        if let Some(tc) = Self::build_tool_config(req) {
            body.insert("toolConfig".to_string(), tc);
        }

        // Merge admin extra request fields (FR-10.8).
        let extra = ctx.model.extra_request_value();
        merge_extra(&mut body, &extra);

        Value::Object(body)
    }

    fn classify_error(
        &self,
        status: u16,
        body: &str,
        headers: &reqwest::header::HeaderMap,
    ) -> UpstreamFailure {
        let parsed: Value = serde_json::from_str(body).unwrap_or(Value::Null);
        let message = parsed
            .pointer("/error/message")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let gstatus = parsed
            .pointer("/error/status")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let retry_after_secs = headers
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(parse_retry_after)
            .or_else(|| parse_retry_delay(&parsed));

        // A short retry hint (Gemini's `retryDelay` for a per-minute rate limit)
        // means the window rolls over quickly, so treat it as a rate limit even
        // when the message mentions "quota" (e.g. free-tier RPM caps). A long
        // hint indicates a daily/quota reset and stays an exhaustion.
        let short_retry = retry_after_secs.map(|s| s <= 90).unwrap_or(false);

        let kind = match status {
            400 | 404 | 422 => FailureKind::BadRequest,
            401 | 403 => FailureKind::AuthError,
            429 if short_retry => FailureKind::RateLimit,
            429 => classify_429(gstatus, &message),
            s if s >= 500 => FailureKind::ServerError,
            _ => FailureKind::ServerError,
        };

        let safe_message = if message.is_empty() {
            format!("upstream returned HTTP {status}")
        } else {
            crate::crypto::redact(&message)
        };

        UpstreamFailure {
            kind,
            status: Some(status),
            retry_after_secs,
            message: safe_message,
            quota_reset_at: None,
        }
    }

    fn parse_stream_chunk(&self, data: &str) -> Result<Vec<StreamEvent>, UpstreamFailure> {
        let v: Value = serde_json::from_str(data).map_err(|e| UpstreamFailure {
            kind: FailureKind::ServerError,
            status: None,
            retry_after_secs: None,
            message: format!("invalid upstream chunk: {e}"),
            quota_reset_at: None,
        })?;
        Ok(events_from_gemini(&v))
    }

    fn parse_full_response(&self, body: &Value) -> Result<Vec<StreamEvent>, UpstreamFailure> {
        Ok(events_from_gemini(body))
    }

    fn default_models_path(&self) -> &'static str {
        "/models"
    }

    fn parse_model_list(&self, body: &Value) -> Vec<DiscoveredModel> {
        let mut out = Vec::new();
        if let Some(models) = body.get("models").and_then(|m| m.as_array()) {
            for m in models {
                let Some(name) = m.get("name").and_then(|n| n.as_str()) else {
                    continue;
                };
                let id = name.strip_prefix("models/").unwrap_or(name).to_string();
                // Only surface models that can actually generate content.
                let methods = m
                    .get("supportedGenerationMethods")
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>())
                    .unwrap_or_default();
                if !methods.is_empty() && !methods.iter().any(|x| x.contains("generateContent")) {
                    continue;
                }
                out.push(DiscoveredModel {
                    id,
                    display_name: m
                        .get("displayName")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    context_window: m.get("inputTokenLimit").and_then(|v| v.as_i64()),
                    max_output_tokens: m.get("outputTokenLimit").and_then(|v| v.as_i64()),
                    capabilities: None,
                    raw_metadata: None,
                });
            }
        }
        out
    }
}

/// Convert a Gemini chunk/response into internal stream events.
fn events_from_gemini(v: &Value) -> Vec<StreamEvent> {
    let mut events = Vec::new();
    let mut tool_index = 0u32;

    if let Some(candidates) = v.get("candidates").and_then(|c| c.as_array()) {
        for cand in candidates {
            if let Some(parts) = cand.pointer("/content/parts").and_then(|p| p.as_array()) {
                for part in parts {
                    if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                        let is_thought = part
                            .get("thought")
                            .and_then(|t| t.as_bool())
                            .unwrap_or(false);
                        let signature = part
                            .get("thoughtSignature")
                            .and_then(|s| s.as_str())
                            .map(String::from);
                        if is_thought {
                            events.push(StreamEvent::ThinkingDelta {
                                text: text.to_string(),
                                signature,
                            });
                        } else if !text.is_empty() {
                            events.push(StreamEvent::TextDelta(text.to_string()));
                        } else if signature.is_some() {
                            // Thought-signature-only part.
                            events.push(StreamEvent::ThinkingDelta {
                                text: String::new(),
                                signature,
                            });
                        }
                    }
                    if let Some(fc) = part.get("functionCall") {
                        let name = fc
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("tool")
                            .to_string();
                        let id = fc.get("id").and_then(|i| i.as_str()).map(String::from);
                        let args = fc.get("args").cloned().unwrap_or(json!({}));
                        let signature = part
                            .get("thoughtSignature")
                            .and_then(|s| s.as_str())
                            .map(String::from);
                        events.push(StreamEvent::ToolCallStart {
                            index: tool_index,
                            id,
                            name,
                            signature,
                        });
                        events.push(StreamEvent::ToolCallArgsDelta {
                            index: tool_index,
                            args: args.to_string(),
                        });
                        tool_index += 1;
                    }
                }
            }
            if let Some(reason) = cand.get("finishReason").and_then(|r| r.as_str()) {
                events.push(StreamEvent::Finish(map_finish(reason)));
            }
        }
    }

    if let Some(usage) = v.get("usageMetadata") {
        events.push(StreamEvent::Usage(TokenUsage {
            input: usage.get("promptTokenCount").and_then(|v| v.as_u64()),
            output: usage.get("candidatesTokenCount").and_then(|v| v.as_u64()),
            cached: usage
                .get("cachedContentTokenCount")
                .and_then(|v| v.as_u64()),
            thinking: usage.get("thoughtsTokenCount").and_then(|v| v.as_u64()),
        }));
    }

    events
}

fn map_finish(reason: &str) -> FinishReason {
    match reason {
        "STOP" => FinishReason::Stop,
        "MAX_TOKENS" => FinishReason::Length,
        "SAFETY" | "RECITATION" | "BLOCKLIST" | "PROHIBITED_CONTENT" | "SPII" => {
            FinishReason::ContentFilter
        }
        other => FinishReason::Other(other.to_string()),
    }
}

fn classify_429(status: &str, message: &str) -> FailureKind {
    let lower = message.to_lowercase();
    let quota_like = lower.contains("quota")
        || lower.contains("exceeded your current quota")
        || lower.contains("billing")
        || status == "RESOURCE_EXHAUSTED" && lower.contains("free_tier");
    // Rate limits are short-lived; quota exhaustion resets on a schedule.
    if quota_like
        && (lower.contains("per_day") || lower.contains("per day") || lower.contains("free_tier"))
    {
        FailureKind::QuotaExhausted
    } else if lower.contains("rate limit") || lower.contains("requests per minute") {
        FailureKind::RateLimit
    } else if quota_like {
        FailureKind::QuotaExhausted
    } else {
        FailureKind::RateLimit
    }
}

fn parse_retry_after(value: &str) -> Option<u64> {
    if let Ok(secs) = value.trim().parse::<u64>() {
        return Some(secs);
    }
    // HTTP-date form.
    if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(value) {
        let delta = dt.with_timezone(&chrono::Utc) - chrono::Utc::now();
        return Some(delta.num_seconds().max(0) as u64);
    }
    None
}

/// Gemini puts `"retryDelay": "23s"` inside error details.
fn parse_retry_delay(v: &Value) -> Option<u64> {
    let details = v.pointer("/error/details")?.as_array()?;
    for d in details {
        if let Some(delay) = d.get("retryDelay").and_then(|x| x.as_str()) {
            let num = delay.trim_end_matches('s').parse::<f64>().ok()?;
            return Some(num.ceil() as u64);
        }
    }
    None
}

fn merge_extra(body: &mut serde_json::Map<String, Value>, extra: &Value) {
    let Some(obj) = extra.as_object() else { return };
    for (k, v) in obj {
        // set-if-absent semantics by default.
        if !body.contains_key(k) {
            body.insert(k.clone(), v.clone());
        } else if let (Some(existing), Some(new)) = (
            body.get_mut(k).and_then(|x| x.as_object_mut()),
            v.as_object(),
        ) {
            for (k2, v2) in new {
                existing.entry(k2.clone()).or_insert_with(|| v2.clone());
            }
        }
    }
}

/// Re-export for the tool-result name lookup in the translator.
pub fn sampling_defaults() -> SamplingParams {
    SamplingParams::default()
}

pub fn message_has_tool_result(m: &Message) -> bool {
    m.parts.iter().any(|p| matches!(p, Part::ToolResult { .. }))
}
