//! Antigravity (`v1internal`) wire-format adapter — a *pure translation* plugin
//! (`plugin-adapter` world, §6.3, §7.1).
//!
//! Kinetix core owns the outbound HTTP send and the SSE framing; this plugin
//! only translates:
//!
//! * `build-url`  → `…/v1internal:streamGenerateContent?alt=sse` (or
//!   `generateContent` when the client did not ask to stream),
//! * `apply-auth` → the `Authorization: Bearer …` + Antigravity `User-Agent`,
//! * `build-body` → the `{project, model, userAgent, requestType, requestId,
//!   request:{contents, systemInstruction, generationConfig, tools, …}}`
//!   envelope, converting the internal message model to Gemini `contents`,
//! * `classify-error` / `parse-stream-chunk` / `parse-full-response` → canonical
//!   event JSON back to the host.
//!
//! Reference source: 9router `open-sse/executors/antigravity.js` and
//! `open-sse/translator/response/openai-to-antigravity.js`.

use serde_json::{json, Map, Value};

/// The IDE fingerprint Antigravity expects (macOS on purpose, even on Linux).
pub(crate) const USER_AGENT: &str = "antigravity/ide/2.11.0 darwin/arm64";

const MAX_OUTPUT_TOKENS: i64 = 64000;

/// Fields Google `generateContent` rejects (thinking fields set at body root).
const BLACKLIST: &[&str] = &[
    "output_config",
    "thinking",
    "reasoning_effort",
    "reasoning",
    "enable_thinking",
    "thinking_budget",
    "thinkingConfig",
];

/// Transient upstream error patterns that should be retried by the host.
const TRANSIENT_PATTERNS: &[&str] = &[
    "high traffic",
    "agent execution terminated due to error",
    "agent terminated due to error",
    "capacity",
    "temporarily unavailable",
    "timeout",
    "stream ended",
    "stream closed",
    "stream terminated",
    "stream interrupted",
    "empty response",
];

/// A neutral error the host-side impl maps onto the adapter world's
/// `PluginError` (the two worlds have distinct generated types).
#[derive(Debug, Clone)]
pub struct AdapterError {
    pub code: String,
    pub message: String,
}

fn err(code: &str, message: impl Into<String>) -> AdapterError {
    AdapterError {
        code: code.to_string(),
        message: message.into(),
    }
}

fn bad(message: impl Into<String>) -> AdapterError {
    err("bad_request", message)
}

pub fn wire_format() -> String {
    "antigravity".to_string()
}

// ---------------------------------------------------------------------------
// URL + auth
// ---------------------------------------------------------------------------

pub fn build_url(provider_json: &str, model_json: &str) -> Result<String, AdapterError> {
    let provider: Value = serde_json::from_str(provider_json).unwrap_or(Value::Null);
    let base = provider
        .get("base_url")
        .and_then(|b| b.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("https://daily-cloudcode-pa.googleapis.com")
        .trim_end_matches('/');
    // Kinetix core streams via SSE, so the streaming action is used. (Image
    // generation, which needs `generateContent`, is not yet a Kinetix route.)
    let _ = model_json;
    Ok(format!("{base}/v1internal:streamGenerateContent?alt=sse"))
}

pub fn apply_auth(_provider_json: &str, credential: &str) -> Result<String, AdapterError> {
    let headers = json!([
        ["Authorization", format!("Bearer {credential}")],
        ["Content-Type", "application/json"],
        ["User-Agent", USER_AGENT],
    ]);
    Ok(headers.to_string())
}

// ---------------------------------------------------------------------------
// Body construction
// ---------------------------------------------------------------------------

pub fn build_body(
    request_json: &str,
    provider_json: &str,
    model_json: &str,
) -> Result<String, AdapterError> {
    let req: Value =
        serde_json::from_str(request_json).map_err(|e| bad(format!("bad request json: {e}")))?;
    let provider: Value = serde_json::from_str(provider_json).unwrap_or(Value::Null);
    let model: Value = serde_json::from_str(model_json).unwrap_or(Value::Null);

    let upstream_model = model
        .get("upstream_id")
        .and_then(|m| m.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| req.get("requested_model").and_then(|m| m.as_str()))
        .unwrap_or("gemini-3-flash")
        .to_string();

    let project = project_id(&provider, &req);
    let session_id = session_id(&req);
    let request_id = build_request_id(&session_id, &upstream_model);

    // systemInstruction from the internal `system` string list.
    let system_instruction = req
        .get("system")
        .and_then(|s| s.as_array())
        .map(|arr| {
            let parts: Vec<Value> = arr
                .iter()
                .filter_map(|s| s.as_str())
                .map(|t| json!({ "text": t }))
                .collect();
            json!({ "parts": parts })
        })
        .filter(|si| {
            si.get("parts")
                .and_then(|p| p.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(false)
        });

    // contents from messages.
    let mut contents: Vec<Value> = Vec::new();
    if let Some(messages) = req.get("messages").and_then(|m| m.as_array()) {
        for m in messages {
            let role = match m.get("role").and_then(|r| r.as_str()).unwrap_or("user") {
                "assistant" => "model",
                _ => "user",
            };
            let mut parts: Vec<Value> = Vec::new();
            if let Some(ps) = m.get("parts").and_then(|p| p.as_array()) {
                for p in ps {
                    if let Some(v) = part_to_gemini(p) {
                        parts.push(v);
                    }
                }
            }
            if !parts.is_empty() {
                contents.push(json!({ "role": role, "parts": parts }));
            }
        }
    }

    // generationConfig.
    let mut gen = Map::new();
    if let Some(t) = req.get("temperature").and_then(|v| v.as_f64()) {
        gen.insert("temperature".into(), json!(t));
    }
    if let Some(p) = req.get("top_p").and_then(|v| v.as_f64()) {
        gen.insert("topP".into(), json!(p));
    }
    if let Some(k) = req.get("top_k").and_then(|v| v.as_i64()) {
        gen.insert("topK".into(), json!(k));
    }
    if let Some(mt) = req.get("max_tokens").and_then(|v| v.as_i64()) {
        gen.insert("maxOutputTokens".into(), json!(mt.min(MAX_OUTPUT_TOKENS)));
    }
    if let Some(stop) = req.get("stop").and_then(|v| v.as_array()) {
        if !stop.is_empty() {
            gen.insert("stopSequences".into(), Value::Array(stop.clone()));
        }
    }

    // Google `generateContent` rejects thinking/reasoning fields set at the
    // request root (e.g. `thinkingConfig`); strip them from the caller's extra
    // fields so they never reach the envelope.
    let extra = req
        .get("extra")
        .and_then(|e| e.as_object())
        .map(|obj| {
            let mut out = obj.clone();
            for k in BLACKLIST {
                out.remove(*k);
            }
            out
        })
        .unwrap_or_default();

    // tools → a single functionDeclarations group (Gemini expects one).
    let mut tools: Option<Value> = None;
    if let Some(arr) = req.get("tools").and_then(|t| t.as_array()) {
        let mut decls: Vec<Value> = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for t in arr {
            let name = sanitize_function_name(t.get("name").and_then(|n| n.as_str()).unwrap_or(""));
            if !seen.insert(name.clone()) {
                continue;
            }
            let params = t
                .get("parameters")
                .cloned()
                .unwrap_or_else(|| json!({ "type": "object", "properties": {} }));
            decls.push(json!({
                "name": name,
                "description": t.get("description").cloned().unwrap_or(Value::Null),
                "parameters": clean_schema(params),
            }));
        }
        if !decls.is_empty() {
            tools = Some(json!([{ "functionDeclarations": decls }]));
        }
    }

    let mut request = Map::new();
    request.insert("contents".into(), Value::Array(contents));
    if let Some(si) = system_instruction {
        request.insert("systemInstruction".into(), si);
    }
    request.insert("generationConfig".into(), Value::Object(gen));
    if let Some(t) = tools {
        request.insert("tools".into(), t);
        request.insert(
            "toolConfig".into(),
            json!({ "functionCallingConfig": { "mode": "VALIDATED" } }),
        );
    }
    request.insert("sessionId".into(), json!(session_id));
    // Caller extra fields (provider-specific), minus the blacklisted keys.
    if !extra.is_empty() {
        request.insert("clientExtra".into(), Value::Object(extra));
    }
    // Google rejects explicit nulls; omit safetySettings entirely.

    let mut envelope = Map::new();
    envelope.insert("project".into(), json!(project));
    envelope.insert("model".into(), json!(upstream_model));
    envelope.insert("userAgent".into(), json!("antigravity"));
    envelope.insert("requestType".into(), json!("agent"));
    envelope.insert("requestId".into(), json!(request_id));
    envelope.insert("request".into(), Value::Object(request));

    Ok(Value::Object(envelope).to_string())
}

fn project_id(provider: &Value, req: &Value) -> String {
    // Prefer an operator-configured project (provider extra_headers), then a
    // client-supplied hint, then a deterministic fallback (the API accepts a
    // generated id when the account has no explicit project).
    if let Some(project) = provider
        .get("extra_headers")
        .and_then(|e| e.as_str())
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| {
            v.get("x-antigravity-project")
                .and_then(|p| p.as_str())
                .map(str::to_string)
        })
    {
        return project;
    }
    if let Some(project) = req
        .get("extra")
        .and_then(|e| e.get("antigravity_project"))
        .and_then(|p| p.as_str())
    {
        return project.to_string();
    }
    let seed = format!(
        "{}:{}",
        req.get("requested_model")
            .and_then(|m| m.as_str())
            .unwrap_or(""),
        session_id(req)
    );
    let h = fnv1a(&seed);
    format!("kinetix-{h:08x}")
}

fn session_id(req: &Value) -> String {
    req.get("extra")
        .and_then(|e| e.get("session_id").or_else(|| e.get("sessionId")))
        .and_then(|s| s.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| format!("{:016x}", fnv1a("antigravity:default")))
}

/// `agent/<conversationId>/<ts>/<trajectoryId>/<step>` (9router's IDE shape).
fn build_request_id(session_id: &str, model: &str) -> String {
    let conversation = uuid_from_seed(&format!("antigravity:conversation:{session_id}"));
    let trajectory = uuid_from_seed(&format!("antigravity:trajectory:{session_id}:{model}"));
    let ts = kinetix_plugin_sdk::helpers::now_unix_millis();
    format!("agent/{conversation}/{ts}/{trajectory}/1")
}

/// Gemini function-name rule: `[a-zA-Z_][a-zA-Z0-9_.:\-]{0,63}`.
fn sanitize_function_name(name: &str) -> String {
    if name.is_empty() {
        return "_unknown".to_string();
    }
    let mut s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if !s
        .chars()
        .next()
        .map(|c| c.is_ascii_alphabetic() || c == '_')
        .unwrap_or(false)
    {
        s.insert(0, '_');
    }
    s.truncate(64);
    s
}

/// Gemini rejects `additionalProperties`/`$schema` and requires `type` on
/// object schemas; strip the unsupported keys.
fn clean_schema(v: Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, val) in map {
                if k == "additionalProperties" || k == "$schema" || k.starts_with("x-") {
                    continue;
                }
                out.insert(k, clean_schema(val));
            }
            if !out.contains_key("type") && out.contains_key("properties") {
                out.insert("type".into(), json!("object"));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(clean_schema).collect()),
        other => other,
    }
}

/// Convert one internal part to a Gemini part.
fn part_to_gemini(p: &Value) -> Option<Value> {
    match p.get("type").and_then(|t| t.as_str())? {
        "text" => Some(json!({ "text": p.get("text").and_then(|t| t.as_str()).unwrap_or("") })),
        "thinking" => Some(json!({
            "thought": true,
            "text": p.get("text").and_then(|t| t.as_str()).unwrap_or("")
        })),
        "image" => Some(json!({
            "inlineData": {
                "mimeType": p.get("mime").and_then(|m| m.as_str()).unwrap_or("image/png"),
                "data": p.get("data").and_then(|d| d.as_str()).unwrap_or("")
            }
        })),
        "image_url" => Some(json!({
            "fileData": { "fileUri": p.get("url").and_then(|u| u.as_str()).unwrap_or("") }
        })),
        "tool_call" => {
            let name = sanitize_function_name(p.get("name").and_then(|n| n.as_str()).unwrap_or(""));
            let args: Value = p
                .get("arguments")
                .and_then(|a| a.as_str())
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_else(|| json!({}));
            let mut part = json!({ "functionCall": { "name": name, "args": args } });
            if let Some(sig) = p.get("signature").and_then(|s| s.as_str()) {
                if let Some(obj) = part.as_object_mut() {
                    obj.insert("thoughtSignature".into(), json!(sig));
                }
            }
            Some(part)
        }
        "tool_result" => {
            let name = sanitize_function_name(p.get("name").and_then(|n| n.as_str()).unwrap_or(""));
            let content = p.get("content").and_then(|c| c.as_str()).unwrap_or("");
            Some(json!({
                "functionResponse": { "name": name, "response": { "result": content } }
            }))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

pub fn classify_error(status: u16, body: &str, headers_json: &str) -> Result<String, AdapterError> {
    let headers: Value = serde_json::from_str(headers_json).unwrap_or(Value::Null);
    let retry_after = parse_retry_after(&headers, body);
    let mut message =
        extract_error_message(body).unwrap_or_else(|| format!("upstream HTTP {status}"));

    let kind = if status == 429 {
        "quota_exhausted"
    } else if status == 401 || status == 403 {
        "auth_error"
    } else if status >= 500 {
        // Any 5xx is a server error; transient ones (high traffic, capacity,
        // stream ended) are annotated so the host's trace explains a retry.
        if is_transient(&message) {
            message = format!("transient upstream error: {message}");
        }
        "server_error"
    } else if status >= 400 {
        "bad_request"
    } else {
        "server_error"
    };

    let evidence = json!({
        "kind": kind,
        "status": status,
        "retry_after_secs": retry_after,
        "message": message,
        "quota_reset_at": Value::Null,
    });
    Ok(evidence.to_string())
}

/// Retry-after seconds from headers or a "reset after 2h7m23s" message.
fn parse_retry_after(headers: &Value, body: &str) -> Option<u64> {
    if let Some(v) = headers.get("retry-after").and_then(|v| v.as_str()) {
        if let Ok(secs) = v.trim().parse::<u64>() {
            return Some(secs);
        }
    }
    if let Some(v) = headers
        .get("x-ratelimit-reset-after")
        .and_then(|v| v.as_str())
    {
        if let Ok(secs) = v.trim().parse::<u64>() {
            return Some(secs);
        }
    }
    parse_reset_from_message(body)
}

fn parse_reset_from_message(body: &str) -> Option<u64> {
    let lower = body.to_ascii_lowercase();
    let idx = lower.find("reset after")?;
    let rest = &lower[idx + "reset after".len()..];
    let mut total: u64 = 0;
    let mut num = String::new();
    for c in rest.chars() {
        if c.is_ascii_digit() {
            num.push(c);
        } else if c == 'h' || c == 'm' || c == 's' {
            let n: u64 = num.parse().unwrap_or(0);
            total += match c {
                'h' => n * 3600,
                'm' => n * 60,
                _ => n,
            };
            num.clear();
            if c == 's' {
                break;
            }
        } else if !num.is_empty() {
            break;
        }
    }
    if total > 0 {
        Some(total)
    } else {
        None
    }
}

fn extract_error_message(body: &str) -> Option<String> {
    let v: Value = serde_json::from_str(body).ok()?;
    v.pointer("/error/message")
        .and_then(|m| m.as_str())
        .or_else(|| v.get("message").and_then(|m| m.as_str()))
        .or_else(|| v.get("error").and_then(|m| m.as_str()))
        .map(str::to_string)
}

fn is_transient(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    TRANSIENT_PATTERNS.iter().any(|p| m.contains(p))
}

// ---------------------------------------------------------------------------
// Stream parsing → canonical events
// ---------------------------------------------------------------------------

pub fn parse_stream_chunk(data: &str) -> Result<String, AdapterError> {
    let v: Value = serde_json::from_str(data).map_err(|e| bad(format!("bad sse json: {e}")))?;
    // Antigravity wraps everything in a `response` object.
    let resp = v.get("response").unwrap_or(&v);
    let mut events: Vec<Value> = Vec::new();

    if let Some(id) = resp.get("responseId").and_then(|r| r.as_str()) {
        events.push(json!({ "type": "start", "upstream_request_id": id }));
    }

    let mut tool_index: u32 = 0;
    if let Some(candidates) = resp.get("candidates").and_then(|c| c.as_array()) {
        for c in candidates {
            if let Some(parts) = c.pointer("/content/parts").and_then(|p| p.as_array()) {
                for p in parts {
                    if let Some(text) = p.get("text").and_then(|t| t.as_str()) {
                        if p.get("thought").and_then(|t| t.as_bool()).unwrap_or(false) {
                            events.push(json!({
                                "type": "thinking_delta",
                                "text": text,
                                "signature": p.get("thoughtSignature").and_then(|s| s.as_str()),
                            }));
                        } else {
                            events.push(json!({ "type": "text_delta", "text": text }));
                        }
                    }
                    if let Some(fc) = p.get("functionCall") {
                        let name = sanitize_function_name(
                            fc.get("name").and_then(|n| n.as_str()).unwrap_or(""),
                        );
                        let args = fc.get("args").cloned().unwrap_or_else(|| json!({}));
                        events.push(json!({
                            "type": "tool_call_start",
                            "index": tool_index,
                            "id": Value::Null,
                            "name": name,
                            "signature": p.get("thoughtSignature").and_then(|s| s.as_str()),
                        }));
                        events.push(json!({
                            "type": "tool_call_args_delta",
                            "index": tool_index,
                            "args": args.to_string(),
                        }));
                        tool_index += 1;
                    }
                }
            }
            if let Some(reason) = c.get("finishReason").and_then(|r| r.as_str()) {
                events.push(json!({ "type": "finish", "reason": map_finish(reason) }));
            }
        }
    }

    if let Some(meta) = resp.get("usageMetadata") {
        events.push(json!({
            "type": "usage",
            "input": meta.get("promptTokenCount").and_then(|v| v.as_u64()),
            "output": meta.get("candidatesTokenCount").and_then(|v| v.as_u64()),
            "cached": meta.get("cachedContentTokenCount").and_then(|v| v.as_u64()),
            "thinking": meta.get("thoughtsTokenCount").and_then(|v| v.as_u64()),
        }));
    }

    Ok(Value::Array(events).to_string())
}

pub fn parse_full_response(body_json: &str) -> Result<String, AdapterError> {
    let v: Value = serde_json::from_str(body_json).unwrap_or(Value::Null);
    let resp = v.get("response").unwrap_or(&v);
    // Reuse the streaming parser on a synthesized single chunk.
    parse_stream_chunk(&resp.to_string())
}

fn map_finish(reason: &str) -> &'static str {
    match reason {
        "STOP" => "stop",
        "MAX_TOKENS" => "length",
        "SAFETY" | "RECITATION" | "BLOCKLIST" | "PROHIBITED_CONTENT" => "content_filter",
        _ => "stop",
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Deterministic RFC-4122-shaped UUID seeded by SHA-256 (no rng in the guest).
fn uuid_from_seed(seed: &str) -> String {
    let digest = sha256(seed.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Minimal SHA-256 (the guest has no crypto crate; this is not secret material).
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}
