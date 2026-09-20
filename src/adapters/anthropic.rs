//! Anthropic Messages outbound adapter (wire format `anthropic`).
//!
//! Used for Anthropic upstreams and for cross-provider routes (FR-12.7).

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::adapters::{Adapter, DiscoveredModel, UpstreamContext};
use crate::types::{
    FailureKind, FinishReason, ImageData, InternalRequest, Part, ProxyError, Role, StreamEvent,
    TokenUsage, ToolChoice, UpstreamFailure,
};

pub struct AnthropicAdapter;

impl AnthropicAdapter {
    pub fn new() -> Self {
        AnthropicAdapter
    }

    fn content_blocks(parts: &[Part]) -> Vec<Value> {
        let mut out = Vec::new();
        for p in parts {
            match p {
                Part::Text(t) => out.push(json!({ "type": "text", "text": t })),
                Part::Thinking { text, signature } => {
                    if let Some(sig) = signature {
                        out.push(json!({
                            "type": "thinking",
                            "thinking": text,
                            "signature": sig
                        }));
                    }
                }
                Part::Image(ImageData::Base64 { mime, data }) => out.push(json!({
                    "type": "image",
                    "source": { "type": "base64", "media_type": mime, "data": data }
                })),
                Part::Image(ImageData::Url(url)) => out.push(json!({
                    "type": "image",
                    "source": { "type": "url", "url": url }
                })),
                Part::ToolCall {
                    id,
                    name,
                    arguments,
                    ..
                } => {
                    let input: Value = serde_json::from_str(arguments).unwrap_or(json!({}));
                    out.push(json!({
                        "type": "tool_use",
                        "id": id.clone().unwrap_or_else(|| format!("toolu_{name}")),
                        "name": name,
                        "input": input
                    }));
                }
                Part::ToolResult {
                    tool_call_id,
                    content,
                    is_error,
                    ..
                } => {
                    out.push(json!({
                        "type": "tool_result",
                        "tool_use_id": tool_call_id,
                        "content": content,
                        "is_error": is_error
                    }));
                }
            }
        }
        out
    }

    fn build_messages(req: &InternalRequest) -> Vec<Value> {
        let mut msgs = Vec::new();
        for m in &req.messages {
            let role = match m.role {
                Role::Assistant => "assistant",
                _ => "user",
            };
            let blocks = Self::content_blocks(&m.parts);
            if blocks.is_empty() {
                continue;
            }
            msgs.push(json!({ "role": role, "content": blocks }));
        }
        msgs
    }

    fn build_tools(req: &InternalRequest) -> Option<Value> {
        if req.tools.is_empty() {
            return None;
        }
        let tools: Vec<Value> = req
            .tools
            .iter()
            .map(|t| {
                json!({
                    "name": t.name,
                    "description": t.description.clone().unwrap_or_default(),
                    "input_schema": if t.parameters.is_null() { json!({"type":"object","properties":{}}) } else { t.parameters.clone() }
                })
            })
            .collect();
        Some(Value::Array(tools))
    }

    fn build_tool_choice(req: &InternalRequest) -> Option<Value> {
        match req.tool_choice {
            Some(ToolChoice::None) => Some(json!({ "type": "none" })),
            Some(ToolChoice::Required) => Some(json!({ "type": "any" })),
            Some(ToolChoice::Specific) => Some(json!({
                "type": "tool",
                "name": req.tool_choice_name.clone().unwrap_or_default()
            })),
            Some(ToolChoice::Auto) | None => None,
        }
    }
}

impl Default for AnthropicAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Adapter for AnthropicAdapter {
    fn wire_format(&self) -> &'static str {
        "anthropic"
    }

    fn build_url(&self, ctx: &UpstreamContext<'_>) -> Result<String, ProxyError> {
        let base = ctx.provider.base_url.trim_end_matches('/');
        Ok(format!("{base}/messages"))
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
                    .unwrap_or_else(|| "x-api-key".to_string());
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
        body.insert("model".to_string(), json!(ctx.model.upstream_id));
        body.insert("stream".to_string(), json!(true));

        if !req.system.is_empty() {
            body.insert("system".to_string(), json!(req.system.join("\n\n")));
        }
        body.insert("messages".to_string(), json!(Self::build_messages(req)));

        // max_tokens is required by Anthropic.
        let max = req
            .params
            .max_tokens
            .map(|m| m as i64)
            .or(ctx.model.max_output_tokens)
            .unwrap_or(4096);
        body.insert("max_tokens".to_string(), json!(max));

        let params = ctx.model.params();
        if let Some(t) = req.params.temperature {
            if params
                .get("temperature")
                .map(|s| s.supported)
                .unwrap_or(true)
            {
                body.insert("temperature".to_string(), json!(t));
            }
        }
        if let Some(p) = req.params.top_p {
            if params.get("top_p").map(|s| s.supported).unwrap_or(true) {
                body.insert("top_p".to_string(), json!(p));
            }
        }
        if let Some(k) = req.params.top_k {
            if params.get("top_k").map(|s| s.supported).unwrap_or(true) {
                body.insert("top_k".to_string(), json!(k));
            }
        }
        if !req.params.stop.is_empty() {
            body.insert("stop_sequences".to_string(), json!(req.params.stop));
        }

        if let Some(tools) = Self::build_tools(req) {
            body.insert("tools".to_string(), tools);
        }
        if let Some(tc) = Self::build_tool_choice(req) {
            body.insert("tool_choice".to_string(), tc);
        }

        // Thinking map.
        if let Some(level) = req.thinking {
            let tmap = ctx.model.thinking();
            let key = match level {
                crate::types::ThinkingLevel::Off => "off",
                crate::types::ThinkingLevel::Low => "low",
                crate::types::ThinkingLevel::Medium => "medium",
                crate::types::ThinkingLevel::High => "high",
            };
            if let Some(v) = tmap.levels.get(key) {
                if !v.is_null() {
                    body.insert("thinking".to_string(), v.clone());
                }
            }
        }

        let extra = ctx.model.extra_request_value();
        if let Some(obj) = extra.as_object() {
            for (k, v) in obj {
                body.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }

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
        // Anthropic error type (kept for classification clarity; the message
        // is what distinguishes quota from a plain rate limit).
        let _etype = parsed
            .pointer("/error/type")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let retry_after_secs = headers
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());

        let kind = match status {
            400 | 404 | 422 => FailureKind::BadRequest,
            401 | 403 => FailureKind::AuthError,
            429 => {
                // Anthropic uses `rate_limit_error` for throttling; a quota /
                // credit exhaustion surfaces in the message. Distinguish them so
                // a quota problem benches the account until reset while a plain
                // rate limit only cools it down briefly (FR-12.7).
                let lower = message.to_ascii_lowercase();
                if lower.contains("quota") || lower.contains("credit") {
                    FailureKind::QuotaExhausted
                } else {
                    FailureKind::RateLimit
                }
            }
            529 => FailureKind::ServerError,
            s if s >= 500 => FailureKind::ServerError,
            _ => FailureKind::ServerError,
        };

        UpstreamFailure {
            kind,
            status: Some(status),
            retry_after_secs,
            message: if message.is_empty() {
                format!("upstream returned HTTP {status}")
            } else {
                crate::crypto::redact(&message)
            },
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
        let event_type = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
        let mut events = Vec::new();
        match event_type {
            "content_block_delta" => {
                let delta = v.get("delta").cloned().unwrap_or(Value::Null);
                match delta.get("type").and_then(|t| t.as_str()).unwrap_or("") {
                    "text_delta" => {
                        if let Some(t) = delta.get("text").and_then(|x| x.as_str()) {
                            events.push(StreamEvent::TextDelta(t.to_string()));
                        }
                    }
                    "thinking_delta" => {
                        if let Some(t) = delta.get("thinking").and_then(|x| x.as_str()) {
                            events.push(StreamEvent::ThinkingDelta {
                                text: t.to_string(),
                                signature: None,
                            });
                        }
                    }
                    "signature_delta" => {
                        if let Some(s) = delta.get("signature").and_then(|x| x.as_str()) {
                            events.push(StreamEvent::ThinkingDelta {
                                text: String::new(),
                                signature: Some(s.to_string()),
                            });
                        }
                    }
                    "input_json_delta" => {
                        let index = v.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as u32;
                        if let Some(partial) = delta.get("partial_json").and_then(|x| x.as_str()) {
                            events.push(StreamEvent::ToolCallArgsDelta {
                                index,
                                args: partial.to_string(),
                            });
                        }
                    }
                    _ => {}
                }
            }
            "content_block_start" => {
                let index = v.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as u32;
                if let Some(block) = v.get("content_block") {
                    if block.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
                        let id = block.get("id").and_then(|i| i.as_str()).map(String::from);
                        let name = block
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("tool")
                            .to_string();
                        events.push(StreamEvent::ToolCallStart {
                            index,
                            id,
                            name,
                            signature: None,
                        });
                    }
                }
            }
            "message_delta" => {
                if let Some(usage) = v.get("usage") {
                    events.push(StreamEvent::Usage(TokenUsage {
                        input: usage.get("input_tokens").and_then(|v| v.as_u64()),
                        output: usage.get("output_tokens").and_then(|v| v.as_u64()),
                        cached: usage
                            .get("cache_read_input_tokens")
                            .and_then(|v| v.as_u64()),
                        thinking: None,
                    }));
                }
                if let Some(reason) = v.pointer("/delta/stop_reason").and_then(|r| r.as_str()) {
                    events.push(StreamEvent::Finish(match reason {
                        "end_turn" | "stop_sequence" => FinishReason::Stop,
                        "max_tokens" => FinishReason::Length,
                        "tool_use" => FinishReason::ToolCalls,
                        other => FinishReason::Other(other.to_string()),
                    }));
                }
            }
            "message_start" => {
                if let Some(usage) = v.pointer("/message/usage") {
                    events.push(StreamEvent::Usage(TokenUsage {
                        input: usage.get("input_tokens").and_then(|v| v.as_u64()),
                        output: usage.get("output_tokens").and_then(|v| v.as_u64()),
                        cached: usage
                            .get("cache_read_input_tokens")
                            .and_then(|v| v.as_u64()),
                        thinking: None,
                    }));
                }
            }
            _ => {}
        }
        Ok(events)
    }

    fn parse_full_response(&self, body: &Value) -> Result<Vec<StreamEvent>, UpstreamFailure> {
        let mut events = Vec::new();
        if let Some(blocks) = body.get("content").and_then(|c| c.as_array()) {
            let mut idx = 0u32;
            for b in blocks {
                match b.get("type").and_then(|t| t.as_str()).unwrap_or("") {
                    "text" => {
                        if let Some(t) = b.get("text").and_then(|x| x.as_str()) {
                            events.push(StreamEvent::TextDelta(t.to_string()));
                        }
                    }
                    "thinking" => {
                        if let Some(t) = b.get("thinking").and_then(|x| x.as_str()) {
                            events.push(StreamEvent::ThinkingDelta {
                                text: t.to_string(),
                                signature: b
                                    .get("signature")
                                    .and_then(|s| s.as_str())
                                    .map(String::from),
                            });
                        }
                    }
                    "tool_use" => {
                        let id = b.get("id").and_then(|i| i.as_str()).map(String::from);
                        let name = b
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("tool")
                            .to_string();
                        events.push(StreamEvent::ToolCallStart {
                            index: idx,
                            id,
                            name,
                            signature: None,
                        });
                        let input = b.get("input").cloned().unwrap_or(json!({}));
                        events.push(StreamEvent::ToolCallArgsDelta {
                            index: idx,
                            args: input.to_string(),
                        });
                        idx += 1;
                    }
                    _ => {}
                }
            }
        }
        if let Some(usage) = body.get("usage") {
            events.push(StreamEvent::Usage(TokenUsage {
                input: usage.get("input_tokens").and_then(|v| v.as_u64()),
                output: usage.get("output_tokens").and_then(|v| v.as_u64()),
                cached: usage
                    .get("cache_read_input_tokens")
                    .and_then(|v| v.as_u64()),
                thinking: None,
            }));
        }
        if let Some(reason) = body.get("stop_reason").and_then(|r| r.as_str()) {
            events.push(StreamEvent::Finish(match reason {
                "end_turn" | "stop_sequence" => FinishReason::Stop,
                "max_tokens" => FinishReason::Length,
                "tool_use" => FinishReason::ToolCalls,
                other => FinishReason::Other(other.to_string()),
            }));
        }
        Ok(events)
    }

    fn default_models_path(&self) -> &'static str {
        "/models"
    }

    fn parse_model_list(&self, body: &Value) -> Vec<DiscoveredModel> {
        let mut out = Vec::new();
        if let Some(data) = body.get("data").and_then(|d| d.as_array()) {
            for m in data {
                if let Some(id) = m.get("id").and_then(|i| i.as_str()) {
                    out.push(DiscoveredModel {
                        id: id.to_string(),
                        display_name: m
                            .get("display_name")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        context_window: None,
                        capabilities: None,
                        raw_metadata: None,
                        max_output_tokens: None,
                    });
                }
            }
        }
        out
    }
}
