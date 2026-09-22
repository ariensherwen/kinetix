//! OpenAI Responses API inbound frontend (POST /v1/responses).
//!
//! Implements Kinetix's explicitly supported translated subset of the OpenAI
//! Responses API. Kinetix does not provide native Responses upstream passthrough
//! or response-object storage/chaining; unsupported semantics fail closed.

use bytes::Bytes;
use serde_json::{json, Value};

use crate::frontends::{sse_frame, EncoderCtx};
use crate::types::{
    FinishReason, ImageData, InternalRequest, Message, Part, ProxyError, Role, StreamEvent,
    ThinkingLevel, ToolChoice, ToolDef,
};

// ---------------------------------------------------------------------------
// Request decoding
// ---------------------------------------------------------------------------

pub fn decode_request(body: Value) -> Result<InternalRequest, ProxyError> {
    let obj = body
        .as_object()
        .ok_or_else(|| ProxyError::bad_request("request body must be a JSON object"))?;
    validate_supported_subset(obj)?;

    let model = obj
        .get("model")
        .and_then(|m| m.as_str())
        .ok_or_else(|| ProxyError::bad_request("missing required field 'model'"))?
        .to_string();

    let mut system = Vec::new();

    // 1. Optional instructions field (Responses API system-instruction convention).
    if let Some(inst) = obj.get("instructions").and_then(|v| v.as_str()) {
        if !inst.trim().is_empty() {
            system.push(inst.to_string());
        }
    }

    // 2. Input: can be a plain string, or an array of items (messages, function calls, function outputs).
    let mut out_messages = Vec::new();
    if let Some(input) = obj.get("input") {
        match input {
            Value::String(text) => {
                if !text.is_empty() {
                    out_messages.push(Message {
                        role: Role::User,
                        parts: vec![Part::Text(text.clone())],
                    });
                }
            }
            Value::Array(items) => {
                for item in items {
                    decode_input_item(item, &mut system, &mut out_messages)?;
                }
            }
            _ => {
                return Err(ProxyError::bad_request(
                    "'input' must be either a string or an array of items",
                ));
            }
        }
    }

    // 3. Tools
    let tools = decode_tools(obj.get("tools"));
    let (tool_choice, tool_choice_name) = decode_tool_choice(obj.get("tool_choice"));

    // 4. Sampling parameters
    let params = crate::types::SamplingParams {
        temperature: obj.get("temperature").and_then(|v| v.as_f64()),
        top_p: obj.get("top_p").and_then(|v| v.as_f64()),
        top_k: obj.get("top_k").and_then(|v| v.as_f64()),
        max_tokens: obj
            .get("max_output_tokens")
            .or_else(|| obj.get("max_tokens"))
            .and_then(|v| v.as_u64())
            .map(|v| v as u32),
        presence_penalty: obj.get("presence_penalty").and_then(|v| v.as_f64()),
        frequency_penalty: obj.get("frequency_penalty").and_then(|v| v.as_f64()),
        ..Default::default()
    };

    // 5. Reasoning / thinking effort
    let thinking = obj
        .get("reasoning")
        .and_then(|r| r.get("effort"))
        .and_then(|e| e.as_str())
        .or_else(|| obj.get("reasoning_effort").and_then(|v| v.as_str()))
        .and_then(map_reasoning_effort);

    let stream = obj.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);

    // Responses input is always translated through Kinetix's canonical model;
    // there is no native Responses passthrough. Unknown top-level semantics are
    // rejected by validate_supported_subset instead of being carried as extras.
    let extra = serde_json::Map::new();
    let identity_issues = crate::frontends::resolve_tool_result_names(&mut out_messages);
    if let Some(issue) = identity_issues.first() {
        return Err(ProxyError::unsupported(format!(
            "Responses API tool-call state is not translatable: {issue}"
        )));
    }

    Ok(InternalRequest {
        requested_model: model,
        system,
        messages: out_messages,
        tools,
        tool_choice,
        tool_choice_name,
        params,
        stream,
        include_usage: false,
        thinking,
        extra,
        raw_body: None,
    })
}

fn validate_supported_subset(obj: &serde_json::Map<String, Value>) -> Result<(), ProxyError> {
    const SUPPORTED: [&str; 23] = [
        "model",
        "input",
        "instructions",
        "tools",
        "tool_choice",
        "temperature",
        "top_p",
        "top_k",
        "max_output_tokens",
        "max_tokens",
        "presence_penalty",
        "frequency_penalty",
        "stream",
        "reasoning",
        "reasoning_effort",
        "store",
        "background",
        "text",
        "stream_options",
        "truncation",
        "parallel_tool_calls",
        "metadata",
        "include",
    ];

    for key in obj.keys() {
        if !SUPPORTED.contains(&key.as_str()) {
            return Err(ProxyError::unsupported(format!(
                "Responses API field '{key}' is not supported by Kinetix's translated subset"
            )));
        }
    }

    if obj.get("stream").is_some_and(|value| !value.is_boolean()) {
        return Err(ProxyError::bad_request(
            "Responses API 'stream' must be boolean",
        ));
    }
    for key in ["store", "background"] {
        if obj.get(key).is_some_and(|value| !value.is_boolean()) {
            return Err(ProxyError::bad_request(format!(
                "Responses API '{key}' must be boolean"
            )));
        }
    }
    for key in [
        "temperature",
        "top_p",
        "top_k",
        "presence_penalty",
        "frequency_penalty",
    ] {
        if obj.get(key).is_some_and(|value| !value.is_number()) {
            return Err(ProxyError::bad_request(format!(
                "Responses API '{key}' must be numeric"
            )));
        }
    }
    for key in ["max_output_tokens", "max_tokens"] {
        if obj.get(key).is_some_and(|value| value.as_u64().is_none()) {
            return Err(ProxyError::bad_request(format!(
                "Responses API '{key}' must be a non-negative integer"
            )));
        }
    }

    if obj.get("store").and_then(Value::as_bool) == Some(true) {
        return Err(ProxyError::unsupported(
            "Responses API 'store: true' is unsupported; Kinetix does not persist response objects",
        ));
    }
    if obj.get("background").and_then(Value::as_bool) == Some(true) {
        return Err(ProxyError::unsupported(
            "Responses API background mode is unsupported",
        ));
    }
    if obj.get("parallel_tool_calls").is_some() {
        return Err(ProxyError::unsupported(
            "Responses API 'parallel_tool_calls' is not enforceable on translated upstreams",
        ));
    }
    if obj.get("metadata").is_some() {
        return Err(ProxyError::unsupported(
            "Responses API response metadata storage is unsupported",
        ));
    }
    if let Some(include) = obj.get("include") {
        let items = include
            .as_array()
            .ok_or_else(|| ProxyError::bad_request("Responses API 'include' must be an array"))?;
        if !items.is_empty() {
            return Err(ProxyError::unsupported(
                "Responses API 'include' expansions are unsupported",
            ));
        }
    }

    if let Some(truncation) = obj.get("truncation").and_then(Value::as_str) {
        if truncation != "disabled" {
            return Err(ProxyError::unsupported(
                "Responses API automatic truncation is unsupported; only 'disabled' is accepted",
            ));
        }
    }

    if let Some(text) = obj.get("text") {
        let text = text
            .as_object()
            .ok_or_else(|| ProxyError::bad_request("Responses API 'text' must be an object"))?;
        for key in text.keys() {
            if key != "format" {
                return Err(ProxyError::unsupported(format!(
                    "Responses API text.{key} is unsupported"
                )));
            }
        }
        if let Some(format) = text.get("format") {
            let format = format.as_object().ok_or_else(|| {
                ProxyError::bad_request("Responses API 'text.format' must be an object")
            })?;
            for key in format.keys() {
                if key != "type" {
                    return Err(ProxyError::unsupported(format!(
                        "Responses API text.format.{key} is unsupported"
                    )));
                }
            }
            let kind = format.get("type").and_then(Value::as_str).unwrap_or("text");
            if kind != "text" {
                return Err(ProxyError::unsupported(
                    "Responses API structured text.format is unsupported on translated upstreams",
                ));
            }
        }
    }

    if let Some(options) = obj.get("stream_options") {
        let options = options.as_object().ok_or_else(|| {
            ProxyError::bad_request("Responses API 'stream_options' must be an object")
        })?;
        for (key, value) in options {
            match key.as_str() {
                "include_obfuscation" if value.as_bool() == Some(false) => {}
                "include_obfuscation" => {
                    return Err(ProxyError::unsupported(
                        "Responses API stream obfuscation is unsupported",
                    ));
                }
                _ => {
                    return Err(ProxyError::unsupported(format!(
                        "Responses API stream_options.{key} is unsupported"
                    )));
                }
            }
        }
    }

    if let Some(reasoning) = obj.get("reasoning") {
        let reasoning = reasoning.as_object().ok_or_else(|| {
            ProxyError::bad_request("Responses API 'reasoning' must be an object")
        })?;
        for key in reasoning.keys() {
            if key != "effort" {
                return Err(ProxyError::unsupported(format!(
                    "Responses API reasoning.{key} is unsupported; only reasoning.effort is translated"
                )));
            }
        }
        if let Some(effort) = reasoning.get("effort") {
            let effort = effort.as_str().ok_or_else(|| {
                ProxyError::bad_request("Responses API reasoning.effort must be a string")
            })?;
            if map_reasoning_effort(effort).is_none() {
                return Err(ProxyError::unsupported(format!(
                    "Responses API reasoning effort '{effort}' is unsupported"
                )));
            }
        }
    }
    if let Some(effort) = obj.get("reasoning_effort") {
        let effort = effort.as_str().ok_or_else(|| {
            ProxyError::bad_request("Responses API reasoning_effort must be a string")
        })?;
        if map_reasoning_effort(effort).is_none() {
            return Err(ProxyError::unsupported(format!(
                "Responses API reasoning effort '{effort}' is unsupported"
            )));
        }
    }

    if let Some(choice) = obj.get("tool_choice") {
        match choice {
            Value::String(value) if matches!(value.as_str(), "auto" | "none" | "required") => {}
            Value::Object(value)
                if value.get("type").and_then(Value::as_str) == Some("function")
                    && value
                        .get("name")
                        .and_then(Value::as_str)
                        .is_some_and(|name| !name.is_empty())
                    && value
                        .keys()
                        .all(|key| matches!(key.as_str(), "type" | "name")) => {}
            Value::Null => {}
            _ => {
                return Err(ProxyError::unsupported(
                    "Responses API tool_choice supports only auto/none/required or a named function",
                ));
            }
        }
    }

    let nested = nested_translation_issues(obj);
    if let Some(issue) = nested.first() {
        return Err(ProxyError::unsupported(format!(
            "Responses API content is outside Kinetix's translated subset: {issue}"
        )));
    }

    Ok(())
}

fn nested_translation_issues(obj: &serde_json::Map<String, Value>) -> Vec<String> {
    let mut issues = Vec::new();

    if obj
        .get("instructions")
        .is_some_and(|value| !value.is_string())
    {
        issues.push("instructions has a non-text structure that cannot be translated".to_string());
    }

    if let Some(Value::Array(items)) = obj.get("input") {
        for (item_index, item) in items.iter().enumerate() {
            let kind = item.get("type").and_then(Value::as_str).unwrap_or("");
            match kind {
                "function_call" | "function_call_output" => {}
                "" | "message" => {
                    let role = item.get("role").and_then(Value::as_str).unwrap_or("user");
                    if !matches!(role, "system" | "developer" | "user" | "assistant" | "tool") {
                        issues.push(format!("input[{item_index}] has unsupported role '{role}'"));
                    }
                    inspect_responses_content(
                        &format!("input[{item_index}].content"),
                        item.get("content"),
                        matches!(role, "system" | "developer" | "tool"),
                        &mut issues,
                    );
                }
                _ => issues.push(format!(
                    "input[{item_index}] type '{kind}' has no canonical cross-format representation"
                )),
            }
        }
    }

    if let Some(tools) = obj.get("tools").and_then(Value::as_array) {
        for (tool_index, tool) in tools.iter().enumerate() {
            let kind = tool
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("function");
            if kind != "function" {
                issues.push(format!(
                    "tools[{tool_index}] type '{kind}' has no canonical cross-format representation"
                ));
                continue;
            }
            if tool.get("function").is_some() {
                for key in tool
                    .as_object()
                    .into_iter()
                    .flat_map(|object| object.keys())
                {
                    if !matches!(key.as_str(), "type" | "function") {
                        issues.push(format!(
                            "tools[{tool_index}].{key} has unsupported function-tool semantics"
                        ));
                    }
                }
            }
            let function = tool.get("function").unwrap_or(tool);
            if function.get("strict").and_then(Value::as_bool) == Some(true) {
                issues.push(format!(
                    "tools[{tool_index}].strict=true cannot be enforced on translated upstreams"
                ));
            }
            for key in function
                .as_object()
                .into_iter()
                .flat_map(|object| object.keys())
            {
                if !matches!(
                    key.as_str(),
                    "type" | "name" | "description" | "parameters" | "strict" | "function"
                ) {
                    issues.push(format!(
                        "tools[{tool_index}].{key} has unsupported function-tool semantics"
                    ));
                }
            }
        }
    }

    issues
}

fn inspect_responses_content(
    path: &str,
    content: Option<&Value>,
    text_only: bool,
    issues: &mut Vec<String>,
) {
    let Some(Value::Array(parts)) = content else {
        return;
    };
    for (part_index, part) in parts.iter().enumerate() {
        let kind = part.get("type").and_then(Value::as_str).unwrap_or("");
        let part_path = format!("{path}[{part_index}]");
        let is_text = matches!(kind, "text" | "input_text" | "output_text");
        let is_image = matches!(kind, "image_url" | "input_image");
        if text_only && !is_text {
            issues.push(format!(
                "{part_path} type '{kind}' cannot be represented in this message role during translation"
            ));
            continue;
        }
        if !is_text && !is_image {
            issues.push(format!(
                "{part_path} type '{kind}' has no canonical cross-format representation"
            ));
            continue;
        }
        if is_image {
            let url = part
                .pointer("/image_url/url")
                .and_then(Value::as_str)
                .or_else(|| part.get("image_url").and_then(Value::as_str))
                .or_else(|| part.get("url").and_then(Value::as_str));
            if url.is_none() {
                issues.push(format!("{part_path} image is missing a translatable URL"));
            }
        }
    }
}

fn decode_input_item(
    item: &Value,
    system: &mut Vec<String>,
    out: &mut Vec<Message>,
) -> Result<(), ProxyError> {
    let item_type = item.get("type").and_then(|t| t.as_str()).unwrap_or("");

    match item_type {
        "function_call" => {
            let call_id = item
                .get("call_id")
                .or_else(|| item.get("id"))
                .and_then(|v| v.as_str())
                .filter(|value| !value.is_empty())
                .map(String::from)
                .ok_or_else(|| {
                    ProxyError::bad_request("Responses function_call requires a non-empty call_id")
                })?;
            let name = item
                .get("name")
                .and_then(|v| v.as_str())
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    ProxyError::bad_request("Responses function_call requires a non-empty name")
                })?
                .to_string();
            let args = item
                .get("arguments")
                .map(|a| match a {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .unwrap_or_else(|| "{}".to_string());
            out.push(Message {
                role: Role::Assistant,
                parts: vec![Part::ToolCall {
                    id: Some(call_id),
                    name,
                    arguments: args,
                    signature: None,
                }],
            });
            Ok(())
        }
        "function_call_output" => {
            let call_id = item
                .get("call_id")
                .and_then(|v| v.as_str())
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    ProxyError::bad_request(
                        "Responses function_call_output requires a non-empty call_id",
                    )
                })?
                .to_string();
            let content = match item.get("output") {
                Some(Value::String(s)) => s.clone(),
                Some(other) => other.to_string(),
                None => String::new(),
            };
            out.push(Message {
                role: Role::Tool,
                parts: vec![Part::ToolResult {
                    tool_call_id: call_id,
                    name: None,
                    content,
                    is_error: false,
                }],
            });
            Ok(())
        }
        "message" | _ => {
            // Can be typed as "message" or a bare role/content object
            let role = item.get("role").and_then(|r| r.as_str()).unwrap_or("user");
            match role {
                "system" | "developer" => {
                    if let Some(text) = content_as_text(item.get("content")) {
                        if !text.is_empty() {
                            system.push(text);
                        }
                    }
                }
                "user" => {
                    out.push(Message {
                        role: Role::User,
                        parts: decode_content_parts(item.get("content")),
                    });
                }
                "assistant" => {
                    let mut parts = decode_content_parts(item.get("content"));
                    if let Some(tcs) = item.get("tool_calls").and_then(|t| t.as_array()) {
                        for tc in tcs {
                            let id = tc.get("id").and_then(|i| i.as_str()).map(String::from);
                            let func = tc.get("function");
                            let name = func
                                .and_then(|f| f.get("name"))
                                .and_then(|n| n.as_str())
                                .unwrap_or("")
                                .to_string();
                            let args = func
                                .and_then(|f| f.get("arguments"))
                                .map(|a| match a {
                                    Value::String(s) => s.clone(),
                                    other => other.to_string(),
                                })
                                .unwrap_or_else(|| "{}".to_string());
                            if !name.is_empty() {
                                parts.push(Part::ToolCall {
                                    id,
                                    name,
                                    arguments: args,
                                    signature: None,
                                });
                            }
                        }
                    }
                    out.push(Message {
                        role: Role::Assistant,
                        parts,
                    });
                }
                "tool" => {
                    let tool_call_id = item
                        .get("tool_call_id")
                        .or_else(|| item.get("call_id"))
                        .and_then(|i| i.as_str())
                        .unwrap_or("")
                        .to_string();
                    let content = content_as_text(item.get("content")).unwrap_or_default();
                    out.push(Message {
                        role: Role::Tool,
                        parts: vec![Part::ToolResult {
                            tool_call_id,
                            name: None,
                            content,
                            is_error: false,
                        }],
                    });
                }
                _ => {}
            }
            Ok(())
        }
    }
}

fn content_as_text(content: Option<&Value>) -> Option<String> {
    match content? {
        Value::String(s) => Some(s.clone()),
        Value::Array(parts) => {
            let mut text = String::new();
            for p in parts {
                if let Some(t) = p.get("text").and_then(|t| t.as_str()) {
                    text.push_str(t);
                }
            }
            Some(text)
        }
        _ => None,
    }
}

fn decode_content_parts(content: Option<&Value>) -> Vec<Part> {
    match content {
        Some(Value::String(s)) => {
            if s.is_empty() {
                vec![]
            } else {
                vec![Part::Text(s.clone())]
            }
        }
        Some(Value::Array(parts)) => {
            let mut out = Vec::new();
            for p in parts {
                match p.get("type").and_then(|t| t.as_str()).unwrap_or("") {
                    "text" | "input_text" | "output_text" => {
                        if let Some(t) = p.get("text").and_then(|t| t.as_str()) {
                            out.push(Part::Text(t.to_string()));
                        }
                    }
                    "image_url" | "input_image" => {
                        let url = p
                            .pointer("/image_url/url")
                            .and_then(|u| u.as_str())
                            .or_else(|| p.get("image_url").and_then(|u| u.as_str()))
                            .or_else(|| p.get("url").and_then(|u| u.as_str()));
                        if let Some(url) = url {
                            if let Some((mime, data)) = parse_data_url(url) {
                                out.push(Part::Image(ImageData::Base64 { mime, data }));
                            } else {
                                out.push(Part::Image(ImageData::Url(url.to_string())));
                            }
                        }
                    }
                    _ => {}
                }
            }
            out
        }
        _ => vec![],
    }
}

fn parse_data_url(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("data:")?;
    let (meta, data) = rest.split_once(',')?;
    let mime = meta.strip_suffix(";base64").unwrap_or(meta).to_string();
    Some((mime, data.to_string()))
}

fn decode_tools(tools: Option<&Value>) -> Vec<ToolDef> {
    let mut out = Vec::new();
    let Some(arr) = tools.and_then(|t| t.as_array()) else {
        return out;
    };
    for t in arr {
        // Can be flat {"type": "function", "name": ..., "parameters": ...}
        // or nested {"type": "function", "function": {"name": ...}}
        let func = t.get("function").unwrap_or(t);
        let Some(name) = func.get("name").and_then(|n| n.as_str()) else {
            continue;
        };
        out.push(ToolDef {
            name: name.to_string(),
            description: func
                .get("description")
                .and_then(|d| d.as_str())
                .map(String::from),
            parameters: func.get("parameters").cloned().unwrap_or(json!({})),
        });
    }
    out
}

fn decode_tool_choice(tc: Option<&Value>) -> (Option<ToolChoice>, Option<String>) {
    match tc {
        None => (Some(ToolChoice::Auto), None),
        Some(Value::String(s)) => match s.as_str() {
            "none" => (Some(ToolChoice::None), None),
            "required" => (Some(ToolChoice::Required), None),
            "auto" => (Some(ToolChoice::Auto), None),
            _ => (Some(ToolChoice::Auto), None),
        },
        Some(Value::Object(o)) => {
            let name = o
                .get("name")
                .or_else(|| o.get("function").and_then(|f| f.get("name")))
                .and_then(|n| n.as_str())
                .map(String::from);
            (Some(ToolChoice::Specific), name)
        }
        _ => (Some(ToolChoice::Auto), None),
    }
}

fn map_reasoning_effort(s: &str) -> Option<ThinkingLevel> {
    match s {
        "none" | "off" => Some(ThinkingLevel::Off),
        "minimal" | "low" => Some(ThinkingLevel::Low),
        "medium" => Some(ThinkingLevel::Medium),
        "high" => Some(ThinkingLevel::High),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Streaming SSE Encoder
// ---------------------------------------------------------------------------

pub struct ResponsesEncoder {
    ctx: EncoderCtx,
    response_id: String,
    seq: u64,
    created_sent: bool,
    active_text_item: bool,
    text_item_id: String,
    accumulated_text: String,
    active_tools: Vec<ActiveTool>,
    finish_sent: bool,
    usage: Option<crate::types::TokenUsage>,
}

struct ActiveTool {
    index: u32,
    call_id: String,
    name: String,
    arguments: String,
    output_index: usize,
}

impl ResponsesEncoder {
    pub fn new(ctx: EncoderCtx) -> Self {
        let response_id = format!("resp_{}", ctx.request_id.replace(['-', '_'], ""));
        let text_item_id = format!("msg_{}_0", ctx.request_id.replace(['-', '_'], ""));
        ResponsesEncoder {
            ctx,
            response_id,
            seq: 0,
            created_sent: false,
            active_text_item: false,
            text_item_id,
            accumulated_text: String::new(),
            active_tools: Vec::new(),
            finish_sent: false,
            usage: None,
        }
    }

    fn frame(&mut self, event_name: &str, mut data: Value) -> Bytes {
        let seq = self.seq;
        self.seq += 1;
        if let Some(obj) = data.as_object_mut() {
            obj.insert("type".to_string(), Value::String(event_name.to_string()));
            obj.insert("sequence_number".to_string(), json!(seq));
        }
        sse_frame(Some(event_name), &data.to_string())
    }

    fn ensure_created(&mut self, out: &mut Vec<Bytes>) {
        if !self.created_sent {
            self.created_sent = true;
            let resp_obj = json!({
                "id": self.response_id,
                "object": "response",
                "created_at": self.ctx.created,
                "model": self.ctx.model_name,
                "status": "in_progress",
                "error": null,
                "incomplete_details": null,
                "output": [],
                "usage": null
            });
            out.push(self.frame("response.created", json!({ "response": resp_obj.clone() })));
            out.push(self.frame("response.in_progress", json!({ "response": resp_obj })));
        }
    }

    fn ensure_text_item(&mut self, out: &mut Vec<Bytes>) {
        if !self.active_text_item {
            self.active_text_item = true;
            let item = json!({
                "id": self.text_item_id,
                "type": "message",
                "role": "assistant",
                "status": "in_progress",
                "content": []
            });
            out.push(self.frame(
                "response.output_item.added",
                json!({
                    "response_id": self.response_id,
                    "output_index": 0,
                    "item": item
                }),
            ));
            let part = json!({
                "type": "output_text",
                "text": "",
                "annotations": []
            });
            out.push(self.frame(
                "response.content_part.added",
                json!({
                    "response_id": self.response_id,
                    "output_index": 0,
                    "content_index": 0,
                    "item_id": self.text_item_id,
                    "part": part
                }),
            ));
        }
    }

    fn close_text_item(&mut self, out: &mut Vec<Bytes>) {
        if self.active_text_item {
            self.active_text_item = false;
            out.push(self.frame(
                "response.output_text.done",
                json!({
                    "response_id": self.response_id,
                    "output_index": 0,
                    "content_index": 0,
                    "item_id": self.text_item_id,
                    "text": self.accumulated_text
                }),
            ));
            out.push(self.frame(
                "response.content_part.done",
                json!({
                    "response_id": self.response_id,
                    "output_index": 0,
                    "content_index": 0,
                    "item_id": self.text_item_id,
                    "part": {
                        "type": "output_text",
                        "text": self.accumulated_text,
                        "annotations": []
                    }
                }),
            ));
            out.push(self.frame(
                "response.output_item.done",
                json!({
                    "response_id": self.response_id,
                    "output_index": 0,
                    "item": {
                        "id": self.text_item_id,
                        "type": "message",
                        "role": "assistant",
                        "status": "completed",
                        "content": [{
                            "type": "output_text",
                            "text": self.accumulated_text,
                            "annotations": []
                        }]
                    }
                }),
            ));
        }
    }

    pub fn encode(&mut self, event: StreamEvent) -> Vec<Bytes> {
        let mut out = Vec::new();
        match event {
            StreamEvent::Start { .. } => {
                self.ensure_created(&mut out);
            }
            StreamEvent::TextDelta(t) => {
                self.ensure_created(&mut out);
                self.ensure_text_item(&mut out);
                self.accumulated_text.push_str(&t);
                out.push(self.frame(
                    "response.output_text.delta",
                    json!({
                        "response_id": self.response_id,
                        "output_index": 0,
                        "content_index": 0,
                        "item_id": self.text_item_id,
                        "delta": t
                    }),
                ));
            }
            StreamEvent::ThinkingDelta { .. } => {
                // Raw provider reasoning is not a Responses reasoning-summary
                // item. reasoning.effort is supported as an input control, but
                // reasoning output items/summaries are outside this subset.
            }
            StreamEvent::ToolCallStart {
                index, id, name, ..
            } => {
                self.ensure_created(&mut out);
                self.close_text_item(&mut out);
                let call_id = id.unwrap_or_else(|| format!("call_{}_{}", self.response_id, index));
                let output_index = if self.accumulated_text.is_empty() {
                    self.active_tools.len()
                } else {
                    1 + self.active_tools.len()
                };
                let tool = ActiveTool {
                    index,
                    call_id: call_id.clone(),
                    name: name.clone(),
                    arguments: String::new(),
                    output_index,
                };
                self.active_tools.push(tool);
                out.push(self.frame(
                    "response.output_item.added",
                    json!({
                        "response_id": self.response_id,
                        "output_index": output_index,
                        "item": {
                            "id": call_id,
                            "type": "function_call",
                            "call_id": call_id,
                            "name": name,
                            "arguments": "",
                            "status": "in_progress"
                        }
                    }),
                ));
            }
            StreamEvent::ToolCallArgsDelta { index, args } => {
                self.ensure_created(&mut out);
                if let Some(tool) = self.active_tools.iter_mut().find(|t| t.index == index) {
                    tool.arguments.push_str(&args);
                    let call_id = tool.call_id.clone();
                    let out_idx = tool.output_index;
                    out.push(self.frame(
                        "response.function_call_arguments.delta",
                        json!({
                            "response_id": self.response_id,
                            "output_index": out_idx,
                            "item_id": call_id,
                            "call_id": call_id,
                            "delta": args
                        }),
                    ));
                }
            }
            StreamEvent::Usage(u) => {
                self.usage = Some(u);
            }
            StreamEvent::Finish(_finish) => {
                self.finish_sent = true;
                self.close_text_item(&mut out);
                let finished_tools: Vec<(usize, String, String, String)> = self
                    .active_tools
                    .iter()
                    .map(|t| {
                        (
                            t.output_index,
                            t.call_id.clone(),
                            t.name.clone(),
                            t.arguments.clone(),
                        )
                    })
                    .collect();
                for (tool_output_index, tool_call_id, tool_name, tool_arguments) in finished_tools {
                    out.push(self.frame(
                        "response.function_call_arguments.done",
                        json!({
                            "response_id": self.response_id,
                            "output_index": tool_output_index,
                            "item_id": tool_call_id,
                            "call_id": tool_call_id,
                            "name": tool_name,
                            "arguments": tool_arguments
                        }),
                    ));
                    out.push(self.frame(
                        "response.output_item.done",
                        json!({
                            "response_id": self.response_id,
                            "output_index": tool_output_index,
                            "item": {
                                "id": tool_call_id,
                                "type": "function_call",
                                "call_id": tool_call_id,
                                "name": tool_name,
                                "arguments": tool_arguments,
                                "status": "completed"
                            }
                        }),
                    ));
                }
                let final_resp = self.build_response_object();
                out.push(self.frame(
                    "response.completed",
                    json!({
                        "response": final_resp
                    }),
                ));
            }
        }
        out
    }

    fn build_response_object(&self) -> Value {
        let mut output = Vec::new();
        if !self.accumulated_text.is_empty() || self.active_tools.is_empty() {
            output.push(json!({
                "id": self.text_item_id,
                "type": "message",
                "role": "assistant",
                "status": "completed",
                "content": [{
                    "type": "output_text",
                    "text": self.accumulated_text,
                    "annotations": []
                }]
            }));
        }
        for tool in &self.active_tools {
            output.push(json!({
                "id": tool.call_id,
                "type": "function_call",
                "call_id": tool.call_id,
                "name": tool.name,
                "arguments": tool.arguments,
                "status": "completed"
            }));
        }

        let mut usage_obj = json!({
            "total_tokens": self.usage.as_ref().map(|u| u.input.unwrap_or(0) + u.output.unwrap_or(0)).unwrap_or(0),
            "input_tokens": self.usage.as_ref().and_then(|u| u.input).unwrap_or(0),
            "output_tokens": self.usage.as_ref().and_then(|u| u.output).unwrap_or(0),
        });
        if let Some(c) = self.usage.as_ref().and_then(|u| u.cached) {
            usage_obj["input_token_details"] = json!({ "cached_tokens": c });
        }
        if let Some(t) = self.usage.as_ref().and_then(|u| u.thinking) {
            usage_obj["output_token_details"] = json!({ "reasoning_tokens": t });
        }

        json!({
            "id": self.response_id,
            "object": "response",
            "created_at": self.ctx.created,
            "model": self.ctx.model_name,
            "status": "completed",
            "output": output,
            "usage": usage_obj
        })
    }

    pub fn finalize(&mut self) -> Vec<Bytes> {
        let mut out = Vec::new();
        if !self.finish_sent {
            out.extend(self.encode(StreamEvent::Finish(FinishReason::Stop)));
        }
        out
    }

    pub fn error_frame(&mut self, message: &str) -> Vec<Bytes> {
        let response = json!({
            "id": self.response_id,
            "object": "response",
            "created_at": self.ctx.created,
            "model": self.ctx.model_name,
            "status": "failed",
            "error": {
                "message": message,
                "code": "stream_error"
            },
            "incomplete_details": null,
            "output": [],
            "usage": null
        });
        vec![self.frame("response.failed", json!({ "response": response }))]
    }
}

// ---------------------------------------------------------------------------
// Non-streaming Aggregation
// ---------------------------------------------------------------------------

pub fn aggregate_responses(
    model_name: &str,
    request_id: &str,
    events: Vec<StreamEvent>,
    usage: &crate::types::TokenUsage,
) -> Value {
    let mut text = String::new();
    let mut tool_calls: Vec<(u32, String, String, String)> = Vec::new();

    for ev in events {
        match ev {
            StreamEvent::TextDelta(t) => text.push_str(&t),
            StreamEvent::ToolCallStart {
                index, id, name, ..
            } => {
                let call_id = id.unwrap_or_else(|| format!("call_{}_{}", request_id, index));
                tool_calls.push((index, call_id, name, String::new()));
            }
            StreamEvent::ToolCallArgsDelta { index, args } => {
                if let Some(tc) = tool_calls.iter_mut().find(|t| t.0 == index) {
                    tc.3.push_str(&args);
                }
            }
            _ => {}
        }
    }

    let mut output = Vec::new();
    let text_item_id = format!("msg_{}_0", request_id.replace(['-', '_'], ""));

    if !text.is_empty() || tool_calls.is_empty() {
        output.push(json!({
            "id": text_item_id,
            "type": "message",
            "role": "assistant",
            "status": "completed",
            "content": [{
                "type": "output_text",
                "text": text,
                "annotations": []
            }]
        }));
    }

    for (_, call_id, name, args) in tool_calls {
        output.push(json!({
            "id": call_id,
            "type": "function_call",
            "call_id": call_id,
            "name": name,
            "arguments": if args.is_empty() { "{}".to_string() } else { args },
            "status": "completed"
        }));
    }

    let mut usage_obj = json!({
        "total_tokens": usage.input.unwrap_or(0) + usage.output.unwrap_or(0),
        "input_tokens": usage.input.unwrap_or(0),
        "output_tokens": usage.output.unwrap_or(0),
    });
    if let Some(c) = usage.cached {
        usage_obj["input_token_details"] = json!({ "cached_tokens": c });
    }
    if let Some(t) = usage.thinking {
        usage_obj["output_token_details"] = json!({ "reasoning_tokens": t });
    }

    json!({
        "id": format!("resp_{}", request_id.replace(['-', '_'], "")),
        "object": "response",
        "created_at": chrono::Utc::now().timestamp(),
        "model": model_name,
        "status": "completed",
        "output": output,
        "usage": usage_obj
    })
}
