//! The internal, provider-neutral request and streaming-event model.
//!
//! Every inbound frontend decodes into these types; every outbound adapter
//! consumes them. Nothing here references a specific vendor (FR-11.1, NFR-5.1).

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Capabilities & configuration value types (shared with the DB layer)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireFormat {
    Openai,
    Anthropic,
    Gemini,
    /// Host-owned sentinel for providers whose actual wire translation is
    /// supplied by `wire_plugin`. It has no native adapter.
    Plugin,
}

impl WireFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            WireFormat::Openai => "openai",
            WireFormat::Anthropic => "anthropic",
            WireFormat::Gemini => "gemini",
            WireFormat::Plugin => "plugin",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "openai" => Some(WireFormat::Openai),
            "anthropic" => Some(WireFormat::Anthropic),
            "gemini" => Some(WireFormat::Gemini),
            "plugin" => Some(WireFormat::Plugin),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthScheme {
    Bearer,
    CustomHeader,
    QueryParam,
}

impl AuthScheme {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "bearer" => Some(AuthScheme::Bearer),
            "custom_header" => Some(AuthScheme::CustomHeader),
            "query_param" => Some(AuthScheme::QueryParam),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capabilities {
    #[serde(default)]
    pub text: bool,
    #[serde(default)]
    pub vision: bool,
    #[serde(default)]
    pub reasoning: bool,
    // Accept the dashboard's camelCase spelling too; always serialized snake_case.
    #[serde(default, alias = "toolCalling")]
    pub tool_calling: bool,
    #[serde(default)]
    pub audio: bool,
}

impl Capabilities {
    /// Build from a list of capability tokens (bootstrap / discovery import).
    pub fn from_tokens(tokens: &[String]) -> Self {
        let mut c = Capabilities::default();
        for t in tokens {
            match t.as_str() {
                "text" => c.text = true,
                "vision" => c.vision = true,
                "reasoning" => c.reasoning = true,
                "tool_calling" | "tools" => c.tool_calling = true,
                "audio" => c.audio = true,
                _ => {}
            }
        }
        c
    }

    /// Whether the configured capabilities can satisfy a request's needs.
    /// Unconfigured metadata counts as compatible (permissive default, FR-12.8).
    pub fn satisfies(&self, needs: &CapabilityNeeds) -> bool {
        if needs.vision && !self.vision {
            return false;
        }
        if needs.tools && !self.tool_calling {
            return false;
        }
        if needs.reasoning && !self.reasoning {
            return false;
        }
        true
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CapabilityNeeds {
    pub vision: bool,
    pub tools: bool,
    pub reasoning: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Prices {
    pub input_per_1m: Option<f64>,
    pub output_per_1m: Option<f64>,
    pub cached_per_1m: Option<f64>,
    pub thinking_per_1m: Option<f64>,
}

impl Prices {
    pub fn is_configured(&self) -> bool {
        self.input_per_1m.is_some() || self.output_per_1m.is_some()
    }
}

/// Policy for a client-supplied parameter value that is unsupported/out of range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamPolicy {
    Drop,
    Clamp,
    Reject,
    Forward,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamSpec {
    pub supported: bool,
    #[serde(default)]
    pub min: Option<f64>,
    #[serde(default)]
    pub max: Option<f64>,
    #[serde(default)]
    pub default: Option<f64>,
    #[serde(default = "default_policy")]
    pub policy: ParamPolicy,
}

fn default_policy() -> ParamPolicy {
    ParamPolicy::Forward
}

/// Canonical thinking level (FR-10.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThinkingLevel {
    Off,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThinkingMap {
    /// Canonical level -> upstream request field value (opaque JSON).
    #[serde(default)]
    pub levels: std::collections::HashMap<String, serde_json::Value>,
    /// Whether a numeric budget is also sent, and its field name.
    #[serde(default)]
    pub budget_field: Option<String>,
}

// ---------------------------------------------------------------------------
// Internal request model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ImageData {
    Base64 { mime: String, data: String },
    Url(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Part {
    Text(String),
    Image(ImageData),
    ToolCall {
        id: Option<String>,
        name: String,
        arguments: String,
        /// Opaque vendor signature (e.g. Gemini thoughtSignature) to round-trip.
        signature: Option<String>,
    },
    ToolResult {
        tool_call_id: String,
        name: Option<String>,
        content: String,
        is_error: bool,
    },
    Thinking {
        text: String,
        signature: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub struct Message {
    pub role: Role,
    pub parts: Vec<Part>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDef {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolChoice {
    Auto,
    None,
    Required,
    Specific,
}

#[derive(Debug, Clone, Default)]
pub struct SamplingParams {
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub top_k: Option<f64>,
    pub max_tokens: Option<u32>,
    pub stop: Vec<String>,
    pub seed: Option<i64>,
    pub presence_penalty: Option<f64>,
    pub frequency_penalty: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct InternalRequest {
    /// The model name the client asked for (alias, route, or provider/model-id).
    pub requested_model: String,
    pub system: Vec<String>,
    pub messages: Vec<Message>,
    pub tools: Vec<ToolDef>,
    pub tool_choice: Option<ToolChoice>,
    pub tool_choice_name: Option<String>,
    pub params: SamplingParams,
    pub stream: bool,
    pub thinking: Option<ThinkingLevel>,
    /// Fields the client sent that we did not model; forwarded or stripped per config.
    pub extra: serde_json::Map<String, serde_json::Value>,
    /// The original client body (JSON string), kept for same-format passthrough
    /// so unknown/provider-specific fields survive (FR-2.7, FR-2.10).
    pub raw_body: Option<String>,
}

impl InternalRequest {
    pub fn capability_needs(&self) -> CapabilityNeeds {
        let vision = self
            .messages
            .iter()
            .any(|m| m.parts.iter().any(|p| matches!(p, Part::Image(_))));
        CapabilityNeeds {
            vision,
            tools: !self.tools.is_empty(),
            reasoning: self.thinking.is_some(),
        }
    }

    /// Rough size estimate (chars) for context-window compatibility filtering.
    pub fn approx_input_tokens(&self) -> u64 {
        let mut chars: u64 = self.system.iter().map(|s| s.len() as u64).sum();
        for m in &self.messages {
            for p in &m.parts {
                chars += match p {
                    Part::Text(t) => t.len() as u64,
                    Part::Thinking { text, .. } => text.len() as u64,
                    Part::ToolCall {
                        name, arguments, ..
                    } => (name.len() + arguments.len()) as u64,
                    Part::ToolResult { content, .. } => content.len() as u64,
                    Part::Image(_) => 1000, // rough fixed cost for images
                };
            }
        }
        // ~4 chars per token, rounded up.
        chars.div_ceil(4)
    }
}

// ---------------------------------------------------------------------------
// Internal streaming events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct TokenUsage {
    pub input: Option<u64>,
    pub output: Option<u64>,
    pub cached: Option<u64>,
    pub thinking: Option<u64>,
}

impl TokenUsage {
    pub fn merge(&mut self, other: &TokenUsage) {
        if other.input.is_some() {
            self.input = other.input;
        }
        if other.output.is_some() {
            self.output = other.output;
        }
        if other.cached.is_some() {
            self.cached = other.cached;
        }
        if other.thinking.is_some() {
            self.thinking = other.thinking;
        }
    }
}

#[derive(Debug, Clone)]
pub enum FinishReason {
    Stop,
    Length,
    ToolCalls,
    ContentFilter,
    Other(String),
}

impl FinishReason {
    pub fn as_str(&self) -> &str {
        match self {
            FinishReason::Stop => "stop",
            FinishReason::Length => "length",
            FinishReason::ToolCalls => "tool_calls",
            FinishReason::ContentFilter => "content_filter",
            FinishReason::Other(s) => s,
        }
    }
}

#[derive(Debug, Clone)]
pub enum StreamEvent {
    /// The upstream has accepted the request; no client bytes sent yet.
    Start {
        upstream_request_id: Option<String>,
    },
    ThinkingDelta {
        text: String,
        signature: Option<String>,
    },
    TextDelta(String),
    ToolCallStart {
        index: u32,
        id: Option<String>,
        name: String,
        signature: Option<String>,
    },
    ToolCallArgsDelta {
        index: u32,
        args: String,
    },
    Usage(TokenUsage),
    Finish(FinishReason),
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// Key-level: rate limit. Cooldown + retry another target.
    RateLimit,
    /// Key-level: quota exhausted. Mark exhausted until reset + retry another target.
    QuotaExhausted,
    /// Key-level: invalid/forbidden credential. Disable + retry another target.
    AuthError,
    /// Key-level: upstream 5xx or connection failure. Retry another target.
    ServerError,
    ConnectionError,
    Timeout,
    /// Request-level: bad request / unsupported feature. Never retried.
    BadRequest,
}

impl FailureKind {
    pub fn is_key_level(&self) -> bool {
        !matches!(self, FailureKind::BadRequest)
    }
}

#[derive(Debug, Clone)]
pub struct UpstreamFailure {
    pub kind: FailureKind,
    pub status: Option<u16>,
    pub retry_after_secs: Option<u64>,
    /// Redacted, client-safe message.
    pub message: String,
    /// Quota reset instant parsed from the response, if any.
    pub quota_reset_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    RateLimited,
    BudgetExceeded,
    Unsupported,
    Upstream,
    AllTargetsUnavailable,
    Internal,
    /// Control-plane/administrative surface is degraded (NFR-2.7).
    ServiceUnavailable,
}

#[derive(Debug, Clone)]
pub struct ProxyError {
    pub kind: ErrorKind,
    pub message: String,
    pub retry_after_secs: Option<u64>,
    /// Response headers to surface (e.g. X-Kinetix-Fallback).
    pub headers: Vec<(String, String)>,
}

impl ProxyError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::BadRequest, msg)
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::NotFound, msg)
    }
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Unauthorized, msg)
    }
    pub fn unsupported(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Unsupported, msg)
    }
    pub fn rate_limited(msg: impl Into<String>, retry_after: Option<u64>) -> Self {
        Self {
            kind: ErrorKind::RateLimited,
            message: msg.into(),
            retry_after_secs: retry_after,
            headers: Vec::new(),
        }
    }
    pub fn budget_exceeded(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::BudgetExceeded, msg)
    }
    pub fn upstream(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Upstream, msg)
    }
    pub fn all_unavailable(msg: impl Into<String>, retry_after: Option<u64>) -> Self {
        Self {
            kind: ErrorKind::AllTargetsUnavailable,
            message: msg.into(),
            retry_after_secs: retry_after,
            headers: Vec::new(),
        }
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Internal, msg)
    }
    /// Service temporarily degraded (control plane unavailable). Rendered as
    /// 503 and does not affect any inference path (NFR-2.7).
    pub fn unavailable(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::ServiceUnavailable, msg)
    }
    pub fn new(kind: ErrorKind, msg: impl Into<String>) -> Self {
        Self {
            kind,
            message: msg.into(),
            retry_after_secs: None,
            headers: Vec::new(),
        }
    }
    pub fn http_status(&self) -> u16 {
        match self.kind {
            ErrorKind::BadRequest => 400,
            ErrorKind::Unauthorized => 401,
            ErrorKind::Forbidden => 403,
            ErrorKind::NotFound => 404,
            ErrorKind::Unsupported => 422,
            ErrorKind::RateLimited | ErrorKind::BudgetExceeded => 429,
            ErrorKind::AllTargetsUnavailable | ErrorKind::ServiceUnavailable => 503,
            ErrorKind::Upstream | ErrorKind::Internal => 502,
        }
    }
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for ProxyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn satisfies_enforces_reasoning_capability() {
        // A model that does not declare reasoning must not satisfy a request
        // that carries reasoning controls (FR-10.9/FR-12.11).
        let caps = Capabilities {
            text: true,
            vision: true,
            reasoning: false,
            tool_calling: true,
            audio: false,
        };
        let reasoning_needed = CapabilityNeeds {
            vision: false,
            tools: false,
            reasoning: true,
        };
        assert!(!caps.satisfies(&reasoning_needed));
        let text_only = CapabilityNeeds {
            vision: false,
            tools: false,
            reasoning: false,
        };
        assert!(caps.satisfies(&text_only));
        let vision_needed = CapabilityNeeds {
            vision: true,
            tools: false,
            reasoning: false,
        };
        assert!(caps.satisfies(&vision_needed));
    }
}
