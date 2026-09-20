//! Same-format passthrough (FR-2.7, FR-2.10).
//!
//! When the inbound frontend's wire format matches the selected provider's
//! outbound wire format, Kinetix forwards the client's protocol content with
//! minimal parsing/rewriting instead of translating through the internal model.
//! This preserves unknown/provider-specific fields (opaque state) that the
//! internal model does not represent.
//!
//! What is still applied on the passthrough path (FR-2.7): authentication,
//! routing, cancellation, accounting, safety checks, and — for accounting —
//! best-effort extraction of *usage metadata only*.
//!
//! The only content rewrite is the `model` field, replaced with the selected
//! upstream model id (the client sent an alias/Route/model name).

use serde_json::Value;

use crate::frontends::FrontendFormat;
use crate::types::WireFormat;

/// Whether an inbound/outbound format pair qualifies for passthrough.
pub fn is_passthrough(inbound: FrontendFormat, outbound: WireFormat) -> bool {
    match inbound {
        FrontendFormat::OpenAi => outbound == WireFormat::Openai,
        FrontendFormat::Anthropic => outbound == WireFormat::Anthropic,
        FrontendFormat::OpenAiResponses => false,
    }
}

/// Rewrite only the `model` field of a client body to the upstream model id,
/// preserving every other field byte-for-byte in structure.
///
/// When `force_stream` is set (the non-streaming aggregation path), `stream` is
/// also set to `true`: Kinetix always consumes the upstream as a stream
/// internally and aggregates when the client asked for a single JSON body. This
/// is required for OpenAI-compatible upstreams, which only emit the terminal
/// usage chunk when streaming (FR-1.4 + FR-6.2).
pub fn rewrite_model(raw: &str, upstream_id: &str, force_stream: bool) -> Option<String> {
    let mut v: Value = serde_json::from_str(raw).ok()?;
    let obj = v.as_object_mut()?;
    obj.insert("model".to_string(), Value::String(upstream_id.to_string()));
    if force_stream {
        obj.insert("stream".to_string(), Value::Bool(true));
        // Ask for the usage chunk where the OpenAI protocol supports it.
        obj.entry("stream_options".to_string())
            .or_insert_with(|| serde_json::json!({ "include_usage": true }));
    }
    serde_json::to_string(&v).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn passthrough_pairs() {
        assert!(is_passthrough(FrontendFormat::OpenAi, WireFormat::Openai));
        assert!(is_passthrough(
            FrontendFormat::Anthropic,
            WireFormat::Anthropic
        ));
        assert!(!is_passthrough(FrontendFormat::OpenAi, WireFormat::Gemini));
        assert!(!is_passthrough(FrontendFormat::OpenAi, WireFormat::Plugin));
        assert!(!is_passthrough(
            FrontendFormat::OpenAiResponses,
            WireFormat::Openai
        ));
    }

    #[test]
    fn rewrite_keeps_unknown_fields() {
        let raw = json!({
            "model": "coder",
            "stream": true,
            "messages": [{"role": "user", "content": "hi"}],
            "vendor_extension": {"keep": [1, 2, 3]}
        })
        .to_string();
        let out = rewrite_model(&raw, "gemini-3.6-flash", false).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["model"], "gemini-3.6-flash");
        assert_eq!(v["vendor_extension"]["keep"][2], 3);
    }

    #[test]
    fn force_stream_sets_stream_and_usage() {
        let raw = json!({
            "model": "free",
            "stream": false,
            "messages": [{"role": "user", "content": "hi"}]
        })
        .to_string();
        let out = rewrite_model(&raw, "mimo-v2.5-free", true).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["stream"], true);
        assert_eq!(v["stream_options"]["include_usage"], true);
    }
}
