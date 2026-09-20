//! Outbound adapter interface (FR-11.1). One adapter per wire format; chosen by
//! the provider's configured wire format, never by vendor. Built-in code goes
//! through exactly this interface so a plugin can attach later without rewrites.

use async_trait::async_trait;
use futures::stream::BoxStream;
use std::sync::Arc;

pub mod anthropic;
pub mod gemini;
pub mod openai;

use crate::types::{InternalRequest, ProxyError, StreamEvent, UpstreamFailure, WireFormat};

/// Everything an adapter needs to build and authenticate one upstream call.
pub struct UpstreamContext<'a> {
    pub provider: &'a crate::db::ProviderRow,
    pub model: &'a crate::db::ModelRow,
    /// The decrypted credential for the chosen account.
    pub credential: String,
}

/// The result of a successful (accepted) upstream call.
pub struct UpstreamStream {
    pub upstream_request_id: Option<String>,
    pub events: BoxStream<'static, Result<StreamEvent, UpstreamFailure>>,
}

#[async_trait]
pub trait Adapter: Send + Sync {
    /// Wire format this adapter speaks.
    fn wire_format(&self) -> &'static str;

    /// Build the outbound URL for a model call.
    fn build_url(&self, ctx: &UpstreamContext<'_>) -> Result<String, ProxyError>;

    /// Apply authentication to a request builder (header or query param).
    fn apply_auth(
        &self,
        ctx: &UpstreamContext<'_>,
        req: reqwest::RequestBuilder,
    ) -> reqwest::RequestBuilder;

    /// Translate the internal request into the upstream JSON body.
    fn build_body(&self, ctx: &UpstreamContext<'_>, req: &InternalRequest) -> serde_json::Value;

    /// Parse an upstream non-2xx response into a classified failure.
    fn classify_error(
        &self,
        status: u16,
        body: &str,
        headers: &reqwest::header::HeaderMap,
    ) -> UpstreamFailure;

    /// Parse one SSE `data:` payload (or one JSON object) into stream events.
    /// Returning an empty vec is fine (e.g. keepalive or metadata-only chunk).
    fn parse_stream_chunk(&self, data: &str) -> Result<Vec<StreamEvent>, UpstreamFailure>;

    /// Parse a full non-streaming response body into events (thin fallback path).
    fn parse_full_response(
        &self,
        body: &serde_json::Value,
    ) -> Result<Vec<StreamEvent>, UpstreamFailure>;

    /// The path used for model discovery.
    fn default_models_path(&self) -> &'static str {
        "/models"
    }

    /// Extract model IDs (and suggested limits) from a discovery response.
    fn parse_model_list(&self, body: &serde_json::Value) -> Vec<DiscoveredModel> {
        let _ = body;
        Vec::new()
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveredModel {
    pub id: String,
    pub display_name: Option<String>,
    pub context_window: Option<i64>,
    pub max_output_tokens: Option<i64>,
}

/// An adapter registry: selects the built-in adapter for a wire format.
/// Adding a new wire format (or a plugin) means adding an entry here; no
/// frontend code changes (NFR-5.1).
#[derive(Clone)]
pub struct AdapterRegistry {
    gemini: Arc<dyn Adapter>,
    openai: Arc<dyn Adapter>,
    anthropic: Arc<dyn Adapter>,
    /// Plugin-host-backed adapters keyed by `plugin:<id>/<capability>` (§6.0).
    /// A `DashMap` so a plugin adapter can be registered at enable time without
    /// rebuilding the shared registry.
    plugin: Arc<dashmap::DashMap<String, Arc<dyn Adapter>>>,
}

impl AdapterRegistry {
    pub fn new() -> Self {
        AdapterRegistry {
            gemini: Arc::new(crate::adapters::gemini::GeminiAdapter::new()),
            openai: Arc::new(crate::adapters::openai::OpenAiAdapter::new()),
            anthropic: Arc::new(crate::adapters::anthropic::AnthropicAdapter::new()),
            plugin: Arc::new(dashmap::DashMap::new()),
        }
    }

    pub fn for_format(&self, format: WireFormat) -> Arc<dyn Adapter> {
        match format {
            WireFormat::Gemini => self.gemini.clone(),
            WireFormat::Openai => self.openai.clone(),
            WireFormat::Anthropic => self.anthropic.clone(),
            WireFormat::Plugin => Arc::new(UnimplementedAdapter {
                format: "plugin adapter binding required",
            }),
        }
    }

    /// Select the adapter for a provider. A provider bound to a plugin adapter
    /// (`wire_plugin`, §6.0) resolves to the plugin adapter when the host
    /// provides it and the plugin is usable; otherwise selection fails closed
    /// with an unimplemented-format error (never a silent native fallback).
    pub fn for_provider(&self, provider: &crate::db::ProviderRow) -> Arc<dyn Adapter> {
        if let Some(r) = provider.wire_plugin_ref() {
            let key = r.to_string_ref();
            if let Some(adapter) = self.plugin.get(&key) {
                return adapter.clone();
            }
            // Registration keys by plugin id (one adapter capability per plugin);
            // accept a bare-id reference too.
            if let Some(adapter) = self.plugin.get(&r.plugin_id) {
                return adapter.clone();
            }
            return Arc::new(UnimplementedAdapter {
                format: Box::leak(
                    format!("plugin adapter '{key}' is unavailable").into_boxed_str(),
                ),
            });
        }
        self.for_format(provider.wire())
    }

    /// Register a plugin-backed adapter under its namespaced reference.
    pub fn register_plugin(&self, reference: impl Into<String>, adapter: Arc<dyn Adapter>) {
        self.plugin.insert(reference.into(), adapter);
    }
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// A no-op adapter used when a provider's wire format has no built-in
/// implementation yet. Keeps the seam honest: configuration is accepted, calls
/// fail with a clear, format-correct error.
pub struct UnimplementedAdapter {
    pub format: &'static str,
}

#[async_trait]
impl Adapter for UnimplementedAdapter {
    fn wire_format(&self) -> &'static str {
        self.format
    }
    fn build_url(&self, _ctx: &UpstreamContext<'_>) -> Result<String, ProxyError> {
        Err(ProxyError::unsupported(format!(
            "outbound wire format '{}' is not implemented in this build",
            self.format
        )))
    }
    fn apply_auth(
        &self,
        _ctx: &UpstreamContext<'_>,
        req: reqwest::RequestBuilder,
    ) -> reqwest::RequestBuilder {
        req
    }
    fn build_body(&self, _ctx: &UpstreamContext<'_>, _req: &InternalRequest) -> serde_json::Value {
        serde_json::Value::Null
    }
    fn classify_error(
        &self,
        status: u16,
        _body: &str,
        _headers: &reqwest::header::HeaderMap,
    ) -> UpstreamFailure {
        UpstreamFailure {
            kind: crate::types::FailureKind::ServerError,
            status: Some(status),
            retry_after_secs: None,
            message: "adapter not implemented".into(),
            quota_reset_at: None,
        }
    }
    fn parse_stream_chunk(&self, _data: &str) -> Result<Vec<StreamEvent>, UpstreamFailure> {
        Ok(Vec::new())
    }
    fn parse_full_response(
        &self,
        _body: &serde_json::Value,
    ) -> Result<Vec<StreamEvent>, UpstreamFailure> {
        Ok(Vec::new())
    }
}
