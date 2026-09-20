//! Manifest parsing and validation (§5).
//!
//! `plugin.toml` is untrusted input: it is validated before anything is
//! compiled or executed. Validation is intentionally strict and explains each
//! rejection so the admin API and `kinetix plugin install` can surface it.

use anyhow::{anyhow, bail, Result};

use super::types::{parse_size, Capability, Manifest, MANIFEST_VERSION, PLUGIN_API_MAJOR};

/// The result of validating a manifest, including the effective host limits.
#[derive(Debug, Clone)]
pub struct ValidatedManifest {
    pub manifest: Manifest,
    /// Effective limits after applying `min(manifest request, host policy)`.
    pub effective: EffectiveLimits,
}

/// Host policy defaults (§14). These are not ABI constants; operators may lower
/// or raise them.
#[derive(Debug, Clone, Copy)]
pub struct HostPolicy {
    pub max_memory: u64,
    pub max_wall_time_ms: u64,
    pub max_outbound_requests: u32,
    pub max_http_body: u64,
    pub max_storage: u64,
}

impl Default for HostPolicy {
    fn default() -> Self {
        HostPolicy {
            max_memory: 64 * 1024 * 1024,
            max_wall_time_ms: 5000,
            max_outbound_requests: 4,
            max_http_body: 4 * 1024 * 1024,
            max_storage: 10 * 1024 * 1024,
        }
    }
}

/// The effective limits a plugin actually runs under.
#[derive(Debug, Clone, Copy)]
pub struct EffectiveLimits {
    pub memory: u64,
    pub wall_time_ms: u64,
    pub max_outbound_requests: u32,
    pub max_http_body: u64,
    pub storage: u64,
}

/// Parse and validate a `plugin.toml` string.
pub fn parse_and_validate(toml_str: &str, policy: HostPolicy) -> Result<ValidatedManifest> {
    let manifest: Manifest =
        toml::from_str(toml_str).map_err(|e| anyhow!("invalid plugin.toml: {e}"))?;
    validate(manifest, policy)
}

/// Validate an already-parsed manifest.
pub fn validate(manifest: Manifest, policy: HostPolicy) -> Result<ValidatedManifest> {
    if manifest.manifest_version != MANIFEST_VERSION {
        bail!(
            "unsupported manifest_version {} (host supports {})",
            manifest.manifest_version,
            MANIFEST_VERSION
        );
    }
    validate_id(&manifest.id)?;
    if manifest.name.trim().is_empty() {
        bail!("manifest `name` must not be empty");
    }
    if manifest.version.trim().is_empty() {
        bail!("manifest `version` must not be empty");
    }
    match manifest.api_major() {
        Some(major) if major == PLUGIN_API_MAJOR => {}
        Some(major) => bail!(
            "incompatible plugin_api '{}': host implements major {PLUGIN_API_MAJOR}, plugin requests {major}",
            manifest.plugin_api
        ),
        None => bail!("invalid plugin_api '{}'", manifest.plugin_api),
    }

    let provided = manifest.provides.provided();
    if provided.is_empty() {
        bail!("manifest provides no capabilities");
    }
    for p in &provided {
        validate_capability_name(p.capability, &p.name)?;
    }
    // Hooks are not addressable by name in the same way; require at least a
    // recognizable hook name when hooks are declared.
    for h in &manifest.provides.hooks {
        if !matches!(
            h.as_str(),
            "on_request_normalized" | "on_target_candidate" | "on_usage_finalized"
        ) {
            bail!("unknown hook '{h}'");
        }
    }

    let mut integration_ids = std::collections::HashSet::new();
    for integration in &manifest.integrations {
        validate_integration_id(&integration.id)?;
        if !integration_ids.insert(integration.id.as_str()) {
            bail!("duplicate integration id '{}'", integration.id);
        }
        if integration.name.trim().is_empty() {
            bail!("integration '{}' name must not be empty", integration.id);
        }
        if integration.provider_adapter.is_none()
            && integration.credential_strategy.is_none()
            && integration.auth_flow.is_none()
            && integration.model_source.is_none()
        {
            bail!(
                "integration '{}' must reference at least one provided capability",
                integration.id
            );
        }
        if let Some(name) = &integration.provider_adapter {
            if !manifest.provides.provider_adapters.contains(name) {
                bail!(
                    "integration '{}' references unknown provider_adapter '{}'",
                    integration.id,
                    name
                );
            }
        }
        if let Some(name) = &integration.credential_strategy {
            if !manifest.provides.credential_strategies.contains(name) {
                bail!(
                    "integration '{}' references unknown credential_strategy '{}'",
                    integration.id,
                    name
                );
            }
        }
        if let Some(name) = &integration.auth_flow {
            if !manifest.provides.auth_flows.contains(name) {
                bail!(
                    "integration '{}' references unknown auth_flow '{}'",
                    integration.id,
                    name
                );
            }
        }
        if let Some(name) = &integration.model_source {
            if !manifest.provides.model_sources.contains(name) {
                bail!(
                    "integration '{}' references unknown model_source '{}'",
                    integration.id,
                    name
                );
            }
        }
    }

    let mut ui_action_ids = std::collections::HashSet::new();
    for action in &manifest.ui.actions {
        validate_ui_id(&action.id)?;
        if !ui_action_ids.insert(action.id.as_str()) {
            bail!("duplicate ui action id '{}'", action.id);
        }
        if action.label.trim().is_empty() {
            bail!("ui action '{}' label must not be empty", action.id);
        }
        if action.kind != "auth" {
            bail!(
                "ui action '{}' has unsupported kind '{}': expected 'auth'",
                action.id,
                action.kind
            );
        }
        let integration = manifest
            .integrations
            .iter()
            .find(|integration| integration.id == action.integration)
            .ok_or_else(|| {
                anyhow!(
                    "ui action '{}' references unknown integration '{}'",
                    action.id,
                    action.integration
                )
            })?;
        if integration.auth_flow.is_none() || integration.credential_strategy.is_none() {
            bail!(
                "auth ui action '{}' requires integration '{}' to declare auth_flow and credential_strategy",
                action.id,
                action.integration
            );
        }
    }

    for host in &manifest.permissions.network_hosts {
        validate_network_host(host)?;
    }

    // §6.4: a routing-fact provider must declare a determinism mode the host can
    // enforce. `pure` means no outbound HTTP on the request path (enforced by
    // the host); `cached` means the guest publishes host-stamped facts.
    if !manifest.provides.routing_facts.is_empty()
        && !matches!(manifest.routing_facts_mode.as_str(), "pure" | "cached")
    {
        bail!(
            "invalid routing_facts_mode '{}': expected 'pure' or 'cached'",
            manifest.routing_facts_mode
        );
    }

    // §7.1: an adapter plugin is a pure translation library and must not hold
    // outbound network authority. This is enforced at runtime (the adapter-world
    // store refuses buffered host-http); a plugin that also legitimately
    // provides a control-plane capability needing network (e.g. a credential
    // strategy) is unaffected because that capability runs against the
    // `plugin`-world store.

    let effective = effective_limits(&manifest, policy)?;
    Ok(ValidatedManifest {
        manifest,
        effective,
    })
}

/// Apply host policy to the manifest's requested limits (§5, §14). The plugin
/// can never self-grant more than the host allows.
pub fn effective_limits(manifest: &Manifest, policy: HostPolicy) -> Result<EffectiveLimits> {
    let memory = parse_size(&manifest.limits.memory)
        .ok_or_else(|| anyhow!("invalid limits.memory '{}'", manifest.limits.memory))?;
    let max_http_body = parse_size(&manifest.limits.max_http_body).ok_or_else(|| {
        anyhow!(
            "invalid limits.max_http_body '{}'",
            manifest.limits.max_http_body
        )
    })?;
    let storage = parse_size(&manifest.limits.storage)
        .ok_or_else(|| anyhow!("invalid limits.storage '{}'", manifest.limits.storage))?;

    Ok(EffectiveLimits {
        memory: memory.min(policy.max_memory),
        wall_time_ms: manifest.limits.wall_time_ms.min(policy.max_wall_time_ms),
        max_outbound_requests: manifest
            .limits
            .max_outbound_requests
            .min(policy.max_outbound_requests),
        max_http_body: max_http_body.min(policy.max_http_body),
        storage: storage.min(policy.max_storage),
    })
}

fn validate_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 128 {
        bail!("plugin id must be 1..=128 characters");
    }
    let ok = id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-' || c == '_');
    if !ok {
        bail!("plugin id '{id}' may only contain lowercase letters, digits, '.', '-', '_'");
    }
    if id.starts_with('.') || id.ends_with('.') || id.contains("..") {
        bail!("plugin id '{id}' has an invalid dot placement");
    }
    Ok(())
}

fn validate_ui_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 64 {
        bail!("ui action id must be 1..=64 characters");
    }
    let ok = id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if !ok {
        bail!("ui action id '{id}' may only contain lowercase letters, digits, '-', '_'");
    }
    Ok(())
}

fn validate_integration_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 64 {
        bail!("integration id must be 1..=64 characters");
    }
    let ok = id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if !ok {
        bail!("integration id '{id}' may only contain lowercase letters, digits, '-', '_'");
    }
    Ok(())
}

fn validate_capability_name(cap: Capability, name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        bail!(
            "{} capability name must be 1..=64 characters",
            cap.manifest_key()
        );
    }
    let ok = name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if !ok {
        bail!(
            "{} name '{name}' may only contain lowercase letters, digits, '-', '_'",
            cap.manifest_key()
        );
    }
    Ok(())
}

/// §9: wildcards are allowed but conservative — a single leading `*.` label.
/// A bare `*` or a wildcard in the middle of a host is rejected.
fn validate_network_host(host: &str) -> Result<()> {
    let host = host.trim();
    if host.is_empty() {
        bail!("network host must not be empty");
    }
    if host == "*" || host.contains('*') && !host.starts_with("*.") {
        bail!("network host '{host}': only a single leading '*.' wildcard is allowed");
    }
    let base = host.strip_prefix("*.").unwrap_or(host);
    if base.contains('*') {
        bail!("network host '{host}': only a single leading '*.' wildcard is allowed");
    }
    if base.is_empty() || base.contains('/') || base.contains(' ') {
        bail!("network host '{host}' is not a valid hostname");
    }
    Ok(())
}

/// Whether a concrete destination host matches a declared `network_hosts`
/// entry. Wildcard entries match exactly one additional DNS label (§9).
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().to_ascii_lowercase();
    let host = host.trim().to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // one DNS label plus the suffix, and no further subdomain labels
        if let Some(prefix) = host.strip_suffix(suffix) {
            let prefix = prefix.strip_suffix('.').unwrap_or(prefix);
            return !prefix.is_empty() && !prefix.contains('.');
        }
        false
    } else {
        pattern == host
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
manifest_version = 1
id = "dev.example.foo"
name = "Foo"
version = "1.2.0"
plugin_api = "1"

[provides]
credential_strategies = ["foo-auth"]
auth_flows = ["foo-login"]
model_sources = ["foo-models"]

[[integrations]]
id = "foo"
name = "Foo Cloud"
description = "Foo provider integration"
credential_strategy = "foo-auth"
auth_flow = "foo-login"
model_source = "foo-models"

[[ui.actions]]
id = "connect"
label = "Connect account"
kind = "auth"
integration = "foo"

[permissions]
network_hosts = ["api.foo.example", "*.svc.example"]

[limits]
memory = "128MiB"
storage = "2MiB"
"#;

    #[test]
    fn validates_a_good_manifest() {
        let v = parse_and_validate(GOOD, HostPolicy::default()).unwrap();
        assert_eq!(v.manifest.id, "dev.example.foo");
        // 128MiB request is clamped to the 64MiB host policy.
        assert_eq!(v.effective.memory, 64 * 1024 * 1024);
        assert_eq!(v.effective.storage, 2 * 1024 * 1024);
    }

    #[test]
    fn rejects_incompatible_api() {
        let bad = GOOD.replace("plugin_api = \"1\"", "plugin_api = \"2\"");
        assert!(parse_and_validate(&bad, HostPolicy::default()).is_err());
    }

    #[test]
    fn rejects_no_capabilities() {
        let bad = GOOD
            .replace("credential_strategies = [\"foo-auth\"]", "")
            .replace("auth_flows = [\"foo-login\"]", "")
            .replace("model_sources = [\"foo-models\"]", "");
        assert!(parse_and_validate(&bad, HostPolicy::default()).is_err());
    }

    #[test]
    fn rejects_integration_referencing_missing_capability() {
        let bad = GOOD.replace(
            "model_source = \"foo-models\"",
            "model_source = \"missing-models\"",
        );
        let err = parse_and_validate(&bad, HostPolicy::default()).unwrap_err();
        assert!(
            err.to_string()
                .contains("unknown model_source 'missing-models'"),
            "{err}"
        );
    }

    #[test]
    fn rejects_duplicate_integration_ids() {
        let duplicate = format!(
            "{GOOD}\n[[integrations]]\nid = \"foo\"\nname = \"Duplicate\"\nmodel_source = \"foo-models\"\n"
        );
        let err = parse_and_validate(&duplicate, HostPolicy::default()).unwrap_err();
        assert!(
            err.to_string().contains("duplicate integration id 'foo'"),
            "{err}"
        );
    }

    #[test]
    fn rejects_empty_integration_binding() {
        let bad = GOOD
            .replace("credential_strategy = \"foo-auth\"", "")
            .replace("auth_flow = \"foo-login\"", "")
            .replace("model_source = \"foo-models\"", "");
        let err = parse_and_validate(&bad, HostPolicy::default()).unwrap_err();
        assert!(
            err.to_string()
                .contains("must reference at least one provided capability"),
            "{err}"
        );
    }

    #[test]
    fn rejects_integration_referencing_missing_auth_flow() {
        let bad = GOOD
            .replace(
                "model_sources = [\"foo-models\"]",
                "model_sources = [\"foo-models\"]\nauth_flows = [\"foo-login\"]",
            )
            .replace(
                "model_source = \"foo-models\"",
                "auth_flow = \"missing-login\"",
            );
        let err = parse_and_validate(&bad, HostPolicy::default()).unwrap_err();
        assert!(
            err.to_string()
                .contains("unknown auth_flow 'missing-login'"),
            "{err}"
        );
    }

    #[test]
    fn rejects_ui_action_with_unknown_integration() {
        let bad = GOOD.replace("integration = \"foo\"", "integration = \"missing\"");
        let err = parse_and_validate(&bad, HostPolicy::default()).unwrap_err();
        assert!(
            err.to_string()
                .contains("references unknown integration 'missing'"),
            "{err}"
        );
    }

    #[test]
    fn rejects_unsupported_ui_action_kind() {
        let bad = GOOD.replace("kind = \"auth\"", "kind = \"script\"");
        let err = parse_and_validate(&bad, HostPolicy::default()).unwrap_err();
        assert!(
            err.to_string().contains("unsupported kind 'script'"),
            "{err}"
        );
    }

    #[test]
    fn rejects_bad_wildcard() {
        let bad = GOOD.replace("\"*.svc.example\"", "\"api.*.example\"");
        assert!(parse_and_validate(&bad, HostPolicy::default()).is_err());
        let bare = GOOD.replace("\"*.svc.example\"", "\"*\"");
        assert!(parse_and_validate(&bare, HostPolicy::default()).is_err());
    }

    #[test]
    fn wildcard_matches_one_label() {
        assert!(host_matches("*.svc.example", "a.svc.example"));
        assert!(!host_matches("*.svc.example", "a.b.svc.example"));
        assert!(!host_matches("*.svc.example", "svc.example"));
        assert!(host_matches("api.foo.example", "api.foo.example"));
        assert!(!host_matches("api.foo.example", "evil.foo.example"));
    }
}
