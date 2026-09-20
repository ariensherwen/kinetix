//! Plugin lifecycle and invocation (§11–§16).
//!
//! The manager owns install/enable/disable/remove, the per-plugin circuit
//! breaker, and every host→guest invocation. It is the only place that talks to
//! Wasmtime for request-path work, and it always maps guest results into typed
//! evidence that core policy consumes.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use tokio::sync::Semaphore;

use crate::crypto::Crypto;
use crate::db::Pool;

use super::manifest::{self, HostPolicy};
use super::package::{self, Package, SignatureStatus};
use super::runtime::{
    bindings, wit, DeadlineGuard, HostBacking, HostCtx, PluginFault, PluginRuntime, CONFIG_PREFIX,
};
use super::store::{self, PermissionGrant, PluginRow};
use super::types::{Capability, CircuitState, Limits, Manifest, Provided};

/// Bounds concurrent guest invocations so a flood of one plugin cannot exhaust
/// host threads or memory (§14).
const MAX_CONCURRENT_INVOCATIONS: usize = 16;
/// Consecutive runtime faults before a plugin's circuit opens (§15).
const CIRCUIT_FAULT_THRESHOLD: i64 = 5;
/// Cooldown before a half-open probe (§15).
const CIRCUIT_OPEN_SECS: i64 = 60;

/// Backing implementation for host effects (storage, logs, credentials).
pub struct Backing {
    pool: Pool,
    crypto: Arc<Crypto>,
}

#[async_trait::async_trait]
impl HostBacking for Backing {
    async fn kv_get(&self, plugin_id: &str, key: &str) -> Result<Option<Vec<u8>>> {
        store::kv_get(&self.pool, &self.crypto, plugin_id, key).await
    }
    async fn kv_put(&self, plugin_id: &str, key: &str, value: &[u8]) -> Result<()> {
        store::kv_put(&self.pool, &self.crypto, plugin_id, key, value).await
    }
    async fn kv_delete(&self, plugin_id: &str, key: &str) -> Result<()> {
        store::kv_delete(&self.pool, plugin_id, key).await
    }
    fn log(&self, plugin_id: &str, level: &str, message: &str) {
        // §18: plugin logs are namespaced and redacted like core logs.
        match level {
            "error" => tracing::error!(plugin = %plugin_id, "plugin: {message}"),
            "warn" => tracing::warn!(plugin = %plugin_id, "plugin: {message}"),
            "info" => tracing::info!(plugin = %plugin_id, "plugin: {message}"),
            "debug" => tracing::debug!(plugin = %plugin_id, "plugin: {message}"),
            _ => tracing::trace!(plugin = %plugin_id, "plugin: {message}"),
        }
    }
    async fn resolve_secret(
        &self,
        _plugin_id: &str,
        provider_id: &str,
        account_id: &str,
    ) -> Result<String> {
        let account = crate::db::get_account(&self.pool, account_id)
            .await?
            .ok_or_else(|| anyhow!("account not found"))?;
        if account.provider_id != provider_id {
            bail!(
                "account '{}' does not belong to provider '{}'",
                account_id,
                provider_id
            );
        }
        self.crypto.decrypt(&account.secret_enc)
    }
}

/// The plugin manager. Cheap to clone (Arc inside).
#[derive(Clone)]
pub struct PluginManager {
    inner: Arc<Inner>,
}

struct Inner {
    runtime: PluginRuntime,
    pool: Pool,
    crypto: Arc<Crypto>,
    backing: Arc<Backing>,
    http: reqwest::Client,
    policy: HostPolicy,
    package_root: PathBuf,
    semaphore: Semaphore,
    /// Simple counters for the admin metrics surface (§18).
    invocations: std::sync::atomic::AtomicU64,
    faults: std::sync::atomic::AtomicU64,
    timeouts: std::sync::atomic::AtomicU64,
    cancellations: std::sync::atomic::AtomicU64,
    http_requests: std::sync::atomic::AtomicU64,
}

impl PluginManager {
    pub fn new(
        pool: Pool,
        crypto: Arc<Crypto>,
        http: reqwest::Client,
        policy: HostPolicy,
        package_root: PathBuf,
    ) -> Result<Self> {
        std::fs::create_dir_all(&package_root).map_err(|e| {
            anyhow!(
                "creating plugin package store {}: {e}",
                package_root.display()
            )
        })?;
        let runtime = PluginRuntime::new()?;
        let backing = Arc::new(Backing {
            pool: pool.clone(),
            crypto: crypto.clone(),
        });
        Ok(PluginManager {
            inner: Arc::new(Inner {
                runtime,
                pool,
                crypto,
                backing,
                http,
                policy,
                package_root,
                semaphore: Semaphore::new(MAX_CONCURRENT_INVOCATIONS),
                invocations: Default::default(),
                faults: Default::default(),
                timeouts: Default::default(),
                cancellations: Default::default(),
                http_requests: Default::default(),
            }),
        })
    }

    pub fn policy(&self) -> HostPolicy {
        self.inner.policy
    }

    pub fn counters(&self) -> PluginCounters {
        use std::sync::atomic::Ordering::Relaxed;
        PluginCounters {
            invocations: self.inner.invocations.load(Relaxed),
            faults: self.inner.faults.load(Relaxed),
            timeouts: self.inner.timeouts.load(Relaxed),
            cancellations: self.inner.cancellations.load(Relaxed),
            http_requests: self.inner.http_requests.load(Relaxed),
        }
    }

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    /// Install (or upgrade) a plugin from package bytes. Verifies hash, parses
    /// and validates the manifest, checks signature, compiles the component,
    /// and stores it **installed-disabled** (§11).
    pub async fn install(
        &self,
        bytes: &[u8],
        expected_sha256: Option<&str>,
        trusted_keys: &[[u8; 32]],
        allow_untrusted_signature: bool,
    ) -> Result<InstallOutcome> {
        let pkg = package::read_package(bytes)?;
        if let Some(expected) = expected_sha256 {
            if !expected.eq_ignore_ascii_case(&pkg.package_sha256) {
                bail!(
                    "package hash mismatch: expected {expected}, computed {}",
                    pkg.package_sha256
                );
            }
        }
        let validated = package::validate_manifest(&pkg, self.inner.policy)?;
        let sig = package::verify_signature(&pkg, trusted_keys)?;
        if sig == SignatureStatus::Untrusted && !allow_untrusted_signature {
            bail!("package signature is present but not from a trusted publisher key");
        }
        // Compile now so a broken component is rejected before it is stored.
        self.inner
            .runtime
            .compile(&pkg.component)
            .map_err(|e| anyhow!("{e}"))?;

        // Preserve the exact accepted package before publishing its active
        // metadata. The filename is content-addressed so the version string
        // never becomes a filesystem path component.
        let package_path = self
            .persist_package(&validated.manifest.id, &pkg.package_sha256, bytes)
            .await?;

        // Installation and upgrade never grant authority. The operator must
        // explicitly approve the declared permission set before enablement.
        store::upsert_plugin(
            &self.inner.pool,
            &validated,
            &pkg.package_sha256,
            &pkg.component,
            sig.as_str(),
            &package_path,
        )
        .await?;

        Ok(InstallOutcome {
            id: validated.manifest.id.clone(),
            version: validated.manifest.version.clone(),
            package_sha256: pkg.package_sha256,
            signature: sig,
            provides: validated.manifest.provides.provided(),
        })
    }

    async fn persist_package(&self, plugin_id: &str, sha256: &str, bytes: &[u8]) -> Result<String> {
        let relative = PathBuf::from(plugin_id).join(format!("{sha256}.kxp"));
        let target = self.inner.package_root.join(&relative);
        let parent = target
            .parent()
            .ok_or_else(|| anyhow!("plugin package path has no parent"))?;

        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            anyhow!(
                "creating plugin package directory {}: {e}",
                parent.display()
            )
        })?;

        match tokio::fs::read(&target).await {
            Ok(existing) => {
                if existing != bytes {
                    bail!(
                        "plugin package store collision at {} for SHA-256 {}",
                        target.display(),
                        sha256
                    );
                }
                return Ok(relative.to_string_lossy().into_owned());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(anyhow!(
                    "reading existing plugin package {}: {e}",
                    target.display()
                ));
            }
        }

        let temp = target.with_extension(format!("kxp.tmp-{}", uuid::Uuid::new_v4().simple()));
        tokio::fs::write(&temp, bytes)
            .await
            .map_err(|e| anyhow!("writing plugin package {}: {e}", temp.display()))?;

        if let Err(rename_err) = tokio::fs::rename(&temp, &target).await {
            match tokio::fs::read(&target).await {
                Ok(existing) if existing == bytes => {
                    let _ = tokio::fs::remove_file(&temp).await;
                }
                _ => {
                    let _ = tokio::fs::remove_file(&temp).await;
                    return Err(anyhow!(
                        "publishing plugin package {}: {rename_err}",
                        target.display()
                    ));
                }
            }
        }

        Ok(relative.to_string_lossy().into_owned())
    }

    /// Root of the immutable package cache.
    pub fn package_root(&self) -> &Path {
        &self.inner.package_root
    }

    /// Install from a local file path. The computed SHA-256 is recorded (§11).
    pub async fn install_file(
        &self,
        path: &std::path::Path,
        trusted_keys: &[[u8; 32]],
        allow_untrusted_signature: bool,
    ) -> Result<InstallOutcome> {
        let bytes = std::fs::read(path).map_err(|e| anyhow!("reading {}: {e}", path.display()))?;
        self.install(&bytes, None, trusted_keys, allow_untrusted_signature)
            .await
    }

    /// Enable an installed plugin, instantiating it once to prove it loads.
    pub async fn enable(&self, id: &str) -> Result<()> {
        let row = self
            .get(id)
            .await?
            .ok_or_else(|| anyhow!("plugin '{id}' is not installed"))?;
        let manifest = row
            .manifest()
            .ok_or_else(|| anyhow!("plugin '{id}' has an unreadable manifest"))?;
        if !manifest.compatible() {
            bail!("plugin '{id}' is not API-compatible with this host");
        }
        let grants = self.ensure_permissions_approved(id, &manifest).await?;
        let limits = manifest::effective_limits(&manifest, self.inner.policy)?;
        // Instantiate to prove the component links against our host API.
        let mut store = self.new_store(&row, &limits, &grants, false, true);
        let component = self.inner.runtime.compile(&row.component)?;
        let linker = self.inner.runtime.linker()?;
        let _ = self
            .inner
            .runtime
            .instantiate(&linker, &mut store, &component)
            .await?;
        store::set_enabled(&self.inner.pool, id, true).await?;
        store::clear_plugin_failures(&self.inner.pool, id).await?;
        Ok(())
    }

    pub async fn disable(&self, id: &str) -> Result<()> {
        store::set_enabled(&self.inner.pool, id, false).await?;
        Ok(())
    }

    pub async fn remove(&self, id: &str) -> Result<()> {
        store::delete_plugin(&self.inner.pool, id).await?;
        Ok(())
    }

    pub async fn list(&self) -> Result<Vec<PluginRow>> {
        store::list_plugins(&self.inner.pool).await
    }

    pub async fn get(&self, id: &str) -> Result<Option<PluginRow>> {
        store::get_plugin(&self.inner.pool, id).await
    }

    /// Return host-owned dashboard settings without revealing secret values.
    pub async fn ui_settings(&self, id: &str) -> Result<serde_json::Value> {
        let row = self
            .get(id)
            .await?
            .ok_or_else(|| anyhow!("plugin '{id}' is not installed"))?;
        let manifest = row
            .manifest()
            .ok_or_else(|| anyhow!("plugin '{id}' has an unreadable manifest"))?;

        let mut fields = Vec::new();
        for setting in &manifest.ui.settings {
            let storage_key = format!("{CONFIG_PREFIX}{}", setting.key);
            let stored = store::kv_get(
                &self.inner.pool,
                &self.inner.crypto,
                id,
                &storage_key,
            )
            .await?;
            let configured = stored.is_some();
            let value = if setting.kind == "secret" {
                serde_json::Value::Null
            } else if let Some(bytes) = stored {
                let text = String::from_utf8(bytes)
                    .map_err(|_| anyhow!("stored setting '{}' is not utf-8", setting.key))?;
                if setting.kind == "boolean" {
                    serde_json::Value::Bool(text == "true")
                } else {
                    serde_json::Value::String(text)
                }
            } else if let Some(default) = &setting.default {
                if setting.kind == "boolean" {
                    serde_json::Value::Bool(default == "true")
                } else {
                    serde_json::Value::String(default.clone())
                }
            } else {
                serde_json::Value::Null
            };

            fields.push(serde_json::json!({
                "key": setting.key,
                "label": setting.label,
                "kind": setting.kind,
                "description": setting.description,
                "required": setting.required,
                "options": setting.options,
                "configured": configured,
                "value": value,
            }));
        }

        Ok(serde_json::json!({ "id": id, "settings": fields }))
    }

    /// Partially update host-owned plugin settings. Omitted keys are unchanged;
    /// null deletes an optional value. Secret values are never echoed back.
    pub async fn update_ui_settings(
        &self,
        id: &str,
        values: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let row = self
            .get(id)
            .await?
            .ok_or_else(|| anyhow!("plugin '{id}' is not installed"))?;
        let manifest = row
            .manifest()
            .ok_or_else(|| anyhow!("plugin '{id}' has an unreadable manifest"))?;

        for (key, value) in values {
            let setting = manifest
                .ui
                .settings
                .iter()
                .find(|setting| setting.key == *key)
                .ok_or_else(|| anyhow!("unknown plugin setting '{key}'"))?;
            let storage_key = format!("{CONFIG_PREFIX}{key}");

            if value.is_null() {
                if setting.required {
                    bail!("required plugin setting '{key}' cannot be cleared");
                }
                store::kv_delete(&self.inner.pool, id, &storage_key).await?;
                continue;
            }

            let encoded = match setting.kind.as_str() {
                "boolean" => value
                    .as_bool()
                    .ok_or_else(|| anyhow!("plugin setting '{key}' must be boolean"))?
                    .to_string(),
                "text" | "secret" | "select" => {
                    let text = value
                        .as_str()
                        .ok_or_else(|| anyhow!("plugin setting '{key}' must be a string"))?;
                    if setting.required && text.trim().is_empty() {
                        bail!("required plugin setting '{key}' must not be empty");
                    }
                    if setting.kind == "select" && !setting.options.iter().any(|v| v == text) {
                        bail!("plugin setting '{key}' has an unsupported option");
                    }
                    text.to_string()
                }
                other => bail!("unsupported plugin setting kind '{other}'"),
            };

            if encoded.len() > 64 * 1024 {
                bail!("plugin setting '{key}' exceeds 64 KiB");
            }
            store::kv_put(
                &self.inner.pool,
                &self.inner.crypto,
                id,
                &storage_key,
                encoded.as_bytes(),
            )
            .await?;
        }

        self.ui_settings(id).await
    }

    /// Explicitly approve the plugin's currently declared permission set.
    pub async fn approve_permissions(&self, id: &str) -> Result<Vec<PermissionGrant>> {
        let row = self
            .get(id)
            .await?
            .ok_or_else(|| anyhow!("plugin '{id}' is not installed"))?;
        let manifest = row
            .manifest()
            .ok_or_else(|| anyhow!("plugin '{id}' has an unreadable manifest"))?;
        let grants = permission_grants(&manifest);
        store::replace_permissions(&self.inner.pool, id, &grants).await?;
        Ok(grants)
    }

    /// Revoke one permission and immediately disable the plugin.
    pub async fn revoke_permission(&self, id: &str, permission: &str) -> Result<()> {
        if self.get(id).await?.is_none() {
            bail!("plugin '{id}' is not installed");
        }
        store::revoke_permission(&self.inner.pool, id, permission).await?;
        self.disable(id).await
    }

    /// Return approved grants only when they exactly match the current manifest.
    async fn ensure_permissions_approved(
        &self,
        id: &str,
        manifest: &Manifest,
    ) -> Result<Vec<PermissionGrant>> {
        let requested = permission_grants(manifest);
        let approved: Vec<PermissionGrant> = store::permissions(&self.inner.pool, id)
            .await?
            .into_iter()
            .map(|row| PermissionGrant {
                permission: row.permission,
                value_json: row.value_json,
            })
            .collect();

        let requested_set: std::collections::BTreeSet<_> = requested
            .iter()
            .map(|g| (g.permission.clone(), g.value_json.clone()))
            .collect();
        let approved_set: std::collections::BTreeSet<_> = approved
            .iter()
            .map(|g| (g.permission.clone(), g.value_json.clone()))
            .collect();

        if requested_set != approved_set {
            bail!(
                "plugin '{id}' permissions are not approved for the current manifest; run kinetix plugin approve {id}"
            );
        }
        Ok(approved)
    }

    /// Read the plugin's host-stamped cached routing facts (§6.4) for the
    /// request path. Returns `(name, value_json, observed_at, max_age_ms)`.
    /// This never invokes the guest, so a `cached` fact provider cannot add
    /// network or wall-time cost to routing.
    pub async fn cached_facts(
        &self,
        id: &str,
    ) -> Result<Vec<(String, serde_json::Value, Option<String>, Option<u64>)>> {
        let entries = store::kv_list_prefix(
            &self.inner.pool,
            &self.inner.crypto,
            id,
            super::runtime::CACHE_PREFIX,
        )
        .await?;
        let mut out = Vec::new();
        for (key, bytes) in entries {
            let Ok(env) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
                continue;
            };
            let name = key
                .strip_prefix(super::runtime::CACHE_PREFIX)
                .unwrap_or(&key)
                .to_string();
            let value = env.get("value").cloned().unwrap_or(serde_json::Value::Null);
            let observed_at = env
                .get("observed_at")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let max_age_ms = env.get("max_age_ms").and_then(|v| v.as_u64());
            out.push((name, value, observed_at, max_age_ms));
        }
        Ok(out)
    }

    /// Whether a plugin is installed, enabled, and its circuit is not open.
    pub async fn is_usable(&self, id: &str) -> bool {
        let row = match self.get(id).await {
            Ok(Some(row)) if row.status().is_enabled() => row,
            _ => return false,
        };
        let Some(manifest) = row.manifest() else {
            return false;
        };
        if self
            .ensure_permissions_approved(id, &manifest)
            .await
            .is_err()
        {
            return false;
        }
        match store::runtime_state(&self.inner.pool, id).await {
            Ok(Some(state)) => !matches!(state.circuit(), CircuitState::Open),
            _ => true,
        }
    }

    /// Whether the plugin provides the named capability.
    pub async fn provides(&self, id: &str, capability: Capability, name: &str) -> bool {
        match self.get(id).await {
            Ok(Some(row)) => row
                .manifest()
                .map(|m| {
                    m.provides
                        .provided()
                        .iter()
                        .any(|p| p.capability == capability && p.name == name)
                })
                .unwrap_or(false),
            _ => false,
        }
    }

    /// Enabled plugins that declare the named read-only hook, newest id order.
    /// A hook is a side observer: if the plugin is disabled, faulted, or its
    /// circuit is open it simply does not run (core never fails a request on a
    /// hook's behalf, §6.6).
    pub async fn plugins_with_hook(&self, hook: &str) -> Vec<String> {
        let Ok(rows) = self.list().await else {
            return Vec::new();
        };
        let mut ids = Vec::new();
        for row in rows {
            let declares = row
                .manifest()
                .map(|m| m.provides.hooks.iter().any(|h| h == hook))
                .unwrap_or(false);
            if declares && self.is_usable(&row.id).await {
                ids.push(row.id);
            }
        }
        ids
    }

    // -----------------------------------------------------------------------
    // Invocation plumbing
    // -----------------------------------------------------------------------

    fn new_store(
        &self,
        row: &PluginRow,
        limits: &manifest::EffectiveLimits,
        grants: &[PermissionGrant],
        adapter: bool,
        buffered_http_allowed: bool,
    ) -> wasmtime::Store<HostCtx> {
        let manifest = row.manifest().unwrap_or_else(|| Manifest {
            manifest_version: 1,
            id: row.id.clone(),
            name: row.id.clone(),
            version: row.version.clone(),
            plugin_api: "1".into(),
            provides: Default::default(),
            integrations: Default::default(),
            ui: Default::default(),
            permissions: Default::default(),
            limits: Limits::default(),
            routing_facts_mode: "pure".into(),
        });
        // Runtime authority is derived only from approved grant rows.
        let mut network_hosts = Vec::new();
        let mut credential_scopes = Vec::new();
        let mut credential_read = false;
        for grant in grants {
            match grant.permission.as_str() {
                "network_hosts" => {
                    network_hosts = serde_json::from_str(&grant.value_json).unwrap_or_default();
                }
                "credential_scopes" => {
                    credential_scopes = serde_json::from_str(&grant.value_json).unwrap_or_default();
                }
                "credential_read" => {
                    credential_read = serde_json::from_str(&grant.value_json).unwrap_or(false);
                }
                _ => {}
            }
        }

        let ctx = HostCtx {
            plugin_id: row.id.clone(),
            network_hosts,
            credential_read,
            credential_sign: !credential_scopes.is_empty(),
            credential_scopes,
            storage_quota: limits.storage,
            max_outbound_requests: limits.max_outbound_requests,
            max_http_body: limits.max_http_body,
            adapter_stream: adapter,
            buffered_http_allowed,
            outbound_count: 0,
            http: self.inner.http.clone(),
            backing: self.inner.backing.clone(),
            limits: wasmtime::StoreLimitsBuilder::new().build(),
        };
        // `new_store` replaces the placeholder store-limits field.
        self.inner.runtime.new_store(ctx, limits.memory)
    }

    /// Prepare a ready-to-call instance for a plugin.
    async fn prepare(&self, id: &str, buffered_http_allowed: bool) -> Result<Prepared> {
        let row = self
            .get(id)
            .await?
            .ok_or_else(|| anyhow!("plugin '{id}' is not installed"))?;
        if !row.status().is_enabled() {
            bail!("plugin '{id}' is not enabled");
        }
        let manifest = row
            .manifest()
            .ok_or_else(|| anyhow!("plugin '{id}' has an unreadable manifest"))?;
        let grants = self.ensure_permissions_approved(id, &manifest).await?;
        let limits = manifest::effective_limits(&manifest, self.inner.policy)?;
        let component = self.inner.runtime.compile(&row.component)?;
        let linker = self.inner.runtime.linker()?;
        let mut store = self.new_store(&row, &limits, &grants, false, buffered_http_allowed);
        let plugin = self
            .inner
            .runtime
            .instantiate(&linker, &mut store, &component)
            .await?;
        Ok(Prepared {
            store,
            plugin,
            wall_time: Duration::from_millis(limits.wall_time_ms),
        })
    }

    /// Instantiate the optional account-authorization world for one call.
    async fn prepare_auth(&self, id: &str) -> Result<AuthPrepared> {
        let row = self
            .get(id)
            .await?
            .ok_or_else(|| anyhow!("plugin '{id}' is not installed"))?;
        if !row.status().is_enabled() {
            bail!("plugin '{id}' is not enabled");
        }
        let manifest = row
            .manifest()
            .ok_or_else(|| anyhow!("plugin '{id}' has an unreadable manifest"))?;
        let grants = self.ensure_permissions_approved(id, &manifest).await?;
        let limits = manifest::effective_limits(&manifest, self.inner.policy)?;
        let component = self.inner.runtime.compile(&row.component)?;
        let linker = self.inner.runtime.linker()?;
        let mut store = self.new_store(&row, &limits, &grants, false, true);
        let plugin = self
            .inner
            .runtime
            .instantiate_auth(&linker, &mut store, &component)
            .await?;
        Ok(AuthPrepared {
            store,
            plugin,
            wall_time: Duration::from_millis(limits.wall_time_ms),
        })
    }

    /// Start a named plugin-provided account authorization flow.
    pub async fn auth_begin(
        &self,
        id: &str,
        flow_name: &str,
        redirect_uri: &str,
        state: &str,
        pkce_challenge: Option<&str>,
    ) -> Result<String, PluginFault> {
        if !self.provides(id, Capability::AuthFlow, flow_name).await {
            return Err(PluginFault::InvalidResult(format!(
                "plugin '{id}' does not provide auth flow '{flow_name}'"
            )));
        }
        self.bump_invocation();
        let _permit = self.inner.semaphore.acquire().await;
        let mut prepared = self
            .prepare_auth(id)
            .await
            .map_err(|e| PluginFault::Internal(e.to_string()))?;
        let plugin = prepared.plugin;
        let rt = self.inner.runtime.clone();
        let _guard = rt.arm_deadline(&mut prepared.store, prepared.wall_time);
        let result = plugin
            .auth_flow()
            .call_begin(
                &mut prepared.store,
                flow_name,
                redirect_uri,
                state,
                pkce_challenge,
            )
            .await
            .map_err(map_call_error)
            .and_then(map_auth_result);
        self.settle(id, result).await
    }

    /// Exchange a browser callback code for host-persistable credential JSON.
    pub async fn auth_exchange(
        &self,
        id: &str,
        flow_name: &str,
        code: &str,
        redirect_uri: &str,
        pkce_verifier: Option<&str>,
    ) -> Result<
        crate::plugins::runtime::auth_bindings::kinetix::plugin::types::AuthResult,
        PluginFault,
    > {
        if !self.provides(id, Capability::AuthFlow, flow_name).await {
            return Err(PluginFault::InvalidResult(format!(
                "plugin '{id}' does not provide auth flow '{flow_name}'"
            )));
        }
        self.bump_invocation();
        let _permit = self.inner.semaphore.acquire().await;
        let mut prepared = self
            .prepare_auth(id)
            .await
            .map_err(|e| PluginFault::Internal(e.to_string()))?;
        let plugin = prepared.plugin;
        let rt = self.inner.runtime.clone();
        let _guard = rt.arm_deadline(&mut prepared.store, prepared.wall_time);
        let result = plugin
            .auth_flow()
            .call_exchange(
                &mut prepared.store,
                flow_name,
                code,
                redirect_uri,
                pkce_verifier,
            )
            .await
            .map_err(map_call_error)
            .and_then(map_auth_result);
        self.settle(id, result).await
    }

    // -----------------------------------------------------------------------
    // ProviderAdapter invocation (§6.3, §7.1)
    //
    // The adapter world is bound separately so the buffered host-http import can
    // never serve as the adapter transport. Adapters are synchronous translation
    // functions; the manager exposes async methods and `PluginAdapter` (the sync
    // `Adapter` impl) bridges them via `block_in_place`.
    // -----------------------------------------------------------------------

    /// Instantiate the adapter world for a plugin.
    async fn prepare_adapter(&self, id: &str) -> Result<AdapterPrepared> {
        let row = self
            .get(id)
            .await?
            .ok_or_else(|| anyhow!("plugin '{id}' is not installed"))?;
        if !row.status().is_enabled() {
            bail!("plugin '{id}' is not enabled");
        }
        let manifest = row
            .manifest()
            .ok_or_else(|| anyhow!("plugin '{id}' has an unreadable manifest"))?;
        let grants = self.ensure_permissions_approved(id, &manifest).await?;
        let limits = manifest::effective_limits(&manifest, self.inner.policy)?;
        let component = self.inner.runtime.compile(&row.component)?;
        let linker = self.inner.runtime.linker()?;
        let mut store = self.new_store(&row, &limits, &grants, true, false);
        let plugin = self
            .inner
            .runtime
            .instantiate_adapter(&linker, &mut store, &component)
            .await?;
        Ok(AdapterPrepared {
            store,
            plugin,
            wall_time: Duration::from_millis(limits.wall_time_ms),
        })
    }

    pub async fn adapter_wire_format(&self, id: &str) -> Result<String, PluginFault> {
        self.bump_invocation();
        let _permit = self.inner.semaphore.acquire().await;
        let mut p = self
            .prepare_adapter(id)
            .await
            .map_err(|e| PluginFault::Internal(e.to_string()))?;
        let plugin = p.plugin;
        let rt = self.inner.runtime.clone();
        let guard = rt.arm_deadline(&mut p.store, p.wall_time);
        let res = plugin
            .provider_adapter()
            .call_wire_format(&mut p.store)
            .await
            .map_err(map_call_error);
        self.settle_cancellable(id, &guard, res).await
    }

    pub async fn adapter_build_url(
        &self,
        id: &str,
        provider_json: &str,
        model_json: &str,
    ) -> Result<String, PluginFault> {
        self.bump_invocation();
        let _permit = self.inner.semaphore.acquire().await;
        let mut p = self
            .prepare_adapter(id)
            .await
            .map_err(|e| PluginFault::Internal(e.to_string()))?;
        let plugin = p.plugin;
        let rt = self.inner.runtime.clone();
        let guard = rt.arm_deadline(&mut p.store, p.wall_time);
        let res = plugin
            .provider_adapter()
            .call_build_url(&mut p.store, provider_json, model_json)
            .await
            .map_err(map_call_error)
            .and_then(map_adapter_result);
        self.settle_cancellable(id, &guard, res).await
    }

    pub async fn adapter_apply_auth(
        &self,
        id: &str,
        provider_json: &str,
        credential: &str,
    ) -> Result<String, PluginFault> {
        self.bump_invocation();
        let _permit = self.inner.semaphore.acquire().await;
        let mut p = self
            .prepare_adapter(id)
            .await
            .map_err(|e| PluginFault::Internal(e.to_string()))?;
        let plugin = p.plugin;
        let rt = self.inner.runtime.clone();
        let guard = rt.arm_deadline(&mut p.store, p.wall_time);
        let res = plugin
            .provider_adapter()
            .call_apply_auth(&mut p.store, provider_json, credential)
            .await
            .map_err(map_call_error)
            .and_then(map_adapter_result);
        self.settle_cancellable(id, &guard, res).await
    }

    pub async fn adapter_build_body(
        &self,
        id: &str,
        request_json: &str,
        provider_json: &str,
        model_json: &str,
    ) -> Result<String, PluginFault> {
        self.bump_invocation();
        let _permit = self.inner.semaphore.acquire().await;
        let mut p = self
            .prepare_adapter(id)
            .await
            .map_err(|e| PluginFault::Internal(e.to_string()))?;
        let plugin = p.plugin;
        let rt = self.inner.runtime.clone();
        let guard = rt.arm_deadline(&mut p.store, p.wall_time);
        let res = plugin
            .provider_adapter()
            .call_build_body(&mut p.store, request_json, provider_json, model_json)
            .await
            .map_err(map_call_error)
            .and_then(map_adapter_result);
        self.settle_cancellable(id, &guard, res).await
    }

    pub async fn adapter_classify_error(
        &self,
        id: &str,
        status: u16,
        body: &str,
        headers_json: &str,
    ) -> Result<String, PluginFault> {
        self.bump_invocation();
        let _permit = self.inner.semaphore.acquire().await;
        let mut p = self
            .prepare_adapter(id)
            .await
            .map_err(|e| PluginFault::Internal(e.to_string()))?;
        let plugin = p.plugin;
        let rt = self.inner.runtime.clone();
        let guard = rt.arm_deadline(&mut p.store, p.wall_time);
        let res = plugin
            .provider_adapter()
            .call_classify_error(&mut p.store, status, body, headers_json)
            .await
            .map_err(map_call_error)
            .and_then(map_adapter_result);
        self.settle_cancellable(id, &guard, res).await
    }

    pub async fn adapter_parse_stream_chunk(
        &self,
        id: &str,
        data: &str,
    ) -> Result<String, PluginFault> {
        self.bump_invocation();
        let _permit = self.inner.semaphore.acquire().await;
        let mut p = self
            .prepare_adapter(id)
            .await
            .map_err(|e| PluginFault::Internal(e.to_string()))?;
        let plugin = p.plugin;
        let rt = self.inner.runtime.clone();
        let guard = rt.arm_deadline(&mut p.store, p.wall_time);
        let res = plugin
            .provider_adapter()
            .call_parse_stream_chunk(&mut p.store, data)
            .await
            .map_err(map_call_error)
            .and_then(map_adapter_result);
        self.settle_cancellable(id, &guard, res).await
    }

    pub async fn adapter_parse_full_response(
        &self,
        id: &str,
        body_json: &str,
    ) -> Result<String, PluginFault> {
        self.bump_invocation();
        let _permit = self.inner.semaphore.acquire().await;
        let mut p = self
            .prepare_adapter(id)
            .await
            .map_err(|e| PluginFault::Internal(e.to_string()))?;
        let plugin = p.plugin;
        let rt = self.inner.runtime.clone();
        let guard = rt.arm_deadline(&mut p.store, p.wall_time);
        let res = plugin
            .provider_adapter()
            .call_parse_full_response(&mut p.store, body_json)
            .await
            .map_err(map_call_error)
            .and_then(map_adapter_result);
        self.settle_cancellable(id, &guard, res).await
    }

    /// Record a successful invocation, closing the breaker.
    async fn record_success(&self, id: &str) {
        let _ = store::clear_plugin_failures(&self.inner.pool, id).await;
    }

    /// Record a fault and trip the breaker when the threshold is reached (§15).
    async fn record_fault(&self, id: &str, fault: &PluginFault) {
        use std::sync::atomic::Ordering::Relaxed;
        self.inner.faults.fetch_add(1, Relaxed);
        if matches!(fault, PluginFault::Timeout) {
            self.inner.timeouts.fetch_add(1, Relaxed);
        }
        if !fault.counts_against_circuit() {
            return;
        }
        let _ = store::record_plugin_failure(
            &self.inner.pool,
            id,
            CIRCUIT_FAULT_THRESHOLD,
            CIRCUIT_OPEN_SECS,
            fault.code(),
        )
        .await;
    }

    fn bump_invocation(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        self.inner.invocations.fetch_add(1, Relaxed);
    }

    // -----------------------------------------------------------------------
    // Capability invocations
    // -----------------------------------------------------------------------

    /// CredentialStrategy::resolve (§6.1). Returns the opaque lease only; the
    /// secret never crosses back to core from a plugin in this path.
    pub async fn credential_resolve(
        &self,
        id: &str,
        provider_id: &str,
        account_id: &str,
        account_label: &str,
    ) -> Result<wit::types::CredentialLease, PluginFault> {
        self.bump_invocation();
        let _permit = self.inner.semaphore.acquire().await;
        let mut p = self
            .prepare(id, true)
            .await
            .map_err(|e| PluginFault::Internal(e.to_string()))?;
        let plugin = p.plugin;
        let rt = self.inner.runtime.clone();
        let _guard = rt.arm_deadline(&mut p.store, p.wall_time);
        let res = plugin
            .credential_strategy()
            .call_resolve(&mut p.store, provider_id, account_id, account_label)
            .await
            .map_err(map_call_error)
            .and_then(map_plugin_result);
        self.settle(id, res).await
    }

    /// ModelSource::discover (§6.2).
    pub async fn model_discover(
        &self,
        id: &str,
        provider_id: &str,
        base_url: &str,
        models_path: &str,
    ) -> Result<Vec<wit::types::DiscoveredModel>, PluginFault> {
        self.bump_invocation();
        let _permit = self.inner.semaphore.acquire().await;
        let mut p = self
            .prepare(id, true)
            .await
            .map_err(|e| PluginFault::Internal(e.to_string()))?;
        let plugin = p.plugin;
        let rt = self.inner.runtime.clone();
        let _guard = rt.arm_deadline(&mut p.store, Duration::from_secs(30));
        let res = plugin
            .model_source()
            .call_discover(&mut p.store, provider_id, base_url, models_path)
            .await
            .map_err(map_call_error)
            .and_then(map_plugin_result);
        self.settle(id, res).await
    }

    /// HealthProbe::probe (§6.5).
    pub async fn health_probe(
        &self,
        id: &str,
        provider_id: &str,
        account_id: &str,
    ) -> Result<wit::types::HealthObservation, PluginFault> {
        self.bump_invocation();
        let _permit = self.inner.semaphore.acquire().await;
        let mut p = self
            .prepare(id, true)
            .await
            .map_err(|e| PluginFault::Internal(e.to_string()))?;
        let plugin = p.plugin;
        let rt = self.inner.runtime.clone();
        let _guard = rt.arm_deadline(&mut p.store, Duration::from_secs(10));
        let res = plugin
            .health_probe()
            .call_probe(&mut p.store, provider_id, account_id)
            .await
            .map_err(map_call_error)
            .and_then(map_plugin_result);
        self.settle(id, res).await
    }

    /// RoutingFacts::facts (§6.4). `request_json` must carry only request/config
    /// facts core already knows. `cancelled` is polled while the guest runs; if
    /// the client disconnects the guest is epoch-interrupted and the outcome is
    /// reported as [`PluginFault::Cancelled`], never a fault (§7.2).
    pub async fn routing_facts_cancellable(
        &self,
        id: &str,
        request_json: &str,
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<Vec<wit::types::RoutingFact>, PluginFault> {
        self.bump_invocation();
        let _permit = self.inner.semaphore.acquire().await;
        let mut p = self
            .prepare(id, false)
            .await
            .map_err(|e| PluginFault::Internal(e.to_string()))?;
        let plugin = p.plugin;
        let rt = self.inner.runtime.clone();
        let guard = rt.arm_deadline(&mut p.store, Duration::from_millis(25));
        let watchdog = spawn_cancel_watchdog(guard.cancelled.clone(), cancelled);
        let res = plugin
            .routing_facts()
            .call_facts(&mut p.store, request_json)
            .await
            .map_err(map_call_error)
            .and_then(map_plugin_result);
        watchdog.abort();
        self.settle_cancellable(id, &guard, res).await
    }

    /// RoutingFacts::facts (§6.4). `request_json` must carry only request/config
    /// facts core already knows.
    pub async fn routing_facts(
        &self,
        id: &str,
        request_json: &str,
    ) -> Result<Vec<wit::types::RoutingFact>, PluginFault> {
        self.bump_invocation();
        let _permit = self.inner.semaphore.acquire().await;
        let mut p = self
            .prepare(id, false)
            .await
            .map_err(|e| PluginFault::Internal(e.to_string()))?;
        let plugin = p.plugin;
        let rt = self.inner.runtime.clone();
        let _guard = rt.arm_deadline(&mut p.store, Duration::from_millis(25));
        let res = plugin
            .routing_facts()
            .call_facts(&mut p.store, request_json)
            .await
            .map_err(map_call_error)
            .and_then(map_plugin_result);
        self.settle(id, res).await
    }

    /// Read-only hook: on_request_normalized (§6.6).
    pub async fn hook_request_normalized(
        &self,
        id: &str,
        request_json: &str,
    ) -> Result<(), PluginFault> {
        self.bump_invocation();
        let _permit = self.inner.semaphore.acquire().await;
        let mut p = self
            .prepare(id, true)
            .await
            .map_err(|e| PluginFault::Internal(e.to_string()))?;
        let plugin = p.plugin;
        let rt = self.inner.runtime.clone();
        let _guard = rt.arm_deadline(&mut p.store, Duration::from_millis(25));
        let res = plugin
            .hooks()
            .call_on_request_normalized(&mut p.store, request_json)
            .await
            .map_err(map_call_error)
            .and_then(map_plugin_result);
        self.settle(id, res).await
    }

    /// Read-only hook: on_target_candidate (§6.6).
    pub async fn hook_target_candidate(
        &self,
        id: &str,
        target_json: &str,
    ) -> Result<(), PluginFault> {
        self.bump_invocation();
        let _permit = self.inner.semaphore.acquire().await;
        let mut p = self
            .prepare(id, true)
            .await
            .map_err(|e| PluginFault::Internal(e.to_string()))?;
        let plugin = p.plugin;
        let rt = self.inner.runtime.clone();
        let _guard = rt.arm_deadline(&mut p.store, Duration::from_millis(25));
        let res = plugin
            .hooks()
            .call_on_target_candidate(&mut p.store, target_json)
            .await
            .map_err(map_call_error)
            .and_then(map_plugin_result);
        self.settle(id, res).await
    }

    /// Fire-and-forget hook: on_usage_finalized (§6.6). Runs off the request
    /// path; the caller must never await it inline.
    pub async fn hook_usage_finalized(
        &self,
        id: &str,
        usage_json: &str,
    ) -> Result<(), PluginFault> {
        self.bump_invocation();
        let _permit = self.inner.semaphore.acquire().await;
        let mut p = self
            .prepare(id, true)
            .await
            .map_err(|e| PluginFault::Internal(e.to_string()))?;
        let plugin = p.plugin;
        let rt = self.inner.runtime.clone();
        let _guard = rt.arm_deadline(&mut p.store, p.wall_time);
        let res = plugin
            .hooks()
            .call_on_usage_finalized(&mut p.store, usage_json)
            .await
            .map_err(map_call_error)
            .and_then(map_plugin_result);
        self.settle(id, res).await
    }

    /// Validate an installed plugin by instantiating it (§11 self-check).
    pub async fn validate(&self, id: &str) -> Result<Vec<Provided>> {
        let row = self
            .get(id)
            .await?
            .ok_or_else(|| anyhow!("plugin '{id}' is not installed"))?;
        let manifest = row
            .manifest()
            .ok_or_else(|| anyhow!("plugin '{id}' has an unreadable manifest"))?;
        let limits = manifest::effective_limits(&manifest, self.inner.policy)?;
        let component = self.inner.runtime.compile(&row.component)?;
        let linker = self.inner.runtime.linker()?;
        // Validation proves linking with no runtime authority granted.
        let mut store = self.new_store(&row, &limits, &[], false, false);
        let _ = self
            .inner
            .runtime
            .instantiate(&linker, &mut store, &component)
            .await?;
        Ok(manifest.provides.provided())
    }

    /// Resolve a `plugin:<id>/<capability>` reference to an enabled plugin that
    /// provides it. `None` means the binding is unsatisfied (fail closed, §6.0).
    pub async fn resolve_binding(&self, reference: &str, capability: Capability) -> Option<String> {
        let r = super::types::PluginRef::parse(reference)?;
        if self.provides(&r.plugin_id, capability, &r.capability).await
            && self.is_usable(&r.plugin_id).await
        {
            Some(r.plugin_id)
        } else {
            None
        }
    }

    async fn settle<T>(&self, id: &str, res: Result<T, PluginFault>) -> Result<T, PluginFault> {
        match res {
            Ok(v) => {
                self.record_success(id).await;
                Ok(v)
            }
            Err(fault) => {
                self.record_fault(id, &fault).await;
                Err(fault)
            }
        }
    }

    /// As [`settle`], but a cancellation is never counted as a fault (§7.2):
    /// when the client disconnects the guest is epoch-interrupted, and that
    /// termination must not move the plugin toward an open circuit.
    async fn settle_cancellable<T>(
        &self,
        id: &str,
        guard: &DeadlineGuard,
        res: Result<T, PluginFault>,
    ) -> Result<T, PluginFault> {
        match res {
            Ok(v) => {
                self.record_success(id).await;
                Ok(v)
            }
            Err(fault) => {
                if guard.is_cancelled() {
                    // Client-driven cancellation: recorded as a cancellation, not
                    // a plugin fault (AC: a disconnect must not count as a fault).
                    self.inner
                        .cancellations
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Err(PluginFault::Cancelled);
                }
                self.record_fault(id, &fault).await;
                Err(fault)
            }
        }
    }
}

/// Poll an external cancellation flag while a guest call runs and, once set,
/// flip the guard's cancelled flag. The guard's epoch ticker then interrupts the
/// guest on its next tick (§7.2). Returns the watchdog task to abort after the
/// call completes.
fn spawn_cancel_watchdog(
    guard_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    external: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if external.load(std::sync::atomic::Ordering::SeqCst) {
                guard_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
}

struct Prepared {
    store: wasmtime::Store<HostCtx>,
    plugin: bindings::Plugin,
    wall_time: Duration,
}

struct AuthPrepared {
    store: wasmtime::Store<HostCtx>,
    plugin: crate::plugins::runtime::auth_bindings::PluginAuth,
    wall_time: Duration,
}

struct AdapterPrepared {
    store: wasmtime::Store<HostCtx>,
    plugin: crate::plugins::runtime::adapter_bindings::PluginAdapter,
    wall_time: Duration,
}

/// Map a `wasmtime::Result` error from a guest call into a [`PluginFault`].
fn map_call_error(e: wasmtime::Error) -> PluginFault {
    let msg = e.to_string();
    if msg.contains("epoch") || msg.contains("interrupt") || msg.contains("deadline") {
        PluginFault::Timeout
    } else {
        PluginFault::Trap(msg)
    }
}

/// Map the guest's `Result<T, PluginError>` into a [`PluginFault`].
fn map_plugin_result<T>(r: Result<T, wit::types::PluginError>) -> Result<T, PluginFault> {
    r.map_err(|e| PluginFault::PluginError {
        code: e.code,
        message: e.message,
        retryable: e.retryable,
    })
}

/// Like [`map_plugin_result`] but for the separately-bound auth world.
fn map_auth_result<T>(
    result: Result<T, crate::plugins::runtime::auth_bindings::kinetix::plugin::types::PluginError>,
) -> Result<T, PluginFault> {
    result.map_err(|e| PluginFault::PluginError {
        code: e.code,
        message: e.message,
        retryable: e.retryable,
    })
}

/// Like [`map_plugin_result`] but for the separately-bound adapter world, whose
/// generated `PluginError` type is distinct from the `plugin` world's.
fn map_adapter_result<T>(
    r: Result<T, crate::plugins::runtime::adapter_bindings::kinetix::plugin::types::PluginError>,
) -> Result<T, PluginFault> {
    r.map_err(|e| PluginFault::PluginError {
        code: e.code,
        message: e.message,
        retryable: e.retryable,
    })
}

/// Host-side counters surfaced by the admin metrics endpoint (§18).
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct PluginCounters {
    pub invocations: u64,
    pub faults: u64,
    pub timeouts: u64,
    pub cancellations: u64,
    pub http_requests: u64,
}

/// The outcome of a successful install.
#[derive(Debug, Clone)]
pub struct InstallOutcome {
    pub id: String,
    pub version: String,
    pub package_sha256: String,
    pub signature: SignatureStatus,
    pub provides: Vec<Provided>,
}

/// Turn a validated manifest into the all-or-nothing permission grant set (§20).
pub fn permission_grants(manifest: &Manifest) -> Vec<PermissionGrant> {
    let mut grants = Vec::new();
    if !manifest.permissions.network_hosts.is_empty() {
        grants.push(PermissionGrant {
            permission: "network_hosts".into(),
            value_json: serde_json::to_string(&manifest.permissions.network_hosts)
                .unwrap_or_else(|_| "[]".into()),
        });
    }
    if !manifest.permissions.credential_scopes.is_empty() {
        grants.push(PermissionGrant {
            permission: "credential_scopes".into(),
            value_json: serde_json::to_string(&manifest.permissions.credential_scopes)
                .unwrap_or_else(|_| "[]".into()),
        });
    }
    if manifest.permissions.credential_read {
        grants.push(PermissionGrant {
            permission: "credential_read".into(),
            value_json: "true".into(),
        });
    }
    grants
}

/// The set of capabilities an enabled plugin provides, for the dashboard.
pub fn manifest_summary(row: &PluginRow) -> serde_json::Value {
    let manifest = row.manifest();
    serde_json::json!({
        "id": row.id,
        "name": manifest.as_ref().map(|m| m.name.clone()).unwrap_or_else(|| row.id.clone()),
        "version": row.version,
        "plugin_api_major": row.plugin_api_major,
        "sha256": row.package_sha256,
        "signature": row.signature,
        "status": row.status().as_str(),
        "provides": manifest.as_ref().map(|m| m.provides.provided()).unwrap_or_default(),
        "integrations": manifest.as_ref().map(|m| m.integrations.clone()).unwrap_or_default(),
        "ui": manifest.as_ref().map(|m| m.ui.clone()).unwrap_or_default(),
        "permissions": manifest.as_ref().map(|m| m.permissions.clone()).unwrap_or_default(),
        "limits": manifest.as_ref().map(|m| m.limits.clone()).unwrap_or_default(),
    })
}

/// Package-level helper used by the CLI and admin API.
pub fn read_package(path: &std::path::Path) -> Result<Package> {
    package::read_package_file(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn backing_rejects_cross_provider_account_lookup() {
        let dir = std::env::temp_dir().join(format!(
            "kinetix-plugin-credential-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}?mode=rwc", dir.join("t.db").display());
        let pool = crate::db::connect(&url).await.unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let crypto = Arc::new(Crypto::new(&[11u8; 32]));

        fn new_provider(name: &str) -> crate::db::NewProvider<'_> {
            crate::db::NewProvider {
                name,
                base_url: "https://example.com",
                wire_format: crate::types::WireFormat::Openai,
                auth_scheme: crate::types::AuthScheme::Bearer,
                custom_header_name: None,
                custom_param_name: None,
                extra_headers: serde_json::json!({}),
                timeout_ms: 30_000,
                capability_mode: "permissive",
                models_path: None,
                rate_limit_rules: serde_json::json!({}),
                follow_redirects: false,
                credential_hosts: "",
                allow_insecure_tls: false,
                wire_plugin: "",
                credential_plugin: "",
                model_source_plugin: "",
            }
        }
        let provider_a = crate::db::insert_provider(&pool, &new_provider("A"))
            .await
            .unwrap();
        let provider_b = crate::db::insert_provider(&pool, &new_provider("B"))
            .await
            .unwrap();
        let secret_enc = crypto.encrypt("provider-b-secret").unwrap();
        let account_id = crate::db::insert_account(
            &pool,
            &provider_b,
            "B account",
            &secret_enc,
            "****",
            1,
            1,
            None,
            "unknown",
        )
        .await
        .unwrap();

        let backing = Backing { pool, crypto };
        let err = backing
            .resolve_secret("dev.example.plugin", &provider_a, &account_id)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("does not belong"), "{err}");
    }

    #[test]
    fn permission_grants_are_all_or_nothing() {
        let m: Manifest = toml::from_str(
            r#"
manifest_version = 1
id = "x"
name = "X"
version = "1"
plugin_api = "1"
[provides]
model_sources = ["m"]
[permissions]
network_hosts = ["a.example"]
credential_scopes = ["provider:p"]
credential_read = true
"#,
        )
        .unwrap();
        let grants = permission_grants(&m);
        assert_eq!(grants.len(), 3);
        assert!(grants.iter().any(|g| g.permission == "credential_read"));
    }
}
