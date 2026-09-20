//! Host-managed plugin persistence (§10).
//!
//! Plugins never touch SQL directly; every access goes through these typed
//! helpers. Plugin KV is encrypted at rest using the host crypto with a
//! separate key label derived from the master key (§10, §8.3).

use anyhow::{Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Row};

use crate::crypto::Crypto;
use crate::db::Pool;

use super::manifest::ValidatedManifest;
use super::types::{CircuitState, Manifest, PluginStatus};

/// A stored plugin row.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct PluginRow {
    pub id: String,
    pub version: String,
    pub plugin_api_major: i64,
    pub package_sha256: String,
    pub enabled: i64,
    pub signature: String,
    pub manifest_json: String,
    #[serde(skip)]
    pub component: Vec<u8>,
    pub installed_at: String,
    pub updated_at: String,
}

impl PluginRow {
    pub fn status(&self) -> PluginStatus {
        if self.enabled != 0 {
            PluginStatus::Enabled
        } else {
            PluginStatus::Disabled
        }
    }

    pub fn manifest(&self) -> Option<Manifest> {
        serde_json::from_str(&self.manifest_json).ok()
    }
}

/// A stored permission grant.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct PermissionRow {
    pub plugin_id: String,
    pub permission: String,
    pub value_json: String,
    pub approved_at: String,
}

/// Immutable package provenance retained separately from active plugin state.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct PackageRow {
    pub plugin_id: String,
    pub version: String,
    pub package_sha256: String,
    pub package_path: String,
    pub signature: String,
    pub source: String,
    pub installed_at: String,
}

/// A stored circuit-breaker row.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct RuntimeStateRow {
    pub plugin_id: String,
    pub circuit_state: String,
    pub consecutive_failures: i64,
    pub circuit_open_until: Option<String>,
    pub last_error_code: Option<String>,
    pub last_error_at: Option<String>,
}

impl RuntimeStateRow {
    pub fn circuit(&self) -> CircuitState {
        CircuitState::parse(&self.circuit_state)
    }
}

/// Insert or replace an installed plugin in a disabled, unapproved state.
/// Every install or upgrade requires explicit permission approval before enable.
pub async fn upsert_plugin(
    pool: &Pool,
    validated: &ValidatedManifest,
    sha256: &str,
    component: &[u8],
    signature: &str,
    package_path: &str,
) -> Result<()> {
    let manifest_json = serde_json::to_string(&validated.manifest)?;
    let api_major = validated.manifest.api_major().unwrap_or(0) as i64;
    let now = crate::db::now_iso();

    let mut tx = pool.begin().await.context("begin plugin upsert")?;

    // Install and upgrade are always installed-disabled. An upgrade must never
    // inherit active authority from the previous component (§11, §20).
    sqlx::query(
        "INSERT INTO plugins
         (id, version, plugin_api_major, package_sha256, enabled, signature,
          manifest_json, component, installed_at, updated_at)
         VALUES (?,?,?,?,0,?,?,?,?,?)
         ON CONFLICT(id) DO UPDATE SET
           version=excluded.version,
           plugin_api_major=excluded.plugin_api_major,
           package_sha256=excluded.package_sha256,
           enabled=0,
           signature=excluded.signature,
           manifest_json=excluded.manifest_json,
           component=excluded.component,
           updated_at=excluded.updated_at",
    )
    .bind(&validated.manifest.id)
    .bind(&validated.manifest.version)
    .bind(api_major)
    .bind(sha256)
    .bind(signature)
    .bind(&manifest_json)
    .bind(component)
    .bind(&now)
    .bind(&now)
    .execute(&mut *tx)
    .await?;

    // Installation and upgrade never approve permissions implicitly. Clear any
    // previous grants so a new component cannot inherit authority.
    sqlx::query("DELETE FROM plugin_permissions WHERE plugin_id = ?")
        .bind(&validated.manifest.id)
        .execute(&mut *tx)
        .await?;

    // Retain immutable provenance independently from the active plugin row.
    // Reinstalling identical bytes is idempotent; older package versions remain.
    sqlx::query(
        "INSERT INTO plugin_packages
         (plugin_id, version, package_sha256, package_path, signature, source, installed_at)
         VALUES (?,?,?,?,?,'local',?)
         ON CONFLICT(plugin_id, package_sha256) DO NOTHING",
    )
    .bind(&validated.manifest.id)
    .bind(&validated.manifest.version)
    .bind(sha256)
    .bind(package_path)
    .bind(signature)
    .bind(&now)
    .execute(&mut *tx)
    .await?;

    // Ensure a runtime-state row exists.
    sqlx::query(
        "INSERT OR IGNORE INTO plugin_runtime_state (plugin_id, circuit_state, consecutive_failures)
         VALUES (?, 'closed', 0)",
    )
    .bind(&validated.manifest.id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionGrant {
    pub permission: String,
    pub value_json: String,
}

pub async fn list_plugins(pool: &Pool) -> Result<Vec<PluginRow>> {
    Ok(
        sqlx::query_as::<_, PluginRow>("SELECT * FROM plugins ORDER BY id")
            .fetch_all(pool)
            .await?,
    )
}

pub async fn get_plugin(pool: &Pool, id: &str) -> Result<Option<PluginRow>> {
    Ok(
        sqlx::query_as::<_, PluginRow>("SELECT * FROM plugins WHERE id = ?")
            .bind(id)
            .fetch_optional(pool)
            .await?,
    )
}

pub async fn list_packages(pool: &Pool, id: &str) -> Result<Vec<PackageRow>> {
    Ok(sqlx::query_as::<_, PackageRow>(
        "SELECT * FROM plugin_packages
         WHERE plugin_id = ?
         ORDER BY installed_at DESC, version DESC",
    )
    .bind(id)
    .fetch_all(pool)
    .await?)
}

pub async fn set_enabled(pool: &Pool, id: &str, enabled: bool) -> Result<()> {
    sqlx::query("UPDATE plugins SET enabled = ?, updated_at = ? WHERE id = ?")
        .bind(if enabled { 1 } else { 0 })
        .bind(crate::db::now_iso())
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_plugin(pool: &Pool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM plugins WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn permissions(pool: &Pool, id: &str) -> Result<Vec<PermissionRow>> {
    Ok(sqlx::query_as::<_, PermissionRow>(
        "SELECT * FROM plugin_permissions WHERE plugin_id = ? ORDER BY permission",
    )
    .bind(id)
    .fetch_all(pool)
    .await?)
}

/// Replace the approved permission set atomically.
pub async fn replace_permissions(pool: &Pool, id: &str, grants: &[PermissionGrant]) -> Result<()> {
    let mut tx = pool
        .begin()
        .await
        .context("begin plugin permission update")?;
    sqlx::query("DELETE FROM plugin_permissions WHERE plugin_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let now = crate::db::now_iso();
    for grant in grants {
        sqlx::query(
            "INSERT INTO plugin_permissions (plugin_id, permission, value_json, approved_at)
             VALUES (?,?,?,?)",
        )
        .bind(id)
        .bind(&grant.permission)
        .bind(&grant.value_json)
        .bind(&now)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Revoke one approved permission grant.
pub async fn revoke_permission(pool: &Pool, id: &str, permission: &str) -> Result<()> {
    sqlx::query("DELETE FROM plugin_permissions WHERE plugin_id = ? AND permission = ?")
        .bind(id)
        .bind(permission)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn runtime_state(pool: &Pool, id: &str) -> Result<Option<RuntimeStateRow>> {
    Ok(sqlx::query_as::<_, RuntimeStateRow>(
        "SELECT * FROM plugin_runtime_state WHERE plugin_id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?)
}

/// Bump the plugin's consecutive-failure counter and open the circuit when the
/// threshold is reached (§15). Returns the new count.
pub async fn record_plugin_failure(
    pool: &Pool,
    id: &str,
    threshold: i64,
    open_secs: i64,
    code: &str,
) -> Result<i64> {
    let now = crate::db::now_iso();
    sqlx::query(
        "UPDATE plugin_runtime_state
         SET consecutive_failures = consecutive_failures + 1,
             last_error_code = ?, last_error_at = ?
         WHERE plugin_id = ?",
    )
    .bind(code)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;
    let n =
        sqlx::query("SELECT consecutive_failures FROM plugin_runtime_state WHERE plugin_id = ?")
            .bind(id)
            .fetch_optional(pool)
            .await?
            .map(|r| r.get::<i64, _>("consecutive_failures"))
            .unwrap_or(0);
    if n >= threshold {
        let until = (chrono::Utc::now() + chrono::Duration::seconds(open_secs)).to_rfc3339();
        sqlx::query(
            "UPDATE plugin_runtime_state SET circuit_state = 'open', circuit_open_until = ? WHERE plugin_id = ?",
        )
        .bind(until)
        .bind(id)
        .execute(pool)
        .await?;
    }
    Ok(n)
}

pub async fn clear_plugin_failures(pool: &Pool, id: &str) -> Result<()> {
    sqlx::query(
        "UPDATE plugin_runtime_state
         SET consecutive_failures = 0, circuit_state = 'closed', circuit_open_until = NULL
         WHERE plugin_id = ?",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn set_circuit(
    pool: &Pool,
    id: &str,
    state: CircuitState,
    open_until: Option<&str>,
) -> Result<()> {
    sqlx::query("UPDATE plugin_runtime_state SET circuit_state = ?, circuit_open_until = ? WHERE plugin_id = ?")
        .bind(state.as_str())
        .bind(open_until)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Plugin KV (encrypted at rest)
// ---------------------------------------------------------------------------

/// Encrypt and store a plugin KV entry.
pub async fn kv_put(
    pool: &Pool,
    crypto: &Crypto,
    plugin_id: &str,
    key: &str,
    value: &[u8],
) -> Result<()> {
    let plaintext = base64::engine::general_purpose::STANDARD.encode(value);
    let enc = crypto.encrypt_kv(&plaintext)?;
    sqlx::query(
        "INSERT INTO plugin_kv (plugin_id, key, value, updated_at) VALUES (?,?,?,?)
         ON CONFLICT(plugin_id, key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
    )
    .bind(plugin_id)
    .bind(key)
    .bind(enc.as_bytes())
    .bind(crate::db::now_iso())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn kv_get(
    pool: &Pool,
    crypto: &Crypto,
    plugin_id: &str,
    key: &str,
) -> Result<Option<Vec<u8>>> {
    let row = sqlx::query("SELECT value FROM plugin_kv WHERE plugin_id = ? AND key = ?")
        .bind(plugin_id)
        .bind(key)
        .fetch_optional(pool)
        .await?;
    let Some(row) = row else { return Ok(None) };
    let enc: Vec<u8> = row.get("value");
    let enc = String::from_utf8(enc).context("plugin KV ciphertext not utf-8")?;
    let plaintext = crypto.decrypt_kv(&enc)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(plaintext.trim())
        .context("plugin KV plaintext not base64")?;
    Ok(Some(bytes))
}

pub async fn kv_delete(pool: &Pool, plugin_id: &str, key: &str) -> Result<()> {
    sqlx::query("DELETE FROM plugin_kv WHERE plugin_id = ? AND key = ?")
        .bind(plugin_id)
        .bind(key)
        .execute(pool)
        .await?;
    Ok(())
}

/// List KV entries whose key begins with `prefix`, newest key order. Used by
/// the host to read cached routing facts on the request path (§6.4) without
/// invoking the guest.
pub async fn kv_list_prefix(
    pool: &Pool,
    crypto: &Crypto,
    plugin_id: &str,
    prefix: &str,
) -> Result<Vec<(String, Vec<u8>)>> {
    let rows = sqlx::query(
        "SELECT key, value FROM plugin_kv WHERE plugin_id = ? AND key LIKE ? ORDER BY key",
    )
    .bind(plugin_id)
    .bind(format!("{prefix}%"))
    .fetch_all(pool)
    .await?;
    let mut out = Vec::new();
    for row in rows {
        let key: String = row.get("key");
        let enc: Vec<u8> = row.get("value");
        let enc = match String::from_utf8(enc) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let plaintext = match crypto.decrypt_kv(&enc) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let bytes = match base64::engine::general_purpose::STANDARD.decode(plaintext.trim()) {
            Ok(b) => b,
            Err(_) => continue,
        };
        out.push((key, bytes));
    }
    Ok(out)
}

/// Total bytes stored for a plugin (for quota enforcement, §14).
pub async fn kv_bytes(pool: &Pool, plugin_id: &str) -> Result<u64> {
    let row = sqlx::query(
        "SELECT COALESCE(SUM(LENGTH(value)), 0) AS n FROM plugin_kv WHERE plugin_id = ?",
    )
    .bind(plugin_id)
    .fetch_one(pool)
    .await?;
    Ok(row.get::<i64, _>("n").max(0) as u64)
}
