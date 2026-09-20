//! End-to-end plugin lifecycle tests against a real database and Wasmtime host.
//!
//! These exercise the acceptance criteria that do not require a fully-featured
//! guest component: hash verification, API-compatibility rejection,
//! installed-disabled semantics, fail-closed enablement for an incompatible
//! component, all-or-nothing permissions, and removal (which cascades state).

use std::sync::Arc;

use kinetix::crypto::Crypto;
use kinetix::db::{self, Pool};
use kinetix::plugins::{Capability, HostPolicy, PluginManager};

const GOOD_MANIFEST: &str = r#"
manifest_version = 1
id = "dev.example.foo"
name = "Foo Provider Integration"
version = "1.2.0"
plugin_api = "1"

[provides]
model_sources = ["foo-models"]
routing_facts = ["foo-facts"]

[permissions]
network_hosts = ["api.foo.example"]
credential_scopes = ["provider:foo"]

[limits]
memory = "64MiB"
storage = "2MiB"
"#;

/// A minimal valid component (magic + component-model version, no sections)
/// that compiles but does not implement the plugin world, so it can be
/// installed but not enabled.
const EMPTY_COMPONENT: &[u8] = b"\0asm\x0d\0\x01\0";

async fn manager() -> (PluginManager, Pool) {
    let dir = std::env::temp_dir().join(format!("kinetix-plugin-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let url = format!("sqlite://{}?mode=rwc", dir.join("t.db").display());
    let pool = db::connect(&url).await.unwrap();
    db::migrate(&pool).await.unwrap();
    let crypto = Arc::new(Crypto::new(&[9u8; 32]));
    let http = reqwest::Client::new();
    let manager = PluginManager::new(pool.clone(), crypto, http, HostPolicy::default()).unwrap();
    (manager, pool)
}

/// Build a `.kxp` archive in memory.
fn build_kxp(manifest: &str, wasm: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, data) in [
        ("plugin.toml", manifest.as_bytes()),
        ("plugin.wasm", wasm),
        ("README.md", b"# Foo"),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, name, data).unwrap();
    }
    builder.into_inner().unwrap()
}

#[tokio::test]
async fn install_is_disabled_and_records_provenance() {
    let (m, pool) = manager().await;
    let kxp = build_kxp(GOOD_MANIFEST, EMPTY_COMPONENT);
    let outcome = m.install(&kxp, None, &[], false).await.unwrap();
    assert_eq!(outcome.id, "dev.example.foo");
    assert_eq!(outcome.version, "1.2.0");
    assert_eq!(outcome.provides.len(), 2);

    // Installed, but disabled (install and enable are separate operations).
    let row = m.get("dev.example.foo").await.unwrap().unwrap();
    assert_eq!(row.enabled, 0);
    assert_eq!(row.package_sha256.len(), 64);

    // Installation records requested permissions in the manifest but grants
    // no runtime authority until the operator explicitly approves them (§20).
    let perms = kinetix::plugins::store::permissions(&pool, "dev.example.foo")
        .await
        .unwrap();
    assert!(perms.is_empty());
}

#[tokio::test]
async fn hash_mismatch_is_rejected() {
    let (m, _pool) = manager().await;
    let kxp = build_kxp(GOOD_MANIFEST, EMPTY_COMPONENT);
    let err = m
        .install(&kxp, Some(&"0".repeat(64)), &[], false)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("hash mismatch"), "{err}");
}

#[tokio::test]
async fn enable_requires_explicit_permission_approval() {
    let (m, _pool) = manager().await;
    let kxp = build_kxp(GOOD_MANIFEST, EMPTY_COMPONENT);
    m.install(&kxp, None, &[], false).await.unwrap();

    let err = m.enable("dev.example.foo").await.unwrap_err();
    assert!(
        err.to_string().contains("permissions are not approved"),
        "{err}"
    );
    assert_eq!(m.get("dev.example.foo").await.unwrap().unwrap().enabled, 0);
}

#[tokio::test]
async fn upgrade_disables_plugin_and_clears_previous_approvals() {
    let (m, pool) = manager().await;
    let kxp = build_kxp(GOOD_MANIFEST, EMPTY_COMPONENT);
    m.install(&kxp, None, &[], false).await.unwrap();
    m.approve_permissions("dev.example.foo").await.unwrap();
    kinetix::plugins::store::set_enabled(&pool, "dev.example.foo", true)
        .await
        .unwrap();

    let upgraded = GOOD_MANIFEST.replace("version = \"1.2.0\"", "version = \"1.3.0\"");
    let upgraded_kxp = build_kxp(&upgraded, EMPTY_COMPONENT);
    m.install(&upgraded_kxp, None, &[], false).await.unwrap();

    let row = m.get("dev.example.foo").await.unwrap().unwrap();
    assert_eq!(row.version, "1.3.0");
    assert_eq!(row.enabled, 0);
    assert!(
        kinetix::plugins::store::permissions(&pool, "dev.example.foo")
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn revoking_a_permission_disables_the_plugin() {
    let (m, pool) = manager().await;
    let kxp = build_kxp(GOOD_MANIFEST, EMPTY_COMPONENT);
    m.install(&kxp, None, &[], false).await.unwrap();
    m.approve_permissions("dev.example.foo").await.unwrap();
    kinetix::plugins::store::set_enabled(&pool, "dev.example.foo", true)
        .await
        .unwrap();

    m.revoke_permission("dev.example.foo", "network_hosts")
        .await
        .unwrap();

    assert_eq!(m.get("dev.example.foo").await.unwrap().unwrap().enabled, 0);
    let perms = kinetix::plugins::store::permissions(&pool, "dev.example.foo")
        .await
        .unwrap();
    assert!(!perms.iter().any(|p| p.permission == "network_hosts"));
}

#[tokio::test]
async fn incompatible_api_is_rejected_before_enable() {
    let (m, _pool) = manager().await;
    let bad = GOOD_MANIFEST.replace("plugin_api = \"1\"", "plugin_api = \"2\"");
    let kxp = build_kxp(&bad, EMPTY_COMPONENT);
    let err = m.install(&kxp, None, &[], false).await.unwrap_err();
    assert!(err.to_string().contains("incompatible plugin_api"), "{err}");
}

#[tokio::test]
async fn undeclared_capabilities_are_rejected() {
    let (m, _pool) = manager().await;
    let bad = GOOD_MANIFEST
        .replace("model_sources = [\"foo-models\"]", "")
        .replace("routing_facts = [\"foo-facts\"]", "");
    let kxp = build_kxp(&bad, EMPTY_COMPONENT);
    let err = m.install(&kxp, None, &[], false).await.unwrap_err();
    assert!(
        err.to_string().contains("provides no capabilities"),
        "{err}"
    );
}

#[tokio::test]
async fn component_not_implementing_the_world_fails_to_enable() {
    let (m, _pool) = manager().await;
    let kxp = build_kxp(GOOD_MANIFEST, EMPTY_COMPONENT);
    m.install(&kxp, None, &[], false).await.unwrap();
    m.approve_permissions("dev.example.foo").await.unwrap();
    // Enable instantiates the component; an empty component does not satisfy the
    // plugin world, so enablement fails closed (AC#4).
    let err = m.enable("dev.example.foo").await.unwrap_err();
    assert!(!err.to_string().is_empty());
    // It stays disabled.
    assert_eq!(m.get("dev.example.foo").await.unwrap().unwrap().enabled, 0);
}

#[tokio::test]
async fn removing_a_plugin_cascades_stored_state() {
    let (m, pool) = manager().await;
    let kxp = build_kxp(GOOD_MANIFEST, EMPTY_COMPONENT);
    m.install(&kxp, None, &[], false).await.unwrap();
    let crypto = Crypto::new(&[9u8; 32]);
    kinetix::plugins::store::kv_put(&pool, &crypto, "dev.example.foo", "lease:h1", b"secret")
        .await
        .unwrap();
    assert!(
        kinetix::plugins::store::kv_bytes(&pool, "dev.example.foo")
            .await
            .unwrap()
            > 0
    );
    m.remove("dev.example.foo").await.unwrap();
    assert!(m.get("dev.example.foo").await.unwrap().is_none());
    // KV rows are gone via ON DELETE CASCADE.
    assert_eq!(
        kinetix::plugins::store::kv_bytes(&pool, "dev.example.foo")
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn a_reference_to_a_disabled_plugin_does_not_resolve() {
    let (m, _pool) = manager().await;
    let kxp = build_kxp(GOOD_MANIFEST, EMPTY_COMPONENT);
    m.install(&kxp, None, &[], false).await.unwrap();
    // Installed-disabled: a config binding must not resolve (fail closed, §6.0).
    let resolved = m
        .resolve_binding("plugin:dev.example.foo/foo-models", Capability::ModelSource)
        .await;
    assert!(resolved.is_none());
}

#[tokio::test]
async fn kv_is_encrypted_and_namespaced_by_plugin() {
    let (m, pool) = manager().await;
    let kxp = build_kxp(GOOD_MANIFEST, EMPTY_COMPONENT);
    m.install(&kxp, None, &[], false).await.unwrap();
    let crypto = Crypto::new(&[9u8; 32]);
    kinetix::plugins::store::kv_put(&pool, &crypto, "dev.example.foo", "k", b"v1")
        .await
        .unwrap();
    // A different plugin id cannot read the first plugin's key.
    assert!(
        kinetix::plugins::store::kv_get(&pool, &crypto, "other.plugin", "k")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        kinetix::plugins::store::kv_get(&pool, &crypto, "dev.example.foo", "k")
            .await
            .unwrap()
            .unwrap(),
        b"v1"
    );
    // Stored ciphertext is not the plaintext.
    let raw: Vec<u8> = sqlx::query_scalar("SELECT value FROM plugin_kv WHERE key='k'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_ne!(raw, b"v1");
}
