//! End-to-end test: install and run a real compiled plugin component.
//!
//! This exercises the full path that unit tests cannot: a genuine `.kxp`
//! package containing a WebAssembly component built from `plugins/`, installed
//! through the manager, enabled (which instantiates it), and invoked through a
//! capability. It proves the WIT host boundary works against a real guest.
//!
//! The test is skipped (not failed) when the plugin package or the toolchain
//! that produces it is unavailable, so it does not break environments without
//! `wasm32-unknown-unknown` / `wasm-tools`.

use std::sync::Arc;

use kinetix::crypto::Crypto;
use kinetix::db::{self, Pool};
use kinetix::plugins::{Capability, HostPolicy, PluginManager};

/// Path to the built `.kxp`, produced by `scripts/build-plugin.sh`.
fn package_path() -> Option<std::path::PathBuf> {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = manifest_dir.join("plugins/antigravity-oauth");
    let entry = std::fs::read_dir(&dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.extension().map(|x| x == "kxp").unwrap_or(false))?;
    Some(entry)
}

async fn manager() -> (PluginManager, Pool) {
    let dir = std::env::temp_dir().join(format!("kinetix-ag-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let url = format!("sqlite://{}?mode=rwc", dir.join("t.db").display());
    let pool = db::connect(&url).await.unwrap();
    db::migrate(&pool).await.unwrap();
    let crypto = Arc::new(Crypto::new(&[7u8; 32]));
    let http = reqwest::Client::new();
    let manager = PluginManager::new(
        pool.clone(),
        crypto,
        http,
        HostPolicy::default(),
        dir.join("plugin-packages"),
    )
    .unwrap();
    (manager, pool)
}

#[tokio::test]
async fn installs_enables_and_instantiates_a_real_component() {
    let Some(path) = package_path() else {
        eprintln!(
            "skipping: build the plugin first (scripts/build-plugin.sh plugins/antigravity-oauth)"
        );
        return;
    };
    let bytes = std::fs::read(&path).unwrap();
    let (m, _pool) = manager().await;

    let outcome = m.install(&bytes, None, &[], false).await.unwrap();
    assert_eq!(outcome.id, "dev.kinetix.antigravity-oauth");
    assert!(
        outcome
            .provides
            .iter()
            .any(|p| p.capability == Capability::CredentialStrategy),
        "plugin should provide a credential strategy"
    );

    // Enable instantiates the component: this is the real proof the guest links
    // against the host's WIT world.
    m.approve_permissions("dev.kinetix.antigravity-oauth")
        .await
        .expect("declared permissions should approve");
    m.enable("dev.kinetix.antigravity-oauth")
        .await
        .expect("a real component should enable against the host world");

    // The binding resolves once enabled (fail-closed before that, §6.0).
    let resolved = m
        .resolve_binding(
            "plugin:dev.kinetix.antigravity-oauth/antigravity-oauth",
            Capability::CredentialStrategy,
        )
        .await;
    assert_eq!(resolved.as_deref(), Some("dev.kinetix.antigravity-oauth"));
}

#[tokio::test]
async fn invokes_a_real_guest_capability_through_the_host_boundary() {
    let Some(path) = package_path() else {
        eprintln!("skipping: plugin package not built");
        return;
    };
    let bytes = std::fs::read(&path).unwrap();
    let (m, _pool) = manager().await;
    m.install(&bytes, None, &[], false).await.unwrap();
    m.approve_permissions("dev.kinetix.antigravity-oauth")
        .await
        .unwrap();
    m.enable("dev.kinetix.antigravity-oauth").await.unwrap();

    // Invoke the real `credential-strategy.resolve` export. With no matching
    // account the guest calls `host-credential.read`, which fails, and the guest
    // returns a *structured* PluginError (not a trap): this proves the guest ran
    // and the host WIT boundary carried typed results both ways.
    let result = m
        .credential_resolve(
            "dev.kinetix.antigravity-oauth",
            "antigravity",
            "acc_missing",
            "missing",
        )
        .await;
    match result {
        Err(fault) => {
            assert_eq!(fault.code(), "credential_expired", "got {fault:?}");
            // A structured plugin error must not be counted as a runtime fault.
            assert!(!fault.counts_against_circuit());
        }
        Ok(lease) => panic!("unexpectedly resolved a lease: {lease:?}"),
    }
}

#[tokio::test]
async fn a_real_guest_reports_usable_after_enable() {
    let Some(path) = package_path() else {
        eprintln!("skipping: plugin package not built");
        return;
    };
    let bytes = std::fs::read(&path).unwrap();
    let (m, _pool) = manager().await;
    m.install(&bytes, None, &[], false).await.unwrap();
    m.approve_permissions("dev.kinetix.antigravity-oauth")
        .await
        .unwrap();
    m.enable("dev.kinetix.antigravity-oauth").await.unwrap();

    // The plugin does not provide health-probe, so the host reports an unknown
    // capability rather than invoking a missing export. `credential_strategy`
    // is provided; asking for health through the credential plugin path is
    // covered by the plugin's own `health` export below.
    let usable = m.is_usable("dev.kinetix.antigravity-oauth").await;
    assert!(usable);
}

/// The second world (`plugin-adapter`, §6.3) is bound from the same component
/// and translates the Antigravity `v1internal` wire format end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapter_world_translates_the_antigravity_wire_format() {
    let Some(path) = package_path() else {
        eprintln!("skipping: plugin package not built");
        return;
    };
    let bytes = std::fs::read(&path).unwrap();
    let (m, _pool) = manager().await;
    m.install(&bytes, None, &[], false).await.unwrap();
    m.approve_permissions("dev.kinetix.antigravity-oauth")
        .await
        .unwrap();
    m.enable("dev.kinetix.antigravity-oauth").await.unwrap();
    let id = "dev.kinetix.antigravity-oauth";

    let wf = m
        .adapter_wire_format(id)
        .await
        .expect("adapter world binds");
    assert_eq!(wf, "antigravity");

    let provider =
        r#"{"base_url":"https://daily-cloudcode-pa.googleapis.com","extra_headers":"{}"}"#;
    let model = r#"{"upstream_id":"gemini-3-flash"}"#;

    let url = m.adapter_build_url(id, provider, model).await.unwrap();
    assert!(
        url.ends_with("/v1internal:streamGenerateContent?alt=sse"),
        "got {url}"
    );

    let headers = m.adapter_apply_auth(id, provider, "tok123").await.unwrap();
    assert!(headers.contains("Bearer tok123"), "got {headers}");
    assert!(headers.contains("antigravity/ide/"));

    let request = r#"{"requested_model":"gemini-3-flash","system":["be nice"],"messages":[{"role":"user","parts":[{"type":"text","text":"hi"}]}],"tools":[{"name":"my-tool!","description":"d","parameters":{"type":"object"}}],"stream":true}"#;
    let body = m
        .adapter_build_body(id, request, provider, model)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["model"], "gemini-3-flash");
    assert_eq!(v["userAgent"], "antigravity");
    assert_eq!(v["request"]["contents"][0]["parts"][0]["text"], "hi");
    assert_eq!(v["request"]["contents"][0]["role"], "user");
    assert_eq!(
        v["request"]["systemInstruction"]["parts"][0]["text"],
        "be nice"
    );
    // Function names are sanitized to the Gemini rule.
    assert_eq!(
        v["request"]["tools"][0]["functionDeclarations"][0]["name"],
        "my-tool_"
    );

    // A real Antigravity SSE chunk parses to canonical events.
    let chunk = r#"{"response":{"responseId":"resp_1","candidates":[{"content":{"parts":[{"text":"hello"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":2}}}"#;
    let events = m.adapter_parse_stream_chunk(id, chunk).await.unwrap();
    let ev: serde_json::Value = serde_json::from_str(&events).unwrap();
    let arr = ev.as_array().unwrap();
    assert!(arr
        .iter()
        .any(|e| e["type"] == "text_delta" && e["text"] == "hello"));
    assert!(arr
        .iter()
        .any(|e| e["type"] == "finish" && e["reason"] == "stop"));
    assert!(arr
        .iter()
        .any(|e| e["type"] == "usage" && e["input"] == 5 && e["output"] == 2));
    assert!(arr
        .iter()
        .any(|e| e["type"] == "start" && e["upstream_request_id"] == "resp_1"));
}

/// Error classification maps Antigravity's 429 + reset hint onto the host's
/// typed failure vocabulary.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapter_classifies_quota_exhaustion() {
    let Some(path) = package_path() else {
        eprintln!("skipping: plugin package not built");
        return;
    };
    let bytes = std::fs::read(&path).unwrap();
    let (m, _pool) = manager().await;
    m.install(&bytes, None, &[], false).await.unwrap();
    m.approve_permissions("dev.kinetix.antigravity-oauth")
        .await
        .unwrap();
    m.enable("dev.kinetix.antigravity-oauth").await.unwrap();
    let id = "dev.kinetix.antigravity-oauth";

    let body = r#"{"error":{"message":"Quota exhausted. Your quota will reset after 2h7m23s"}}"#;
    let ev = m.adapter_classify_error(id, 429, body, "{}").await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&ev).unwrap();
    assert_eq!(v["kind"], "quota_exhausted");
    assert_eq!(v["retry_after_secs"], 2 * 3600 + 7 * 60 + 23);
}
