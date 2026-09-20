# Plugins

Kinetix features an opt-in, sandboxed WebAssembly plugin system based on the **WebAssembly Component Model** (powered by Wasmtime 48).

Plugins allow operators to extend Kinetix without modifying the core gateway or sacrificing security, memory safety, or routing predictability:

* **Custom Wire Protocols (`wire_plugin`)**: Implement proprietary or non-standard outbound wire protocols (such as Google's internal `v1internal` API) as pure translation libraries, while Kinetix manages HTTP transport and SSE streaming.
* **Dynamic Credential Strategies (`credential_plugin`)**: Handle automated token acquisition and refresh (e.g., OAuth 2.0 refresh-token exchanges, cloud IAM credentials) with host-managed encrypted leases.
* **Routing Facts (`plugin.<id>.<name>`)**: Supply custom typed facts for target predicate evaluation in executable Routes.
* **Account Health Probes**: Perform scheduled background quota and availability health checks.
* **Model Discovery (`model_source_plugin`)**: Interrogate upstream APIs to discover available models.
* **Read-Only Lifecycle Hooks**: Observe request, candidate, and usage events asynchronously on a non-blocking queue.

Native adapters and standard configuration-driven providers remain zero-overhead and completely isolated from installed plugins.

---

## Architecture and Sandbox Model

Plugins execute inside a strictly isolated WebAssembly sandbox with **zero ambient authority**:

```
+-------------------------------------------------------------+
|                        Kinetix Core                         |
|  [Pipeline]   [Router / Predicates]   [Account Pools / DB]   |
+------------------------------+------------------------------+
                               | Typed WIT Seams
                               v
+-------------------------------------------------------------+
|                 Wasmtime Component Sandbox                  |
|  +-----------------------+     +-------------------------+  |
|  |     Plugin World      |     |  Plugin-Adapter World   |  |
|  | - CredentialStrategy  |     | - Pure wire translation |  |
|  | - RoutingFactProvider |     | - No network imports    |  |
|  | - ModelSource         |     | - SSE framing owned by  |  |
|  | - HealthProbe         |     |   Kinetix core host     |  |
|  | - Read-only Hooks     |     +-------------------------+  |
|  +-----------------------+                                  |
|          | (Host-mediated capabilities)                     |
|          v                                                  |
|  [Encrypted Namespaced KV]    [Host HTTP (Approved Hosts)]  |
+-------------------------------------------------------------+
```

### Safety Guarantees

1. **Hardware-Enforced Memory Isolation**: Plugins run in WebAssembly linear memory. They cannot inspect host process memory, execute arbitrary system calls, or access the local filesystem or environment.
2. **Mediated Network Access**: Plugins have no direct socket access. Outbound HTTP requests must pass through the host HTTP capability, strictly filtered against the plugin's approved `network_hosts`. Provider adapters (`plugin-adapter` world) import **no network capabilities at all**.
3. **Encrypted Storage Isolation**: Each plugin receives an isolated logical namespace in SQLite (`plugin_kv`). Values are encrypted with AES-256-GCM using a key derived from `KINETIX_MASTER_KEY` under the context label `kinetix-plugin-kv`.
4. **All-or-Nothing Permissions**: Operators approve the entire declared permission set before a plugin can be enabled. Revoking any grant disables the plugin immediately.
5. **Preemptive Execution Limits**: Execution is preempted by Wasmtime epoch interruption (10 ms ticks, default 10 s deadline for evaluations; 30 s for adapter stream setup). Memory is capped at 64 MiB per store.
6. **Per-Plugin Circuit Breaker**: Persisted in SQLite (`plugin_runtime_state`). Consecutive unhandled traps or errors trip the circuit to `open`, causing bound providers to fail closed cleanly without risking proxy stability.
7. **Client Cancellation Neutrality**: Client disconnects trigger epoch interruption and are recorded as cancellations, never penalizing the plugin's circuit-breaker state.

---

## Capability Seams

Plugins interact with Kinetix solely through typed interfaces defined in `wit/kinetix-plugin.wit` (package `kinetix:plugin@1.0.0`):

### 1. Provider Adapter (`wire_plugin`)
* **WIT World**: `plugin-adapter`
* **Exported Functions**: `wire-format`, `build-url`, `apply-auth`, `build-body`, `classify-error`, `parse-stream-chunk`, `parse-full-response`
* **Contract**: The adapter is a *pure translation library*. It converts canonical Kinetix requests (`src/types.rs`) into upstream request bodies, and converts upstream response chunks into canonical SSE events (`text`, `tool_call`, `usage`, `finish_reason`). Kinetix core retains full ownership of HTTP transport, connection pooling, client keepalives, and byte-robust SSE framing.

### 2. Credential Strategy (`credential_plugin`)
* **WIT World**: `plugin` (`interface credential-strategy`)
* **Exported Functions**: `resolve`, `refresh`, `revoke`
* **Contract**: Takes a configured credential handle and returns an authorization token. The secret token is stored as an encrypted lease (`lease:<handle>`) in the host-managed KV store and refreshed automatically before expiration.

### 3. Routing Fact Provider
* **WIT World**: `plugin` (`interface routing-fact-provider`)
* **Exported Functions**: `evaluate-facts`
* **Contract**: Computes typed facts exposed to executable Route predicates under the namespace `plugin.<plugin-id>.<fact-name>` (e.g. `plugin.dev.example.geo.region`).
  * `pure` providers: Side-effect free; forbidden from making outbound network calls.
  * `cached` providers: Periodically refreshed; values older than `max_age_ms` expire and evaluate as `unknown`.

### 4. Health Probe
* **WIT World**: `plugin` (`interface health-probe`)
* **Exported Functions**: `check-health`
* **Contract**: Executes on a core-owned background schedule (never on the client request path) to verify provider accounts and report availability or quota evidence. Kinetix core retains ownership of cooldown and circuit policies.

### 5. Model Source (`model_source_plugin`)
* **WIT World**: `plugin` (`interface model-source`)
* **Exported Functions**: `discover-models`
* **Contract**: Invoked by `POST /admin/api/providers/:id/discover` to discover available upstream models and their capabilities.

### 6. Read-Only Hooks
* **WIT World**: `plugin` (`interface hooks`)
* **Exported Functions**: `on-request-normalized`, `on-target-candidate`, `on-usage-finalized`
* **Contract**: Dispatched asynchronously on a bounded fire-and-forget channel. Hooks can never modify payloads, delay responses, or crash in-flight requests.

---

## Package Format (`.kxp`)

A Kinetix Plugin package is an uncompressed tar archive containing:

```text
foo.kxp
├── plugin.toml          # Plugin manifest
├── plugin.wasm          # Compiled WebAssembly component
├── signature.ed25519    # Optional Ed25519 signature
├── README.md            # Optional documentation
└── LICENSE              # Optional license text
```

### Manifest Example (`plugin.toml`)

```toml
manifest_version = 1
plugin_api = "1"
id = "dev.kinetix.antigravity-oauth"
name = "Antigravity OAuth"
version = "0.1.0"

[provides]
credential_strategies = ["antigravity-oauth"]
auth_flows = ["antigravity"]
provider_adapters = ["antigravity"]

[[integrations]]
id = "antigravity"
name = "Google Antigravity"
description = "Connect a Google Antigravity account and use the v1internal model API."
provider_adapter = "antigravity"
credential_strategy = "antigravity-oauth"
auth_flow = "antigravity"

[permissions]
network_hosts = ["accounts.google.com", "oauth2.googleapis.com", "www.googleapis.com"]
credential_scopes = ["provider:antigravity"]
credential_read = true

[limits]
memory = "64MiB"
wall_time_ms = 10000
max_outbound_requests = 2
max_http_body = "1MiB"
storage = "1MiB"
```

### Integration descriptors

An optional `[[integrations]]` entry groups low-level capabilities into a
user-facing integration. The descriptor is declarative metadata: it does not
execute code in the dashboard and grants no additional permission.

Each referenced `provider_adapter`, `credential_strategy`, `auth_flow`, or
`model_source` must exist in the same manifest's `[provides]` list. Kinetix rejects duplicate
integration IDs or references to undeclared capabilities during installation.

### Account authorization flows

A plugin may declare named `auth_flows`. These use the separate
`plugin-auth` WIT world, so older plugin API v1 components that do not provide
browser login remain compatible.

Kinetix owns the security-sensitive browser session mechanics:

- 256-bit random CSRF `state`,
- S256 PKCE verifier/challenge generation and in-memory storage,
- ten-minute flow expiry,
- one-time state consumption before code exchange,
- credential JSON validation, encryption, and account insertion.

The plugin owns provider-specific behavior:

- constructing the provider authorization URL (its host must also be present
  in the reviewed `network_hosts` set),
- exchanging the callback code,
- optional provider user-info/onboarding calls through approved `host-http`,
- mapping the result to the provider credential JSON consumed by its
  credential strategy.

The callback never writes an account into an arbitrary provider. The selected
provider must already be bound to the integration's declared
`credential_strategy`.

---

## Developing Plugins

The separate `plugins/` workspace contains the official Rust SDK and example plugins.

### 1. Project Setup

Add `kinetix-plugin-sdk` to your `Cargo.toml`:

```toml
[package]
name = "my-plugin"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
kinetix-plugin-sdk = { path = "../sdk" }
wit-bindgen = "0.62"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
```

### 2. Implement Capabilities

Export the WIT world using `kinetix_plugin_sdk`:

```rust
use kinetix_plugin_sdk::guest::*;

struct MyPlugin;

impl Guest for MyPlugin {
    // Implement required world interfaces...
}

export!(MyPlugin);
```

### 3. Build with `scripts/build-plugin.sh`

The build script compiles the crate to `wasm32-wasip1` (or `wasm32-unknown-unknown`), converts it to a component using `wasm-tools`, validates WIT compliance, and packages the `.kxp` archive:

```bash
./scripts/build-plugin.sh plugins/antigravity-oauth
```

The output package is produced at `plugins/antigravity-oauth/target/antigravity-oauth-0.1.0.kxp`.

### Installed package retention

When Kinetix accepts a package, it preserves the exact `.kxp` bytes in a
content-addressed cache under:

```text
$KINETIX_DATA_DIR/plugins/packages/<plugin-id>/<sha256>.kxp
```

SQLite records the plugin id, declared version, SHA-256, signature status,
source, and relative package path. Previous package versions are retained when
a plugin is upgraded, providing immutable provenance and the artifact inputs
needed for a future rollback operation. The active runtime still uses the
validated manifest/component stored by the host; plugins never receive
filesystem access to this cache.

---

## Operating Plugins

### CLI Workflow

```bash
# 1. Install package (installed-disabled by default)
kinetix plugin install plugins/antigravity-oauth/target/antigravity-oauth-0.1.0.kxp \
  --allow-untrusted-signature

# 2. View manifest and requested permissions
kinetix plugin show dev.kinetix.antigravity-oauth

# 3. Approve declared permissions (all-or-nothing)
kinetix plugin approve dev.kinetix.antigravity-oauth

# 4. Enable the plugin
kinetix plugin enable dev.kinetix.antigravity-oauth

# 5. Verify exports and linking
kinetix plugin validate dev.kinetix.antigravity-oauth

# 6. List active plugins
kinetix plugin list
```

### Binding to Providers

Once enabled, bind the plugin's capabilities to providers in your configuration or bootstrap file:

```toml
[[providers]]
name = "Google Antigravity"
base_url = "https://autopush-alkalimakersuite-pa.sandbox.googleapis.com"
wire_format = "antigravity"
auth_scheme = "bearer"
wire_plugin = "plugin:dev.kinetix.antigravity-oauth/antigravity"
credential_plugin = "plugin:dev.kinetix.antigravity-oauth/antigravity-oauth"

  [[providers.accounts]]
  label = "primary"
  api_key = "refresh_token_here"
```

Or configure via the Admin API:

```bash
curl -X POST http://127.0.0.1:8080/admin/api/providers \
  -H "Content-Type: application/json" \
  -b cookie.txt \
  -d '{
    "name": "Google Antigravity",
    "base_url": "https://autopush-alkalimakersuite-pa.sandbox.googleapis.com",
    "wire_format": "antigravity",
    "auth_scheme": "bearer",
    "wire_plugin": "plugin:dev.kinetix.antigravity-oauth/antigravity",
    "credential_plugin": "plugin:dev.kinetix.antigravity-oauth/antigravity-oauth",
    "api_key": "refresh_token_here",
    "account_label": "primary"
  }'
```

### Using Plugin Routing Facts in Routes

```json
{
  "name": "region-aware-route",
  "strategy": "priority",
  "targets": [
    {
      "model": "ProviderEU/model-1",
      "predicate": {
        "expr": {
          "fact": "plugin.dev.example.geo.region",
          "op": "eq",
          "value": "eu"
        }
      }
    },
    {
      "model": "ProviderUS/model-1",
      "predicate": {
        "expr": {
          "fact": "plugin.dev.example.geo.region",
          "op": "eq",
          "value": "us"
        }
      }
    }
  ]
}
```

---

## Bundled Plugin: Antigravity OAuth

The repository includes a production-grade component at `plugins/antigravity-oauth`:

* **Capabilities**:
  * Credential strategy `antigravity-oauth`: Exchanges Google OAuth 2.0 refresh tokens for temporary access tokens via `oauth2.googleapis.com`.
  * Provider adapter `antigravity`: Translates between standard OpenAI/Anthropic messages and Google's internal `v1internal` protocol, parsing stream chunks and mapping 429 quota-reset headers.
* **Tests**: `tests/plugin_e2e.rs` verifies real component installation, permission approval, capability resolution, token refresh, and stream chunk parsing against a live SQLite database.
