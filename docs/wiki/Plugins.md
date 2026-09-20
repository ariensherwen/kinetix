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
2. **Mediated Network Access**: Plugins have no direct socket access. Outbound HTTP requests must pass through the host HTTP capability and an approved `network_hosts` entry. Kinetix resolves the destination, rejects private/link-local/metadata/special-use IPs, pins the checked DNS answers into a no-proxy/no-redirect HTTPS client, and rejects plugin-supplied `Host` or hop-by-hop/proxy headers before sending. Provider adapters (`plugin-adapter` world) import **no network capabilities at all**.
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
  * `pure` providers: Evaluated on the request path with buffered HTTP disabled.
  * `cached` providers: Refreshed by Kinetix off the request path at `routing_facts_refresh_ms` (default 30s, allowed 5s–1h). Approved buffered HTTP is available only during that refresh. The returned facts and any `cache-set` publications are validated, host-stamped, and committed as one atomic snapshot. Values older than `max_age_ms` expire and evaluate as `unknown`; a failed refresh leaves the previous snapshot intact.

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

[integrations.provider]
base_url = "https://autopush-alkalimakersuite-pa.sandbox.googleapis.com"
wire_format = "plugin"
auth_scheme = "bearer"
timeout_ms = 120000
capability_mode = "permissive"
follow_redirects = false

[permissions]
network_hosts = ["accounts.google.com", "oauth2.googleapis.com", "www.googleapis.com"]
credential_scopes = ["credential_strategy:antigravity-oauth"]
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
user-facing integration. It is declarative metadata only: it executes no
dashboard code and grants no additional authority.

Every referenced `provider_adapter`, `credential_strategy`, `auth_flow`, or
`model_source` must be declared by the same plugin in `[provides]`. Kinetix
rejects duplicate integration IDs, empty integrations, and references to
undeclared capabilities during installation.

### Credential scopes for generated providers

Credential access may be scoped either to a concrete provider id or to the
provider's plugin binding:

```toml
[permissions]
credential_scopes = ["credential_strategy:antigravity-oauth"]
credential_read = true
```

`credential_strategy:<name>` is resolved by the host at credential-use time.
It authorizes this plugin only when the target provider's
`credential_plugin` is exactly `plugin:<this-plugin-id>/<name>`. This is the
preferred scope for Integration-created providers because their database ids
are generated at runtime. Literal `provider:<id>` scopes and `*` remain
supported; `*` should be reserved for plugins that genuinely need access
across provider bindings.

### Integration provider templates

An Integration may declare host-owned provider defaults:

```toml
[integrations.provider]
base_url = "https://api.example.com"
wire_format = "plugin"
auth_scheme = "bearer"
timeout_ms = 120000
capability_mode = "permissive"
follow_redirects = false
```

Kinetix validates the template when the package is installed. Creating the
provider is a separate admin operation and re-runs outbound URL checks plus
capability-binding checks. The host derives `wire_plugin`,
`credential_plugin`, and `model_source_plugin` from the parent Integration;
the package cannot inject bindings to another plugin. Repeating setup returns
the existing matching provider instead of creating a duplicate.

### Native dashboard actions

Plugins may optionally declare `[[ui.actions]]` records. These are
host-rendered controls, not plugin JavaScript. Kinetix validates each action at
install time and the dashboard maps it to an operation already implemented and
authorized by Kinetix core.

The first supported kind is `auth`:

```toml
[[ui.actions]]
id = "connect-account"
label = "Connect account"
kind = "auth"
integration = "antigravity"
description = "Sign in and add an account to a compatible provider."
```

An `auth` action must reference an integration that declares both
`auth_flow` and `credential_strategy`. The browser never executes guest code
and never receives the credential returned by the authorization exchange.

### Storage quota

`limits.storage` applies to all encrypted plugin KV values, including normal
guest storage, cached routing facts, and host-owned `_config:` settings.
Kinetix measures decrypted value bytes, accounts correctly for key replacement,
and serializes competing writes so concurrent calls cannot overcommit the
configured budget.

### Host-owned settings

Plugins may also declare `[[ui.settings]]` fields of kind `text`, `secret`,
`boolean`, or `select`. The dashboard renders these with Kinetix-owned form
controls. Values are validated against the manifest and encrypted in the
plugin KV store under the reserved `_config:` namespace.

Guests may read `_config:<key>` through `host-storage`, but guest writes and
deletes to that namespace are rejected. Secret values are write-only from the
dashboard's perspective: the API reports only whether they are configured.

Example:

```toml
[[ui.settings]]
key = "login_hint"
label = "Google account hint"
kind = "text"
description = "Optional email address used as an OAuth login hint."
```

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
source, and relative package path. Previous package versions are retained
across upgrades, and package provenance survives plugin removal. This provides
immutable audit history and the artifact inputs needed for a future rollback
operation. Plugins never receive filesystem access to this cache.

---

## Plugin Catalog

Kinetix ships an embedded official catalog metadata file at
`plugins/catalog.json`, exposed through `GET /admin/api/plugins/catalog`.
The catalog powers dashboard discovery, but it is deliberately **not** a trust
root for package installation.

Catalog metadata may describe publisher, capabilities, version, and expected
artifact naming. Package installation still requires the normal Kinetix package
pipeline: package bytes are hashed, signatures are evaluated, permissions are
reviewed, and the plugin installs disabled.

Remote signed release-asset installation is enabled only when all of the
following are present:

- the catalog entry is marked `installable = true`;
- it contains an HTTPS distribution URL, exact SHA-256, publisher key id, and
  explicit redirect-host allow-list;
- the publisher key id resolves in the separate compiled
  `plugins/trusted-publishers.json` trust store;
- the downloaded package's SHA, manifest id/version, and Ed25519 signature all
  verify before installation.

The dashboard sends only the catalog plugin id. It cannot supply an arbitrary
download URL or signing key.

### Publisher bootstrap

Generate the signing key offline and keep the private key out of the repository:

```sh
openssl genpkey -algorithm ED25519 -out kinetix-plugin-signing.pem
bash scripts/plugin-publisher-key.sh kinetix-plugin-signing.pem
```

Commit only the printed raw public key (base64) to
`plugins/trusted-publishers.json`, with a stable key id such as
`kinetix-official-v1`. Set `KINETIX_PLUGIN_SIGNING_KEY_FILE` when using
`scripts/release-local.sh`, or configure the
`KINETIX_PLUGIN_SIGNING_KEY_PEM` GitHub Actions secret for the manual release
workflow.

`scripts/build-plugin.sh` then embeds `signature.ed25519` in the deterministic
`.kxp`. Release checksums include both Kinetix binaries and signed plugin
packages.

Do not set an entry `installable = true` until the signed release asset exists
and its exact SHA-256 and redirect hosts have been committed to the catalog.

### Update review

For an already-installed catalog plugin, the dashboard does not install the new
version immediately. It first calls
`GET /admin/api/plugins/catalog/{id}/preview`.

Kinetix downloads the candidate through the same trusted catalog verification
path used by installation, then compares the candidate manifest with the
currently active manifest. The preview shows:

- added/removed network hosts;
- added/removed credential scopes;
- any change to plaintext `credential_read`.

Only after explicit confirmation does Kinetix install the verified candidate.
The upgrade still lands disabled and clears every permission approval, even
when the displayed permission diff is empty.

## Version history and rollback

Kinetix retains accepted package bytes independently from the active plugin row.
The dashboard shows every retained version, its SHA-256, provenance source, and
which package is currently active.

Rolling back is deliberately a reactivation, not a pointer swap:

1. resolve the retained package by plugin id + SHA-256;
2. reject invalid/escaping package paths;
3. read the exact retained `.kxp`;
4. recompute and verify its SHA-256;
5. re-parse and validate the manifest id/version;
6. recompile the WebAssembly component;
7. activate it through the normal plugin upsert path.

Before rollback, the dashboard requests a retained-package preview. Kinetix
re-hashes and revalidates the target package, then computes a semantic
permission delta for:

- added/removed `network_hosts`;
- added/removed `credential_scopes`;
- changes to `credential_read`.

The reactivated package is always **disabled** and all permission grants are
cleared even when the diff is empty. An operator must review and approve the
rolled-back manifest before it can be enabled again.

## Dashboard organization

The Plugins & Integrations page is split into three host-owned views:

- **Discover** — browse bundled catalog metadata and install trusted packages;
- **Installed** — inspect lifecycle state, permissions, settings, runtime limits,
  integrations, package history, and rollback;
- **Updates** — show only installed catalog plugins whose published catalog
  version differs, with review-first permission-diff flow before upgrade.

The views are presentation only. They do not alter package trust, permission
approval, enablement, or rollback semantics.

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
wire_format = "plugin"
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
