# Kinetix Plugin Architecture

## Status

**Implemented (post-v1).** This turns Kinetix's existing internal extension seams into a secure external plugin
architecture using the WebAssembly Component Model (Wasmtime 48). Plugins remain opt-in and post-v1.

The architecture deliberately preserves Kinetix's rule that provider behavior should remain
configuration-driven whenever possible. A plugin exists only when an integration cannot be expressed
through supported wire formats, credential schemes, model discovery configuration, or built-in
internal seams.

This document serves as both the technical design and the implementation reference for the plugin
subsystem (§28 records what is landed in the repository). Where it is more restrictive than the
earlier post-v1 sketch (FR-11.6 in `docs/DESIGN.md`, which described plugins registering whole
providers that could join Routes), the narrower capability model in §6 is a deliberate, recorded
refinement, not an accidental divergence.

## 1. Goals

The plugin system should let operators add integrations such as:

- new credential acquisition/refresh mechanisms;
- provider-specific model discovery;
- new outbound wire protocols;
- bounded provider/account health probes;
- typed routing facts;
- narrowly modeled request/response extension hooks.

It must preserve:

- protocol correctness;
- pre-commit-only fallback;
- deterministic/explainable Routes;
- existing virtual keys, limits, budgets, usage accounting and Route Trace;
- upstream credential isolation;
- one-machine deployment;
- bounded data-plane overhead;
- native-adapter performance independent of installed plugins.

## 2. Non-goals

The plugin system is **not**:

- a workflow engine;
- an arbitrary scripting layer;
- an alternate Route engine;
- an admin-auth extension mechanism;
- a way to inject arbitrary middleware into Axum;
- direct SQLite access;
- unrestricted filesystem/network execution;
- a marketplace;
- a compatibility promise for Kinetix's internal Rust types.

## 3. Core architectural rule

> **Plugins extend integration behavior; Kinetix owns policy.**

The following stay in core:

```text
client auth
 -> virtual-key authorization
 -> request limits / budget
 -> canonical request
 -> Route predicates / selection
 -> fallback policy / commit state
 -> accounting / audit / trace
```

Plugins can participate only at explicit typed extension points around that pipeline.

## 4. Runtime choice

### Decision: WebAssembly Component Model hosted by Wasmtime

External plugins are WebAssembly Components. Kinetix embeds Wasmtime and exposes a versioned WIT
host API.

Why:

- process memory isolation from the Rust core;
- cross-language plugin SDKs;
- typed interface contracts rather than Rust ABI coupling;
- host-controlled imports;
- deterministic refusal of incompatible interfaces;
- explicit resource limits;
- no need to ship a second long-running service.

Native Rust `.so` / `.dll` plugins are not a supported public format.

### Host runtime pinning

The host is pinned to an exact Wasmtime release and a specific component-model revision, recorded in
the build metadata and surfaced by `kinetix plugin validate`. Because the component-model ABI in
Wasmtime still moves independently of WIT semantics, upgrading Wasmtime is treated like a
`plugin_api` change: it requires re-running the conformance suite against every installed plugin and
is never shipped as a silent patch bump. The host must use Wasmtime's async component support; the
streaming and cancellation requirements in §7.1–7.2 and §16 cannot be met with the synchronous call
model alone.

### WASI policy

Do **not** inherit ambient WASI authority.

Default plugin environment:

```text
filesystem: none
raw sockets: none
environment variables: none, except explicitly supplied non-secret values
wall clock: host API only where needed
randomness: host-provided
stdout/stderr: captured + namespaced + redacted
```

Outbound HTTP is a Kinetix host capability, not unrestricted guest networking.

## 5. Package format

Use `.kxp` ("Kinetix Extension Package"), a deterministic archive:

```text
foo.kxp
├── plugin.toml
├── plugin.wasm
├── README.md
├── LICENSE
└── signature.ed25519       # optional in first release
```

`plugin.toml` example:

```toml
manifest_version = 1
id = "dev.example.foo"
name = "Foo Provider Integration"
version = "1.2.0"
plugin_api = "1"

[provides]
credential_strategies = ["foo-oauth"]
model_sources = ["foo-models"]
health_probes = ["foo-quota"]

[permissions]
network_hosts = [
  "api.foo.example",
  "auth.foo.example"
]
credential_scopes = ["credential_strategy:foo-oauth"]

[limits]
memory = "64MiB"
wall_time_ms = 5000
max_outbound_requests = 4
max_http_body = "4MiB"
storage = "2MiB"
```

Plugin ID is immutable across versions.

### Manifest limits vs host policy

Values in `[limits]` are *requests*, not grants. Host policy is evaluated first and wins: a plugin can
never self-authorize more memory, wall time, outbound requests, or storage than the operator's host
limits allow. The effective limit is `min(manifest request, host policy)`. Storage is declared only
under `[limits]`; §10 governs how that budget is enforced.

## 6. Capability model

### 6.0 Binding a provider or Route to a plugin capability

A plugin capability is inert until core configuration references it. References are explicit and
namespaced by plugin id, so two plugins may both provide a capability name like `foo-oauth` without
collision:

```text
provider.credential_strategy = "plugin:dev.example.foo/foo-oauth"
provider.wire_format        = "plugin:dev.example.foo/foo-wire"
provider.model_source       = "plugin:dev.example.foo/foo-models"
route.target.health_probe   = "plugin:dev.example.foo/foo-quota"
```

Rules:

- the namespace is `plugin:<id>/<capability-name>`; core never resolves an unqualified plugin name;
- Validate/Dry Run rejects a reference to a plugin that is not installed, is disabled, or does not
  declare the capability in `[provides]`;
- if the referenced plugin is disabled at runtime, the bound provider/Route fails closed (the
  candidate is ineligible with an explicit Route Trace reason) rather than silently falling back to
  native behavior;
- a Route target may mix plugin and native capabilities freely; the plugin never gains visibility
  into sibling targets.

### 6.0.1 User-facing integration descriptors

A plugin may optionally group low-level capabilities into declarative
`[[integrations]]` records. Each integration has a stable id, display
name/description, and may reference a provider adapter, credential strategy,
and/or model source exported by that same plugin.

The host validates every reference against `[provides]` at install time.
Integration descriptors are presentation/configuration metadata only: they do
not grant permissions, execute browser code, or alter routing. This lets the
dashboard present a product-level integration such as **Google Antigravity**
instead of requiring operators to manually compose `wire_plugin` and
`credential_plugin` references.

### 6.0.2 Integration provider templates

An Integration may optionally describe the host-owned provider it needs:
base URL, host wire class, auth scheme, timeout/capability defaults, model path,
redirect policy, credential hosts, and static headers. When a
`provider_adapter` is present, the template uses `wire_format = "plugin"`;
the concrete adapter name remains the Integration's capability binding.

Provider creation is a separate authenticated admin action. Core re-validates
outbound URL policy, verifies the plugin is enabled with its declared permissions
approved, resolves each derived capability binding, and creates the provider
with `allow_insecure_tls = false`. Setup is idempotent for an existing matching
base URL and binding set.

Generated provider ids cannot be known in a signed manifest. For this case,
`credential_scopes` supports `credential_strategy:<name>`. At credential-use
time the host authorizes the scope only when the target provider's
`credential_plugin` is exactly `plugin:<this-plugin>/<name>`. Literal
`provider:<id>` and wildcard scopes remain available for other use cases.

### 6.0.3 AuthFlow

AuthFlow provisions an account through a provider-owned browser authorization
flow. It is a separate `plugin-auth` world so existing plugin API v1
components do not gain a mandatory export.

Security ownership is intentionally split:

- **Kinetix core** creates one-time high-entropy CSRF state and PKCE verifier
  material, enforces expiry/replay protection, constructs the callback URI,
  validates the plugin-returned authorization URL against HTTPS + reviewed
  `network_hosts`, bounds and validates the returned credential JSON, encrypts
  it, and inserts the account.
- **The plugin** constructs provider-specific authorization URLs and performs
  token exchange/post-exchange calls through its approved `host-http`
  capability.

The callback may enroll only into a provider whose `credential_plugin` still
matches the integration's declared credential strategy. State is consumed
before token exchange, so callback replay fails closed.

The browser never receives access or refresh tokens from Kinetix. Provider
client constraints remain plugin-specific: for example, the bundled
Antigravity desktop OAuth client supports loopback callbacks only.

### 6.0.4 Declarative dashboard actions

Plugins may declare host-rendered `[[ui.actions]]` metadata. Actions never load
plugin JavaScript into the dashboard origin. Instead, the dashboard renders a
Kinetix-owned control and dispatches an operation that the host already
authorizes.

The initial `auth` action kind references an integration id. The referenced
integration must provide both an `auth_flow` and a `credential_strategy`.
This keeps UX composition in the manifest while CSRF/PKCE, permissions,
credential persistence, and browser authority remain host-owned.

Custom executable plugin UI remains out of scope for this version.

### 6.1 CredentialStrategy

Purpose:

- produce/refresh an account credential;
- report expiry;
- report credential health evidence;
- optionally execute auth flows through admin-controlled operations.

A credential plugin does not choose Routes or accounts.

Preferred result:

```text
CredentialLease {
  handle,
  expires_at,
  refresh_after,
  health
}
```

The handle is opaque. When possible, the plugin uses it through the host HTTP capability without
ever receiving plaintext secret bytes.

### 6.2 ModelSource

Returns discovery **observations**:

```text
DiscoveredModel {
  id,
  display_name?,
  context_window?,
  max_output_tokens?,
  capabilities?,
  raw_metadata?
}
```

Core rules remain:

- observations do not overwrite explicit admin edits;
- unknown remains unknown;
- import is an admin/core operation;
- plugin cannot directly write provider/model tables;
- `raw_metadata` is bounded by the returned-value limit (§14) and is kept only for admin inspection,
  never promoted into canonical model fields without an explicit import action.

### 6.3 ProviderAdapter

Use only when existing outbound wire formats are insufficient.

Responsibilities:

- canonical request -> provider request;
- provider stream -> canonical stream events;
- non-streaming response -> canonical result;
- protocol-native error evidence -> normalized failure evidence;
- opaque provider-state encode/decode.

It does **not** own:

- retry/fallback ordering;
- account cooldown state;
- Route predicates;
- accounting;
- client frontend encoding.

Opaque provider state is tagged with the producing plugin id **and version**. Core stores that tag
alongside the blob and refuses to hand a blob produced by `1.2.0` to a `1.3.0` adapter unless the new
version explicitly declares it can read the old encoding. Core — never the plugin — still owns the
`reject` / `strip_with_warning` portability decision from FR-2.11/12.13; the plugin may only report
that a blob is unreadable, not decide what happens to the request.

This keeps cross-provider behavior centralized.

### 6.4 RoutingFactProvider

Produces typed facts, never target selections.

Example output:

```json
{
  "plugin.dev.example.foo.region": "eu-west",
  "plugin.dev.example.foo.capacity_class": "burst",
  "plugin.dev.example.foo.private_endpoint": true
}
```

Route predicates consume those facts. Missing/failed facts evaluate as `unknown` unless a stronger
capability contract explicitly says otherwise.

#### Determinism and staleness

Routes must remain deterministic and explainable (§1), so a routing-fact capability may not perform
unbounded live network work on the request path. One of two models is required, chosen in the
manifest and enforced by the host:

- **pure:** the routing-facts world does not import `host-http`; facts are derived only from the
  request/config facts core already provides, and evaluation is a side-effect-free function; or
- **cached:** the plugin computes facts on a background schedule and the request path only reads the
  last published snapshot. Each fact carries an `observed_at`; a fact older than its declared
  `max_age` evaluates as `unknown`.

In both models a fact that is missing, failed, or stale is recorded in the Route Trace as `unknown`
**with the reason** (timeout, plugin fault, no observation), so explainability does not degrade
exactly where routing is hardest.

### 6.5 HealthProbe

Produces evidence:

```text
HealthObservation {
  state: healthy | degraded | unavailable | unknown,
  quota_state?,
  reset_at?,
  retry_after?,
  detail_code?,
}
```

Core translates the evidence into account runtime state under Kinetix policy. Health probes run on a
background schedule owned by core, never lazily on the routing path: a cold account must not pay a
probe's wall time inside a client request (NFR-1.1/1.2).

### 6.6 Typed hooks

Do not start with general arbitrary JSON middleware.

Initial hook points:

```text
on_request_normalized      read-only
on_target_candidate        read-only
on_usage_finalized         read-only + optional external side effect
```

`on_usage_finalized` side effects run on the bounded async accounting queue (FR-6.4) and are
fire-and-forget: they may never block, fail, or slow a client request.

Only add a mutable hook after its allowed mutation surface is explicitly modeled.

## 7. WIT host API shape

Illustrative, not final syntax.

### 7.1 Buffered vs streaming host HTTP

The buffered `host-http` below is for **control-plane** capabilities only: model discovery, health
probes, and credential acquisition. It is deliberately not sufficient for a ProviderAdapter.
Because streaming is the normal path (DESIGN principle 3) and TTFT/bounded per-stream memory are SLOs
(NFR-1.2/1.3), adapters use a **separate streaming world** built on Wasmtime's async component
support. A buffered-only interface is never the adapter contract, and `plugin_api = "1"` must not
ship an adapter surface that would have to be replaced to stream.

```wit
interface host-http {
  use types.{http-request, http-response, plugin-error};
  send: func(req: http-request) -> result<http-response, plugin-error>;
}

// Adapter world only. Response bytes arrive incrementally; the guest emits
// canonical events as they are parsed, so a coding-agent stream is never
// whole-response buffered.
interface host-http-stream {
  use types.{http-request, plugin-error};
  enum stream-event { headers, data(list<u8>), end, error(plugin-error) }
  open: func(req: http-request) -> result<response-handle, plugin-error>;
  next: func(h: response-handle) -> result<stream-event, plugin-error>;
  cancel: func(h: response-handle);
}
```

Host HTTP controls timeouts and redirect policy entirely; guests may not request either. This is
consistent with NFR-3.10 (redirect default zero) and keeps NFR-3.11 credential host binding under
host control.

> **Implementation note (see §28).** The adapter class turned out **not** to need a streaming host
> capability: Kinetix core already owns the outbound streaming send and SSE framing, and the
> `ProviderAdapter` seam is a *pure transform* interface (`build_url`/`apply_auth`/`build_body`/
> `classify_error`/`parse_stream_chunk`/`parse_full_response`). A plugin adapter is therefore a pure
> translation library that imports **no** network capability, and the `plugin-adapter` world is bound
> and executed (with the buffered `host-http` refused to adapter stores). The `host-http-stream` sketch
> below is retained only for a future capability that genuinely needs incremental guest transport;
> it is not the adapter contract in the shipped design.

### 7.2 Cancellation

Client disconnect (FR-2.9, NFR-1.10) must reach a running guest. Cancellation is delivered as a
cooperative signal first, then enforced:

```text
client disconnect / core abort
 -> mark the invocation cancelled
 -> abort any in-flight host HTTP for that invocation
 -> signal the guest (host-http-stream.cancel, or a cancel flag the guest may poll)
 -> if the guest does not unwind within a short grace window, terminate it via epoch interruption
```

A cancellation is **not** a plugin fault and must not increment the circuit-breaker counters in §15.
The Route Trace records cancellation as a client-driven outcome, not a plugin failure.

### 7.3 Credential signing

A protocol that must cryptographically transform the credential (for example SigV4-style request
signing) is handled by a host capability, so the highest-value auth plugins are not forced to read
plaintext (§8.2):

```wit
interface host-credential {
  use types.{http-request, credential-ref, plugin-error};
  // Host signs/authorizes the request using the scoped credential without
  // ever returning the secret to the guest.
  sign: func(req: http-request, ref: credential-ref) -> result<http-request, plugin-error>;
}
```

### 7.4 Illustrative interfaces

```wit
package kinetix:plugin@1.0.0;

interface types {
  record plugin-error {
    code: string,
    message: string,
    retryable: bool,
  }

  record account-ref {
    provider-id: string,
    account-id: string,
  }

  record http-request {
    method: string,
    url: string,
    headers: list<tuple<string, string>>,
    body: list<u8>,
    credential: option<credential-ref>,
  }

  variant credential-ref {
    account(account-ref),
    named(string),
  }

  record http-response {
    status: u16,
    headers: list<tuple<string, string>>,
    body: list<u8>,
  }
}

interface host-http {
  use types.{http-request, http-response, plugin-error};
  send: func(req: http-request) -> result<http-response, plugin-error>;
}

interface host-storage {
  get: func(key: string) -> option<list<u8>>;
  put: func(key: string, value: list<u8>) -> result<_, string>;
  delete: func(key: string) -> result<_, string>;
}

interface host-log {
  enum level { trace, debug, info, warn, error }
  log: func(level: level, message: string);
}
```

Each plugin world imports only the interfaces corresponding to approved permissions. In particular,
the routing-facts world imports neither `host-http` nor `host-http-stream` in the `pure` model (§6.4),
and `host-http-stream` and `host-credential` are available only to worlds whose manifest declares the
matching capability.

## 8. Credential security model

### 8.1 Opaque credential handles

Default flow:

```text
Plugin
  -> asks host to send request
  -> request references CredentialRef(account)
  -> Kinetix verifies plugin scope
  -> Kinetix injects credential after policy checks
  -> network request
```

The plugin never sees the secret.

### 8.2 Plaintext access

Only introduce a separate `credential-read` capability when a protocol cannot be implemented
even through host-side signing (§7.3), for example if the guest must derive or transform a secret in a
way the host cannot express.

Requirements:

- explicit manifest permission;
- provider/account scope;
- audit event;
- delivered through a single host call and returned as best-effort short-lived memory; this is **not**
a confidentiality guarantee. WebAssembly linear memory cannot be reliably zeroized: the guest may copy
the value, and the host cannot scrub guest pages after the call returns. Treat `credential-read` as a
materially higher-risk grant and say so in permission review;
- never persisted by host storage automatically;
- admin warning in permission review.

### 8.3 Master key

No plugin can access Kinetix's credential-encryption master key.

## 9. Network capability

All outbound plugin HTTP goes through Kinetix.

Validation pipeline:

```text
plugin request
 -> manifest hostname check
 -> URL parse
 -> credential-host binding check
 -> DNS resolution
 -> private/link-local/metadata rejection
 -> connect-time resolved-IP recheck
 -> TLS verification
 -> redirect policy
 -> per-hop revalidation
 -> size/time limits
 -> request
```

No wildcard `network = true`. `network_hosts` is always an explicit list.

Suggested hostname syntax:

```toml
network_hosts = [
  "api.example.com",
  "*.service.example.com"
]
```

Wildcard policy should be conservative: one DNS label unless explicitly extended. A wildcard host
entry only authorizes connection targets; it must never broaden credential host binding (NFR-3.11). A
credential scoped to `api.foo.example` is not sent to `evil.service.example` merely because a
wildcard matched the connection.

## 10. Plugin storage

A plugin gets a private logical namespace:

```text
(plugin_id, key) -> encrypted blob
```

The plugin cannot query another plugin's keys.

KV is **encrypted by default** using the same host-level encryption machinery with a separate derived
context/key label, because the anticipated first plugins (§25 B) store refresh metadata and tokens.
Do not leave this to plugin-author judgment.

KV blobs are namespaced by plugin id but not by plugin version: state survives an upgrade and the new
version is expected to read and migrate its own keys, since plugin-defined database migrations are
forbidden (§26). Keys written by a version the plugin no longer understands are its own
responsibility to ignore.

Use Kinetix's existing SQLite database for host-managed plugin state rather than giving plugins SQL
access.

Suggested tables:

```sql
CREATE TABLE plugins (
  id TEXT PRIMARY KEY,
  version TEXT NOT NULL,
  plugin_api_major INTEGER NOT NULL,
  package_sha256 TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 0,
  manifest_json TEXT NOT NULL,
  installed_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE plugin_permissions (
  plugin_id TEXT NOT NULL,
  permission TEXT NOT NULL,
  value_json TEXT NOT NULL,
  approved_at TEXT NOT NULL,
  PRIMARY KEY (plugin_id, permission),
  FOREIGN KEY (plugin_id) REFERENCES plugins(id) ON DELETE CASCADE
);

CREATE TABLE plugin_kv (
  plugin_id TEXT NOT NULL,
  key TEXT NOT NULL,
  value BLOB NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (plugin_id, key),
  FOREIGN KEY (plugin_id) REFERENCES plugins(id) ON DELETE CASCADE
);

CREATE TABLE plugin_runtime_state (
  plugin_id TEXT PRIMARY KEY,
  circuit_state TEXT NOT NULL,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  circuit_open_until TEXT,
  last_error_code TEXT,
  last_error_at TEXT,
  FOREIGN KEY (plugin_id) REFERENCES plugins(id) ON DELETE CASCADE
);
```

Plugin KV is encrypted at rest (see §10).

## 11. Installation and verification

### Local file

```bash
kinetix plugin install ./foo.kxp
```

### URL

```bash
kinetix plugin install \
  https://plugins.example/foo-1.2.0.kxp \
  --sha256 <expected>
```

Initial install sequence:

```text
download/read
 -> size limit
 -> hash verification
 -> parse manifest
 -> validate package paths
 -> API compatibility
 -> validate declared capabilities
 -> signature verification (Phase 2; skipped in Phase 1)
 -> permission review
 -> compile component
 -> plugin self-check
 -> store package metadata
 -> installed-disabled
```

Enable is a separate operation.

No central marketplace in the first release.

## 12. Signing

Phase 1:

- SHA-256 required for URL installs;
- local installs record the computed SHA-256.

Phase 2:

- optional Ed25519 package signature;
- operator-managed trusted publisher keys;
- signature status visible in UI.

A package signed by a key that is not trusted is rejected by default; an operator may explicitly
downgrade to warn-and-allow per install, and that choice is audited.

Do not require a global CA.

## 13. Activation and runtime snapshots

Plugin registry participates in Kinetix's immutable validated runtime snapshot.

Config/plugin mutation:

```text
validate
 -> instantiate/check plugin
 -> build next runtime snapshot
 -> atomic swap
```

Existing in-flight requests retain the old snapshot.

Removing/disabling a plugin prevents new requests from referencing it but does not invalidate an
already-owned invocation needed by an in-flight request.

## 14. Resource limits

Start conservative and configurable by host policy.

Suggested defaults:

| Resource | Default |
|---|---:|
| linear memory | 64 MiB |
| component instances | bounded pool |
| synchronous CPU slice | bounded with epoch/fuel policy |
| ordinary operation wall time | 5 s |
| routing fact wall time | 25 ms |
| request hook wall time | 25 ms |
| model discovery wall time | 30 s |
| health probe wall time | 10 s |
| outbound requests / invocation | 4 |
| outbound body | 4 MiB |
| returned value | 4 MiB |
| KV storage | 2–10 MiB/plugin |

These are initial host defaults, not ABI constants. The manifest may *request* limits (§5), but the
host applies `min(manifest request, host policy)`: a plugin can never self-grant more memory, wall
time, outbound requests, or storage than the operator allows.

Routing facts are invoked inline on the request path but must stay within their 25 ms budget; per
§6.4 the `pure` model does no network work, and the `cached` model reads a precomputed snapshot.
Health probes (10 s) and model discovery (30 s) run off the request path.

## 14.1 Catalog distribution and publisher trust

The official catalog is a discovery index, not a signing authority. Package
trust is anchored separately in a compiled publisher-key store.

A catalog install is accepted only after this chain succeeds:

```text
catalog id
 -> embedded catalog entry
 -> HTTPS URL + redirect-host allow-list
 -> bounded download
 -> exact catalog SHA-256
 -> package manifest id/version match
 -> Ed25519 signature verified by separately trusted publisher key
 -> normal install pipeline
 -> installed disabled
 -> explicit permission review
```

The dashboard cannot submit arbitrary URLs or publisher keys for catalog
installation. Redirects are followed manually so every destination remains
HTTPS and inside the entry's explicit host allow-list. Existing local upload
and server-path installation remain separate operator workflows.

Signing private keys never ship with Kinetix. Release tooling consumes them
only from an operator-owned local key file or CI secret and publishes
`signature.ed25519` inside the deterministic `.kxp`.

## 15. Plugin circuit breaker

Per plugin:

```text
closed
 -> repeated plugin faults
 -> open
 -> cooldown
 -> half-open probe
 -> closed
```

Count:

- Wasm traps;
- timeout;
- resource-limit termination;
- invalid WIT result/invariant violation;
- forbidden host-capability call;
- repeated malformed protocol output.

Do **not** count:

- ordinary upstream HTTP failures, unless the plugin violates its classification contract;
- client-driven cancellation or disconnect (§7.2).

Plugin circuit state must not disable unrelated native providers.

## 16. Data-plane semantics

### Credential strategy

```text
candidate selected
 -> core requests credential lease
 -> plugin/host obtains or refreshes credential
 -> failure before commit = candidate unavailable/retryable according to typed result
 -> core decides fallback
```

### Provider adapter

```text
canonical request
 -> plugin encode
 -> core host HTTP transport (streaming, §7.1)
 -> plugin parses canonical events
 -> core frontend encoder
```

The core owns the client-visible commit state. Once committed, no plugin may request target
substitution. Client cancellation propagates into the guest per §7.2.

### Routing facts

```text
request/config facts
 -> bounded plugin fact invocation
 -> typed fact set
 -> Route predicate evaluator
 -> Route Trace
```

The plugin never receives a "choose target" callback.

## 17. Failure contracts

Every capability result should distinguish:

```text
invalid_configuration
unauthorized
credential_expired
rate_limited
quota_exhausted
upstream_unavailable
protocol_error
plugin_internal
timeout
permission_denied
unknown
```

With structured evidence:

```text
retryable
retry_after
reset_at
safe_message
internal_detail_code
```

The core decides cooldown/exhaustion/fallback behavior.

A plugin reports *evidence* in this vocabulary; it never receives a callback that lets it select a
target, force fallback, or move the commit point.

## 18. Audit and observability

Metrics:

```text
kinetix_plugin_invocations_total{plugin,capability,outcome}
kinetix_plugin_duration_seconds{plugin,capability}
kinetix_plugin_traps_total{plugin}
kinetix_plugin_timeouts_total{plugin}
kinetix_plugin_circuit_state{plugin}
kinetix_plugin_http_requests_total{plugin,host,outcome}
kinetix_plugin_storage_bytes{plugin}
```

`host` is bounded because it can only ever be one of the plugin's declared `network_hosts`; the host
enforces that bound so the label cannot explode in cardinality.

Admin-visible invocation record:

```text
plugin id/version
capability
operation
duration
outcome
circuit state
network hosts contacted
permission denial, if any
redacted error code
```

Never log plugin-returned secrets or raw auth headers.

## 19. Route Trace integration

Plugin facts:

```json
{
  "fact": "plugin.dev.example.foo.region",
  "value": "us-east-1",
  "source": {
    "plugin": "dev.example.foo",
    "version": "1.2.0",
    "capability": "routing-facts"
  },
  "duration_ms": 1.7
}
```

Plugin adapter failures:

```json
{
  "phase": "adapter",
  "plugin": "dev.example.foo",
  "candidate": "<opaque-admin-only-ref>",
  "result": "protocol_error",
  "before_commit": true
}
```

Ordinary clients still receive no provider/account topology details. Fact-provider failures follow
the same redaction rule and are recorded as `unknown` with a reason (§6.4).

## 20. Admin API

Suggested endpoints:

```text
GET    /admin/api/plugins
POST   /admin/api/plugins/install
GET    /admin/api/plugins/{id}
POST   /admin/api/plugins/{id}/enable
POST   /admin/api/plugins/{id}/disable
POST   /admin/api/plugins/{id}/upgrade
DELETE /admin/api/plugins/{id}

GET    /admin/api/plugins/{id}/permissions
POST   /admin/api/plugins/{id}/permissions/approve
POST   /admin/api/plugins/{id}/permissions/revoke

GET    /admin/api/plugins/{id}/metrics
GET    /admin/api/plugins/{id}/audit
POST   /admin/api/plugins/{id}/validate
```

Permission approval is **all-or-nothing per install/upgrade**: the declared set is approved or
rejected as a whole. Operators do not partially grant a plugin's requested permissions. If a later
upgrade requests fewer or different permissions, the operator still reviews the diff, and reducing a
permission does not delete plugin KV state (the plugin may still need to read or migrate it).

All mutations enter the existing audit log.

## 21. Dashboard

Plugin details page should show:

```text
Foo Integration 1.2.0
Status: Enabled
Plugin API: 1
SHA-256: ...
Signature: verified / unsigned

Provides
  Credential strategy: foo-oauth
  Model source: foo-models

Permissions
  Network:
    api.foo.example
    auth.foo.example
  Credentials:
    provider:foo
  Storage:
    2 MiB

Runtime
  p50/p95 duration
  errors
  traps/timeouts
  circuit state
  storage used

[Validate] [Disable] [Upgrade] [Remove]
```

Upgrade UI must show a **permission diff** before approval, and the approval is all-or-nothing (§20).

## 22. SDK strategy

Ship an official plugin SDK after the WIT surface stabilizes.

First-class:

- Rust;
- TypeScript/JavaScript compiled to components only once the component toolchain is mature enough for
the supported API (not merely "acceptable");
- Go only once its component tooling is mature enough for the supported API.

Language support is gated on tooling that can actually produce conformant components; a language is
not listed until its generated bindings pass the conformance suite in §23.

The ABI is WIT, not the Rust SDK.

SDK responsibilities:

- generated bindings;
- typed error helpers;
- manifest validation;
- local test host;
- fixture harness;
- package builder;
- `kinetix plugin lint`.

## 23. Testing

### Core host

- invalid/malformed components;
- infinite loop;
- memory growth;
- oversized return value;
- too many outbound requests;
- forbidden host;
- redirect to metadata/private IP;
- DNS rebinding simulation;
- credential-scope violation;
- storage quota exhaustion;
- incompatible API major;
- manifest/package traversal attacks;
- trap during stream parsing;
- disable/upgrade during in-flight request;
- circuit-breaker transitions;
- malformed WIT values and oversized/ill-typed guest returns at the host boundary;
- cancellation delivered while the guest is blocked in host HTTP;
- signature verification failure and untrusted-key handling;
- permission reduction across upgrade, including KV retention;
- upgrade rollback after a failed self-check;
- concurrent upgrade/disable during model discovery or a health probe;
- plugin storage encryption round-trip and key-label isolation.

### Plugin conformance

For provider adapters:

- streaming fixtures;
- partial UTF-8/JSON boundaries;
- tool-call fragmentation;
- reasoning state;
- opaque-state preservation;
- usage;
- cancellation;
- malformed upstream event;
- pre-commit failure;
- post-commit failure;
- client disconnect.

Plugin adapter output must pass the same canonical/frontend golden fixtures used by native adapters.

### Performance

Benchmark:

- no plugins installed;
- plugins installed but not selected;
- routing-fact plugin;
- credential plugin;
- provider adapter plugin.

Native adapter latency targets must remain unchanged.

## 24. Recommended rollout

### P0 — Refactor only

Formalize current internal seams around stable DTOs. Remove accidental `AppState`, database row and
internal-struct leakage.

No external plugins.

### P1 — Host skeleton

Add:

- plugin registry;
- manifest parser;
- package hashing;
- Wasmtime host;
- WIT API v1;
- permission objects;
- resource limits;
- metrics;
- install/enable/disable.

Expose only a non-data-plane validation capability to prove lifecycle/security.

### P2 — ModelSource

First real external capability.

Reason: low risk, control-plane oriented, and easy to test.

### P3 — CredentialStrategy

Add opaque credential handles and host-injected HTTP credentials.

### P4 — HealthProbe / RoutingFactProvider

Add bounded typed observations.

### P5 — ProviderAdapter

Only after the host is stable. Requires the strongest conformance and streaming tests.

### P6 — Typed hooks

Add only concrete hook cases justified by integrations. Do not add arbitrary middleware.

## 25. Recommended first plugins

### A. External model-catalog plugin

Use case:

- organization maintains a private model catalog/API;
- plugin supplies discovery observations to Kinetix.

Capabilities:

```text
ModelSource
network: catalog.example
no credential read unless catalog itself requires a scoped credential
```

This is the safest production proof of the plugin system.

### B. Secret-broker credential plugin

Use case:

- obtain provider credentials from an external secret broker/Vault-like service;
- return opaque credential lease.

Capabilities:

```text
CredentialStrategy
network: secret broker hosts
credential read: none for other providers
storage: optional small refresh metadata
```

### C. Cloud-provider signed-auth plugin

Use case:

- acquire/refresh short-lived cloud credentials or sign requests;
- useful for providers whose auth cannot be represented as a static header/query parameter.

This exercises the host's most important security boundary.

### D. New-wire-format provider adapter

Only after A–C.

This validates that Kinetix can add a genuinely new protocol without moving Route, accounting,
fallback or frontend policy outside the core.

## 26. Decisions to keep out of v1

Do not make any of these prerequisites for current Kinetix:

- plugin marketplace;
- automatic remote update;
- unsigned background updates;
- arbitrary scripting;
- plugin-to-plugin calls;
- plugin dependencies;
- shared plugin storage;
- full WASI filesystem;
- raw socket access;
- plugin-defined admin pages;
- plugin-defined database migrations;
- plugin-defined Route selection strategies;
- plugin-defined opaque-state portability decisions (core owns `reject`/`strip_with_warning`);
- buffered-only host HTTP as the adapter contract.

They can be revisited only with concrete integrations that require them.

## 27. Acceptance criteria for the plugin host

The first public plugin runtime is ready only when all are true:

1. A malicious plugin cannot read another provider's credentials.
2. A malicious plugin cannot connect to an undeclared host.
3. A trap/infinite loop cannot crash Kinetix or block unrelated traffic.
4. An incompatible plugin API is rejected before enable.
5. Permission increases are visible and require approval.
6. Plugin state survives restart without direct DB access.
7. Disabling/upgrading does not corrupt in-flight requests.
8. Plugin facts and failures are explainable in Route Trace/admin audit.
9. A plugin cannot force fallback after commit.
10. Native adapters meet existing benchmark targets with the plugin host present.
11. Plugin request/log data follows the same redaction rules as core data.
12. Package hash/version is recorded for every invocation's plugin version. This requires a migration
    of the existing usage/request schema (FR-6.1); the schema change is planned and reversible, not
    assumed.
13. A client disconnect cancels an in-flight plugin invocation without counting it as a plugin fault.
14. A routing-fact plugin cannot make Routes non-deterministic: `pure` facts are side-effect-free and
    `cached` facts respect `max_age`, with stale/failed facts recorded as `unknown` plus reason.
15. A provider/Route that references a disabled plugin fails closed with an explicit Route Trace
    reason rather than silently using native behavior.
16. A plugin-encoded opaque-state blob is tagged with plugin id and version, and core — not the plugin
    — decides portability (`reject`/`strip_with_warning`).

## 28. Implementation status

This section records what of the proposal has actually been built in the
repository, so the document stays an honest design record rather than an
aspiration. It is a living list: update it as later phases land.

### 28.1 Landed (this pass)

- **Module tree.** `src/plugins/{types,manifest,package,store,runtime,manager,credential}.rs`
  plus the WIT contract at `wit/kinetix-plugin.wit` (package `kinetix:plugin@1.0.0`,
  worlds `plugin` and `plugin-adapter`) and migration `migrations/0003_plugins.sql`.
- **Manifest and package.** `plugin.toml` parsing/validation, `.kxp` reading as an
  untrusted tar archive (never extracted to disk), SHA-256, and Ed25519 signature
  verification against operator trusted keys (§11, §12).
- **Host runtime.** Wasmtime 48 (component model, async, epoch interruption,
  per-store memory limits). The host is pinned in `Cargo.toml`; the runtime
  enforces the §7.1 control-plane-vs-adapter split, the §8/§9 credential model,
  the §10 encrypted KV, and the §14 limits as `min(manifest request, host policy)`.
- **Lifecycle and persistence.** Install is always installed-disabled; enable
  instantiates the component to prove it links (fail-closed); permissions are
  all-or-nothing; the §15 per-plugin circuit breaker is persisted; removal
  cascades stored state.
- **ModelSource.** `POST /admin/api/providers/:id/discover` dispatches to a bound
  plugin model source, and fails closed when the plugin is bound but unavailable
  (§6.0, §6.2).
- **RoutingFactProvider.** Facts are gathered once before target evaluation and
  exposed to predicates as `plugin.<id>.<name>`; `pure` plugins cannot open
  outbound HTTP (§6.4, §7.4); `cached` facts past `max_age_ms` are dropped and
  evaluate as `unknown`; failures are recorded as `unknown` plus a reason in the
  Route Trace (§19).
- **HealthProbe.** Probes run on a core-owned background schedule, never on the
  request path (§6.5); the observation is folded into account health and core
  still owns cooldown/circuit policy.
- **Typed read-only hooks.** `on_request_normalized`, `on_target_candidate`, and
  `on_usage_finalized` run fire-and-forget on a bounded queue; a hook can never
  block, fail, or slow a client request (§6.6).
- **CredentialStrategy.** A bound credential plugin resolves through
  `PluginCredentialStrategy`; the secret crosses back only via the plugin's
  encrypted KV under `lease:<handle>` (§6.1).
- **Cancellation.** A client disconnect (FR-2.9/NFR-1.10) flips a cancellation
  flag, the routing-fact guest is epoch-interrupted, and the outcome is reported
  as a cancellation rather than a plugin fault (§7.2), so it never counts against
  the circuit.
- **ProviderAdapter (P5).** The `plugin-adapter` world is bound and executed. It
  is a *pure translation library*: the plugin supplies
  `wire_format`/`build_url`/`apply_auth`/`build_body`/`classify_error`/
  `parse_stream_chunk`/`parse_full_response` and Kinetix core still owns the
  outbound streaming HTTP send and SSE framing, so the adapter world imports **no
  network capability at all**. The host-side `PluginAdapter` (`src/plugins/adapter.rs`)
  implements the core `Adapter` trait and bridges the synchronous trait onto the
  async guest via `block_in_place`. Canonical events and failure evidence cross
  the boundary as tagged JSON. This **supersedes** the `host-http-stream`
  design in §7.1: because core owns transport, an adapter needs no streaming
  host capability and the buffered `host-http` import is refused to adapter
  stores. A provider bound with `wire_plugin` resolves to its plugin adapter at
  enable time (registered under both `plugin:<id>/<cap>` and the bare id).
- **Guest SDK and real plugin.** `plugins/sdk` (`kinetix-plugin-sdk`, wit-bindgen
  0.62) exposes both worlds and small helpers; `plugins/antigravity-oauth` is a
  real component providing a CredentialStrategy (Google OAuth refresh-token
  exchange) **and** the `antigravity` (`v1internal`) wire format, built by
  `scripts/build-plugin.sh` into a `.kxp`. The component is a valid wasm32
  component (two worlds from one binary).
- **Live guest-invocation tests.** `tests/plugin_e2e.rs` installs, enables, and
  invokes the real compiled component: credential-strategy resolution across the
  host boundary, and the adapter world's `wire_format`/`build_url`/`apply_auth`/
  `build_body`/`parse_stream_chunk`/`classify_error` (including Antigravity 429
  quota-reset parsing).
- **Surface.** CLI `kinetix plugin {install,list,show,enable,disable,validate,
  remove,permissions,approve,revoke}`; admin endpoints under `/admin/api/plugins`
  (§20); dashboard-independent JSON summaries.

### 28.2 Not yet implemented (remaining phases)

- **`host-http-stream`.** Not needed for adapters (see §28.1); reserved for a
  future capability that genuinely needs incremental transport from the guest.
- **`host-credential.sign` data-plane wiring.** The WIT interface exists, but the
  request-signing capability is not yet wired to an adapter path.
- **Non-SSE adapter framing.** The adapter contract assumes SSE `data:` framing
  (core-owned). A provider with a non-SSE stream framing would need a framing hook.
- **Runtime-snapshot integration (§13).** Plugin enable/disable is reflected in
  the plugin store and the in-memory capability maps; folding the plugin registry
  into the same immutable `Snapshot` swap is not yet done.
- **Dashboard.** The React dashboard now exposes installed plugin management:
  local `.kxp` upload, permission review/approval, validation, enable/disable,
  and removal. A remote catalog/discovery experience and declarative
  plugin-provided integration UI remain follow-up work.
- **SDK polish (§22).** `plugins/sdk` exists and works, but it is not published
  and does not yet auto-generate stub impls for the interfaces a plugin does not
  provide (a plugin still hand-writes them, as `antigravity-oauth` does).
