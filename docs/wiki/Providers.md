# Providers

A **provider** is an admin-defined upstream: its endpoint URL, wire format, auth
scheme, models, capabilities, parameters, and prices. Kinetix ships **no provider
presets** — nothing is assumed about a vendor.

## Wire formats

Kinetix has three outbound adapters, selected by the provider's configured
`wire_format` (not by vendor):

| `wire_format` | Upstream protocol | Default models path |
| --- | --- | --- |
| `openai` | OpenAI-compatible `/chat/completions` (streaming) | `/models` |
| `anthropic` | Anthropic `/messages` (streaming) | `/models` |
| `gemini` | Gemini `:streamGenerateContent?alt=sse` | `/models` |

Providers can also bind to external WebAssembly plugin adapters via `wire_plugin` (e.g. `plugin:dev.kinetix.antigravity-oauth/antigravity`).
For these providers, set `wire_format = "plugin"`; the concrete adapter identity comes from the namespaced `wire_plugin` reference, not from a vendor-specific core wire enum.

Inbound formats are OpenAI Chat Completions and Anthropic Messages. When inbound
and outbound formats match, Kinetix uses **same-format passthrough** and forwards
the client body byte-for-byte (preserving unknown/vendor fields) while extracting
usage.

## Auth schemes

| `auth_scheme` | How the credential is sent |
| --- | --- |
| `bearer` | `Authorization: Bearer <key>` |
| `custom_header` | A named header (e.g. `x-goog-api-key`), set via `custom_header_name`. |
| `query_param` | A named query parameter (e.g. `key`), set via `custom_param_name`. |

> For an Anthropic-wire provider, set the required `anthropic-version` header via
> the provider's **extra headers** — Kinetix does not add hidden defaults.

## Capabilities, parameters, prices

- **Capabilities** (`text`, `vision`, `reasoning`, `tool_calling`, `audio`) drive
  strict-provider filtering and are surfaced in `GET /v1/models`. Unconfigured
  metadata is treated as unknown, not assumed false.
- **Parameters** (`temperature`, `top_p`, `top_k`, …) each carry a policy
  (`forward` / `clamp` / `reject` / `drop`) and optional min/max/default. A
  configured default is applied when the client omits the field; a client value
  always wins.
- **Prices** are per-1M-token input/output/cached/thinking. Missing prices mean
  cost is **unknown**, never zero.

## Accounts (credential pools)

Each provider has one or more accounts (credentials). Accounts have a priority and
weight, an optional soft quota, and a quota type (`none` / `daily` / `monthly` /
`rolling`). Health states are `healthy`, `cooldown`, `exhausted`, `disabled`, and
`circuit_open`. Health is maintained automatically:

- A 429 with a short retry hint → brief **cooldown** (honoring `Retry-After`).
- A quota-exhaustion 429 → **exhausted** until the reset window.
- An auth error → **disabled**.
- Repeated 5xx/timeout → a **circuit breaker** opens, then probes half-open.

## Discovery

`POST /admin/api/providers/{id}/discover` (or the dashboard's **Fetch Models**)
lists the upstream's models and flags already-imported and disappeared ones.
Discovery **never overwrites admin edits** and never silently deletes a model
(FR-10.5); it records a per-model observation in the `discovery` column.

## Outbound security (SSRF / TLS / redirects)

- Upstream URLs must be **HTTPS** by default; plain HTTP needs
  `KINETIX_ALLOW_INSECURE_TLS` (or the per-provider `allow_insecure_tls`), a
  visibly-marked dev mode (NFR-3.12).
- Blocked hosts (localhost/internal/metadata ranges, loopback/private/link-local
  IPs) are refused unless `KINETIX_ALLOW_PRIVATE_UPSTREAMS` is set (NFR-3.9).
- **Credential host binding** (NFR-3.11): a credential is only sent to the host(s)
  it is authorized for (`base_url` host plus any `credential_hosts`).
- **Zero-redirect default** (NFR-3.10): redirects are not followed unless the
  provider opts in via `follow_redirects`.
- **Connect-time DNS re-check**: the host is re-resolved and re-validated against
  the policy just before connecting.

## Configuring a provider

```bash
kinetix provider add --name "My Provider" --base-url https://api.example.com/v1 \
  --wire-format openai --auth-scheme bearer --api-key sk-... --account-label primary
kinetix model add --provider "My Provider" --upstream-id gpt-4o-mini --display-name "GPT-4o mini"
```

Or through the dashboard's **Upstream Providers** page (which also offers Test
Ping, Fetch Models, and Validate/Dry Run).

## Plugin-backed providers & capability bindings

When an upstream provider requires non-standard protocols, token refresh flows, or specialized discovery, operators can bind the provider to capabilities exposed by installed WebAssembly plugins:

* **`wire_plugin`** (`plugin:<id>/<capability>`): Delegates wire formatting, error classification, and stream event parsing to a WebAssembly plugin adapter implementing the `plugin-adapter` world. The plugin functions as a pure translation engine; Kinetix core retains full control over the underlying HTTP transport, connection pooling, and client SSE streaming.
* **`credential_plugin`** (`plugin:<id>/<capability>`): Delegates credential acquisition or refresh (e.g., OAuth 2.0 refresh-token exchanges, GCP access tokens) to a WebAssembly credential strategy. Fresh credentials are stored as encrypted leases (`lease:<handle>`) inside the host-managed KV store and automatically attached to requests.
* **`model_source_plugin`** (`plugin:<id>/<capability>`): Delegates upstream model discovery to the plugin when `POST /admin/api/providers/{id}/discover` is executed.

### Fail-closed behavior

If a provider references a plugin that is not installed, is disabled, or whose circuit breaker is tripped:
- The provider **fails closed** immediately.
- Requests targeting this provider are skipped before making outbound connections.
- An explicit failure reason is recorded in the Route Trace (e.g. `plugin '...' is disabled; bound provider fails closed`).
- Native providers and other plugins in the Route remain completely unaffected.

## Notes

- Multiple accounts are for legitimate **resilience and cost ordering**, not limit
  evasion. Confirm each provider's terms before team rollout.
- Built-in providers use static API keys. For dynamic token refresh (such as OAuth 2.0 refresh tokens) or custom upstream protocols, use sandboxed WebAssembly plugins (see [Plugins](Plugins)).
