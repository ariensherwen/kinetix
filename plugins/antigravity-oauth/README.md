# Antigravity plugin

A Kinetix plugin that supplies an **Antigravity** credential strategy **and** the
`antigravity` (`v1internal`) wire format.

[Antigravity](https://antigravity.google) (Google's Cloud Code Assist IDE
backend) authenticates with a Google OAuth2 access token that expires roughly
hourly. This plugin refreshes that token on demand and hands Kinetix an opaque
lease; the live token is written to the plugin's host-encrypted KV and injected
by the host at send time, so the data plane never sees the plugin produce the
secret directly.

The plugin also implements the `plugin-adapter` world (`v1internal` wire format).
That world is a **pure translation library**: Kinetix core owns the outbound HTTP
send and SSE framing, and the adapter only builds the URL/body/headers and parses
stream/error responses. It imports no network capability at all.

The manifest groups those two low-level capabilities into the
`antigravity` integration descriptor. Dashboard clients can therefore present
one user-facing **Google Antigravity** integration instead of exposing separate
wire-adapter and credential-strategy names. It also exports an `antigravity`
AuthFlow so a local Kinetix dashboard can create an account through Google
authorization without manually pasting refresh-token JSON.

## Connect from the dashboard

The bundled Google OAuth client is a desktop/native client and therefore uses a
loopback callback. Set `KINETIX_PUBLIC_BASE_URL` to a loopback URL such as
`http://127.0.0.1:8080`, bind the provider's credential strategy to
`plugin:dev.kinetix.antigravity-oauth/antigravity-oauth`, then use **Connect**
from Plugins & Integrations.

Remote hosted callbacks require an operator-provided web OAuth client, which is
reserved for the declarative plugin-settings layer.

## Credential format

Import each Antigravity account's secret as JSON:

```json
{
  "refresh_token": "1//0g...",
  "access_token": "ya29....",
  "expiry": "2026-09-20T12:00:00Z",
  "project_id": "useful-fuze-12345",
  "email": "user@example.com"
}
```

Only `refresh_token` is required; the rest is refreshed and cached.

## Bind a provider

```
provider.credential_plugin = "plugin:dev.kinetix.antigravity-oauth/antigravity-oauth"
provider.wire_plugin       = "plugin:dev.kinetix.antigravity-oauth/antigravity"
```

`wire_plugin` selects the plugin's `v1internal` adapter; it is registered when
the plugin is enabled and fails closed if the plugin is missing or disabled.

## Permissions

- `network_hosts = ["accounts.google.com", "oauth2.googleapis.com", "www.googleapis.com"]`
  — browser authorization host validation, token exchange, and user-info lookup.
- `credential_scopes = ["provider:antigravity"]`.
- `credential_read = true` — **required** because the refresh-token exchange
  places the secret in a POST body, which the opaque-handle model cannot
  express. This is the materially higher-risk grant described in §8.2 of the
  architecture doc.

## Reference

Derived from the Antigravity handling in the `9router` project
(`open-sse/executors/antigravity.js`,
`src/lib/oauth/providers/antigravity.js`,
`open-sse/providers/registry/antigravity.js`).

## Build

```sh
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown -p kinetix-plugin-antigravity-oauth
wasm-tools component new \
  target/wasm32-unknown-unknown/release/kinetix_plugin_antigravity_oauth.wasm \
  -o plugin.wasm
```
