# Client compatibility notes (FR-9.3)

Checked-in notes for the clients Kinetix is actually exercised against by
maintainers. This is documentation, **not** a public certification claim
(FR-9.3/NFR-7.2: wire compatibility is defined by fixtures, adversarial tests,
and real acceptance sessions, not by reading specifications).

## Pi (coding agent) — OpenAI Chat Completions

Pi is the primary client and is configured as an ordinary OpenAI-compatible
provider pointed at Kinetix. Nothing Pi-specific is required on the Kinetix side.

```jsonc
// Pi provider config (illustrative; exact fields follow Pi docs)
{
  "provider": "kinetix",
  "baseUrl": "http://127.0.0.1:8080/v1", // or https://api.example.com/v1
  "apiKey": "sk-kinetix-…",              // a Kinetix virtual key
  "apiMode": "openai-chat-completions"
}
```

Verified acceptance behaviour (Milestone 1 / FR-9.2):

- A multi-turn streaming conversation, including a tool call, completes through
  OpenAI format. The tool call arrives as an assistant `tool_calls` delta with a
  stable `id` (`call_…`), the function name, and arguments streamed as JSON text
  fragments that reassemble correctly.
- `GET /v1/models` lists the aliases and Routes the key may use, plus bare
  upstream model IDs.
- Request headers Kinetix adds: `X-Request-Id`, `X-Kinetix-Route-Id` (opaque),
  `X-Kinetix-Fallback: 1` when a fallback occurred, and `X-Kinetix-Warning` when
  a `strip_with_warning` portability action affected the request. The fallback
  header is a presence flag (the hop count is internal routing detail and is not
  exposed); resolve the opaque route id for the full trace. Serving
  account/provider names are **not** exposed to clients (FR-12.15).

### Session identity for cache affinity

Kinetix does not guess a conversation identity (FR-7.5). To use cache-aware
sticky routing (FR-7.3), the client must send an explicit session header:
`X-Kinetix-Session`, `X-Session-Id`, `Session-Id` (underscore spelling),
`X-Conversation-Id`, or `X-Session-Affinity`. Without one, each request is
routed independently. Pi sends `X-Session-Id` when configured with
`sendSessionAffinityHeaders` and `sessionAffinityFormat: "openrouter"`, or
`Session-Id` with the `"openai"` format (see `docs/pi-compatibility.md`).

## OpenAI Responses API Clients (Next-Gen Coding Agents)

Kinetix serves an **explicit translated subset** of `POST /v1/responses`. It
normalizes supported Responses requests into Kinetix's canonical request model
and routes them through Gemini, OpenAI-compatible Chat Completions, Anthropic,
or plugin adapters. There is currently **no native Responses upstream
passthrough or Responses object store**.

Supported request semantics:

- text input, `instructions`, message input items, and URL/data-URL image input;
- custom function tools, function-call history, and function-call outputs;
- `tool_choice`: `auto`, `none`, `required`, or one named function;
- `temperature`, `top_p`, `max_output_tokens`, and Kinetix compatibility
  aliases/controls already represented by the canonical model;
- `reasoning.effort` as an input control when the selected model has an
  explicit thinking mapping;
- streaming and non-streaming output for text and custom function calls.

Streaming emits the supported semantic lifecycle events:
`response.created`, `response.in_progress`, output/content item events,
`response.output_text.*`, function-call argument events, and
`response.completed`. `response.completed` is terminal; Kinetix does not add
the Chat Completions `[DONE]` sentinel.

Unsupported semantics fail explicitly instead of being approximated. This
includes `previous_response_id`/conversation state, response storage,
background responses, hosted/MCP/computer/code-interpreter tools,
`include` expansions, structured `text.format`, reasoning summaries/output
items, automatic truncation, metadata storage, and unknown Responses fields.

## Coding-Agent Compatibility CI Matrix

Wire compatibility across coding agents is exercised continuously via
`scripts/compat-matrix.sh` (backed by `scripts/compat-matrix.py`) against synthetic
upstreams:

| Client Profile | Inbound API | Scenarios Tested |
|---|---|---|
| **Pi Coding Agent** | `/v1/chat/completions` | Plain streaming, tool calls & delta reassembly, multi-turn continuation, session affinity, sync fallback |
| **Next-Gen / Codex CLI** | `/v1/responses` | Plain streaming, tool calling, input chaining, session affinity, sync fallback |
| **Claude Code / Anthropic Agent** | `/v1/messages` | Plain streaming, tool calling, tool result continuation, session affinity, sync fallback |

Chat Completions scenarios cover same-format OpenAI passthrough and translated
Gemini paths. Responses scenarios exercise Kinetix's translated Responses
frontend; native Responses upstream passthrough is not implemented. The matrix
has zero external test runner dependencies.

## Anthropic-format clients

`POST /v1/messages` accepts the Anthropic Messages shape with `x-api-key` auth
and `anthropic-version`. Streaming emits `message_start` → content blocks →
`message_delta` → `message_stop`. Known fidelity note: because Kinetix's Gemini
upstream reports usage only at stream end, `message_start` reports
`input_tokens: 0` and `message_delta` carries the output count; the authoritative
input/output/thinking counts are recorded in the usage log and the Route Trace.

## Reasoning / thinking models

Kinetix passes reasoning through the portable-extension layer and never invents
reasoning fields for models without configuration (FR-2.5). Consequence: with a
small `max_tokens`, a reasoning model may spend the entire budget on thinking and
return empty content with `finish_reason: "length"` — this is upstream behaviour,
not a Kinetix bug. Raise `max_tokens` or lower the thinking level.

## Documented deviations from r4

- **Dashboard:** r4 specifies an embedded **Svelte/SvelteKit** dashboard
  (FR-8.1). Kinetix ships the vendored **React 19 + Vite** dashboard, embedded
  the same way (rust-embed). This is a deliberate, documented deviation.
- **Admin API path:** the admin API is mounted under `/admin/api/*` so it does
  not collide with the dashboard's `/admin/<tab>` page routes; the design
  document lists the paths without the `/api` segment.
- **Virtual-key prefix:** `sk-kinetix-…` (an early draft said `sk-prism-`; the
  product was renamed to Kinetix).

## Provider wire-format notes

- **Gemini:** `streamGenerateContent?alt=sse`; SSE frames are CRLF-separated and
  are normalized to LF by the byte-robust framer (FR-2.12). `thoughtSignature`
  values are round-tripped through the internal model's signature slots.
- **OpenAI-compatible:** same-format passthrough forwards the upstream's frames
  verbatim, preserving unknown/vendor fields (FR-2.10) — e.g. vendor `cost` or
  `reasoning_details` fields Kinetix itself never produces.
- **Anthropic:** the `anthropic-version` header is **not** auto-added (no hidden
  defaults); set it via the provider's extra headers.
