# Provider abstraction

> **Status:** alpha. “OpenAI-compatible” describes a wire contract, not identical behavior, safety, quality, privacy, or feature support.

ForgeWard keeps model choice behind a narrow provider port. The core speaks an OpenAI-compatible Chat Completions subset; operators can point it directly at a compatible service or place an optional LiteLLM gateway in front of other providers.

This is closer to a database driver interface than a true ORM. It normalizes transport and common fields, but it cannot make model capabilities semantically interchangeable.

## Why this boundary

There are many “unified LLM” SDKs and gateways. For ForgeWard's security-sensitive controller, a small contract has useful properties:

- provider code does not own lifecycle state or tool execution;
- a base URL, model identifier, and secret reference cover many hosted and local endpoints;
- request and response fixtures can be contract-tested without a live provider;
- optional translation does not become a mandatory dependency; and
- capability gaps remain visible instead of being silently approximated.

The primary wire reference is OpenAI's [Chat Completions API](https://developers.openai.com/api/reference/resources/chat). OpenAI recommends the newer [Responses API](https://developers.openai.com/api/reference/resources/responses/methods/create) for some native use cases, but Chat Completions currently has broader third-party compatibility. Responses support may be added as a separately negotiated transport; it should not silently change the existing contract.

## Supported core contract

The portable request subset is intentionally conservative:

```json
{
  "model": "provider-model-id",
  "messages": [
    {"role": "system", "content": "bounded role instructions"},
    {"role": "user", "content": "engagement context"}
  ],
  "temperature": 0.2,
  "max_tokens": 4096
}
```

Required semantics:

- `model` is an opaque configured identifier, not a capability claim.
- `messages` use `system`, `user`, `assistant`, and, when enabled, `tool` roles.
- plain text content must be supported.
- a successful alpha response must contain at least one assistant text message.
- provider output is schema-validated and remains untrusted after validation.
- token usage is optional metadata and must not control a security decision.

Sampling fields, token limits, structured outputs, tool calls, streaming, vision, reasoning controls, and provider-specific extensions are capabilities, not baseline assumptions. The alpha adapter supports text and can request OpenAI-style `response_format: {type: "json_schema"}` when `capabilities.json_schema` is enabled. ForgeWard should reject a workflow that requires an unavailable capability rather than silently discard the field.

OpenAI documents a function-calling shape in its official [function calling guide](https://developers.openai.com/api/docs/guides/function-calling), but ForgeWard's `0.1` provider adapter does not parse provider tool calls. Roles return a strict deliverable, including any proposed file changes, and the local controller mediates those proposals. If native provider tool calls are added later, a valid shape will still be only a proposal subject to lifecycle, role, project-policy, and human-approval checks.

## Deployment modes

### Direct OpenAI-compatible endpoint

Use this mode when the provider already exposes the supported contract. Configuration needs:

- a stable provider alias;
- an absolute HTTPS base URL ending at the API version root, or HTTP on localhost/loopback;
- optionally, the name of an environment variable containing the API key;
- a model identifier; and
- declared capabilities and timeouts.

The `0.1` direct adapter does not follow redirects and disables ambient proxy configuration. It accepts plaintext HTTP for localhost and numeric loopback addresses; every other HTTP URL fails unless the operator sets the conspicuous `allow_insecure_http: true` escape hatch for an externally protected local network. It streams HTTP-decoded response bytes up to `max_response_bytes` before parsing and discards upstream error bodies. The API key value must never be stored in `.forgeward/firm.yaml`, prompts, logs, or evidence. `forgeward provider test` uses a minimal synthetic prompt and reports endpoint results without echoing credentials.

Examples of primary compatibility documentation include [Ollama's OpenAI compatibility](https://docs.ollama.com/api/openai-compatibility) and [vLLM's OpenAI-compatible server](https://docs.vllm.ai/en/stable/serving/openai_compatible_server/). These links describe those projects' interfaces; they are not claims that every feature or release has been tested by ForgeWard.

### Optional LiteLLM SDK or gateway

[LiteLLM](https://docs.litellm.ai/docs/) is the recommended optional translation layer when an upstream provider does not expose the portable contract or when an operator wants centralized routing. LiteLLM documents both an OpenAI-format [proxy/gateway](https://docs.litellm.ai/docs/simple_proxy) and [OpenAI-compatible endpoint configuration](https://docs.litellm.ai/docs/providers/openai_compatible).

ForgeWard still treats every translated response as untrusted. LiteLLM is not required for direct compatible endpoints, and using it does not expand ForgeWard's policy authority. Operators are responsible for its credentials, callbacks, logs, network exposure, retention, and—when using the gateway—database and virtual-key configuration.

The `litellm` Python extra enables the `adapter: litellm` execution path for native provider dialects in process. It passes the same OpenAI-shaped messages and JSON Schema response request into `litellm.completion`, explicitly disables LiteLLM retries and parameter dropping, and normalizes the result back into ForgeWard-owned types. For centralized routing, budgets, fallbacks, or multi-user governance, run the LiteLLM gateway and point ForgeWard's smaller `openai-compatible` adapter at it instead.

This in-process mode has a narrower security guarantee. When `base_url` is omitted, endpoint selection,
proxy and CA behavior, credentials, callbacks, and network transport are delegated to LiteLLM and its
provider SDKs. `max_response_bytes` is enforced on returned text only after LiteLLM has materialized the
response, so it is not a network-allocation ceiling. Even with an explicit URL, ForgeWard cannot force
LiteLLM's internal client to ignore ambient proxy settings. If transport enforcement and pre-parse body
limits are required, run LiteLLM as a separate HTTPS gateway and use `adapter: openai-compatible`.

Pin and review the LiteLLM version separately. Provider translation is a supply-chain and semantic boundary, so a gateway upgrade should run the provider contract tests before use on a sensitive engagement.

## Configuration model

The following excerpt shows the exact provider and role field names in `0.1`; it is not a complete standalone `firm.yaml` because the remaining required workflow roles and policy are omitted:

```yaml
version: 1

project:
  name: example-project
  default_provider: gateway

providers:
  local:
    adapter: openai-compatible
    base_url: http://127.0.0.1:11434/v1
    model: code-model
    api_key_env: LOCAL_LLM_API_KEY
    timeout_seconds: 90
    max_response_bytes: 2000000
    allow_insecure_http: false
    capabilities:
      tools: false
      json_schema: false
      streaming: false
      images: false
      reasoning: false

  gateway:
    adapter: openai-compatible
    base_url: https://llm-gateway.example.test/v1
    model: planning-model
    api_key_env: FORGEWARD_GATEWAY_KEY
    timeout_seconds: 90
    max_response_bytes: 2000000
    allow_insecure_http: false
    capabilities:
      tools: false
      json_schema: true
      streaming: false
      images: false
      reasoning: false

  native:
    adapter: litellm
    model: anthropic/your-model-id
    api_key_env: ANTHROPIC_API_KEY
    timeout_seconds: 90
    max_response_bytes: 2000000
    allow_insecure_http: false
    enabled: false
    capabilities:
      tools: false
      json_schema: true
      streaming: false
      images: false
      reasoning: true

team:
  - id: architect
    mission: Define a secure, reviewable implementation design.
    provider: gateway
    prompt: architect.md
    allowed_tools: [repository.read, artifact.read]
    may_approve: []
  - id: builder
    mission: Implement only the changes covered by the approved plan.
    provider: local
    prompt: builder.md
    allowed_tools: [repository.read, artifact.read, diff.read, workspace.propose]
    may_approve: []

# Add product, designer, security, scrum-master, reviewer, tester, and release
# roles, then declare workflow, policy, and checks as needed.
```

Alpha keys may evolve. The model belongs to the provider record, so roles that need different models use different provider aliases. Validate a complete checked-out configuration with `forgeward team validate`, list configured providers with `forgeward provider list`, and probe a provider with `forgeward provider test` instead of assuming an excerpt matches a future release.

Environment-variable indirection is deliberate: a configuration file names the secret source but never interpolates the secret into durable project state.

## Capability negotiation

Each provider/model pair should have an explicit capability record:

| Capability | Portable fallback | Failure behavior |
| --- | --- | --- |
| Text chat | None | Provider is unusable |
| Tool calls | Not consumed by the `0.1` provider adapter; use strict deliverable proposals | Block the role, never execute guessed output |
| JSON schema response format | Embed the canonical schema in the prompt, then parse and validate plain JSON | Stop the call on malformed output; automatic retries are disabled |
| Streaming | Non-streamed response | Safe to disable |
| Token usage | Local estimate or unknown | Report unknown; do not treat as zero cost |
| Seed/determinism | None | Record unsupported; models remain nondeterministic |
| Vision or files | Textual artifact reference when appropriate | Block workflows that require the modality |

Capabilities should come from configuration plus a recorded test, not name-based inference. A successful health check proves only that the tested request worked at that time.

## Error normalization

The `0.1` adapter emits bounded controller errors in these categories:

- `missing_credential`, `invalid_base_url`, and `insecure_base_url`;
- `authentication`, `rate_limit`, and `invalid_request`;
- `timeout`, `network`, and `provider_unavailable`;
- `malformed_response` and `response_too_large`; and
- `provider_error` for other HTTP failures.

The HTTP adapter does not automatically retry in `0.1`, and the optional LiteLLM adapter passes `num_retries: 0`. Future controller retries must be bounded, use backoff, and apply only to operations known to be side-effect free. The direct HTTP adapter does not surface upstream error bodies. LiteLLM adapter errors expose only the exception class and normalized category, not the upstream message.

## Privacy and network behavior

ForgeWard sends no usage analytics, crash reports, or artifacts to ForgeWard maintainers. It does send the prompt and selected context to the configured endpoint. Only Git-tracked source is eligible; common credential paths are omitted and known secret shapes are redacted, but those controls are not data classification. Run `forgeward context preview` before a live provider call. “Local-first” does not mean “local-model-only.”

Before using a provider, determine:

- what source and artifact content will be sent;
- where processing occurs;
- whether prompts or outputs are retained or used for training;
- whether the provider or gateway logs request bodies;
- which subprocesses or callbacks the gateway enables; and
- how credentials, rate limits, and deletion are managed.

Use a local endpoint or a provider contract appropriate to the data classification. ForgeWard cannot enforce an external provider's promises.

## Compatibility policy

Compatibility claims should be evidence-based. A provider matrix must record the ForgeWard version, adapter/gateway version, endpoint type, model ID, tested capabilities, test date, and known deviations. Passing one model must not mark an entire provider as supported.

The minimum contract suite covers:

1. successful text completion;
2. malformed response rejection;
3. authentication failure redaction;
4. timeout and network-error classification;
5. JSON-schema response mode on and off;
6. usage metadata missing or malformed;
7. redirect and credential-in-URL rejection behavior; and
8. preservation of the returned model ID in the completion result.

Native tool-call contract tests and provider/model-per-artifact evidence are required when those features are implemented.

Synthetic fixtures must contain no production secrets or private code.

## Alternatives and future work

The “LLM ORM” category is useful but not perfectly standardized. LiteLLM is the optional dialect layer because it presents a unified OpenAI-format SDK/gateway while ForgeWard preserves a direct-endpoint path. ForgeWard does not embed a broad agent framework in its controller because framework tool loops can blur the authority boundary.

Future adapters may target the Responses API or another stable standard, but each transport must preserve the same invariants: models cannot alter policy, call tools directly, approve gates, or write durable controller state.
