"""Provider protocol and adapter factory."""

from __future__ import annotations

import json
from typing import Any, Protocol

from forgeward.models import CompletionRequest, CompletionResult, ProviderConfig


class ProviderError(RuntimeError):
    def __init__(self, message: str, *, code: str, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable


class ModelProvider(Protocol):
    def complete(self, request: CompletionRequest) -> CompletionResult: ...

    def probe(self) -> tuple[bool, str]: ...


def chat_messages(
    request: CompletionRequest, *, transport_json_schema: bool
) -> list[dict[str, Any]]:
    """Normalize roles and preserve the output contract on schema-limited routes."""
    messages = [
        {
            "role": "system" if message.role == "developer" else message.role,
            "content": message.content,
        }
        for message in request.messages
    ]
    if request.response_schema and not transport_json_schema:
        schema = json.dumps(
            request.response_schema,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        if len(schema) > 32_000:
            raise ProviderError(
                "Response schema is too large to embed in a provider prompt",
                code="schema_too_large",
            )
        messages.insert(
            0,
            {
                "role": "system",
                "content": (
                    "Return exactly one JSON object that validates against this canonical JSON "
                    "Schema. Do not use Markdown fences or add prose.\n"
                    f"<response-json-schema>{schema}</response-json-schema>"
                ),
            },
        )
    return messages


def create_provider(config: ProviderConfig) -> ModelProvider:
    if config.adapter == "demo":
        from forgeward.providers.demo import DemoProvider

        return DemoProvider(config)
    if config.adapter == "openai-compatible":
        from forgeward.providers.openai_compatible import OpenAICompatibleProvider

        return OpenAICompatibleProvider(config)
    if config.adapter == "litellm":
        from forgeward.providers.litellm_adapter import LiteLLMProvider

        return LiteLLMProvider(config)
    raise ProviderError(
        f"Unsupported provider adapter: {config.adapter}", code="unsupported_adapter"
    )
