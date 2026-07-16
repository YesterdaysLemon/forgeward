"""Optional in-process LiteLLM adapter for native multi-provider dialects."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any

from forgeward.models import (
    ChatMessage,
    CompletionRequest,
    CompletionResult,
    ProviderConfig,
    Usage,
)
from forgeward.providers.base import ProviderError, chat_messages
from forgeward.providers.url_policy import validate_provider_base_url

_MAX_CREDENTIAL_CHARS = 16_384


class LiteLLMProvider:
    """Translate provider dialects through LiteLLM while preserving ForgeWard types."""

    def __init__(self, config: ProviderConfig) -> None:
        self.config = config
        self.base_url = (
            validate_provider_base_url(
                config.base_url,
                allow_insecure_http=config.allow_insecure_http,
                allow_loopback_http=False,
            )
            if config.base_url is not None
            else None
        )

    def probe(self) -> tuple[bool, str]:
        try:
            result = self.complete(
                CompletionRequest(
                    model=self.config.model,
                    messages=[
                        ChatMessage(role="user", content="Reply with exactly: forgeward-ready")
                    ],
                    max_tokens=20,
                    temperature=0,
                    metadata={"role": "doctor"},
                )
            )
        except ProviderError as exc:
            return False, f"{exc.code}: {exc}"
        return bool(result.content.strip()), f"response received from {result.model}"

    def complete(self, request: CompletionRequest) -> CompletionResult:
        try:
            import litellm  # type: ignore[import-not-found]
        except ImportError as exc:
            raise ProviderError(
                "LiteLLM adapter is not installed; install ForgeWard with the `litellm` extra",
                code="missing_dependency",
            ) from exc

        api_key: str | None = None
        if self.config.api_key_env:
            api_key = os.environ.get(self.config.api_key_env)
            if not api_key:
                raise ProviderError(
                    f"Required credential variable {self.config.api_key_env} is not set",
                    code="missing_credential",
                )
            if len(api_key) > _MAX_CREDENTIAL_CHARS:
                raise ProviderError(
                    "Configured credential exceeds the supported length",
                    code="invalid_credential",
                )

        messages = chat_messages(
            request, transport_json_schema=self.config.capabilities.json_schema
        )
        if api_key:
            if api_key in request.model:
                raise ProviderError(
                    "Configured credential appears in the model identifier",
                    code="invalid_request",
                )
            for message in messages:
                content = message.get("content")
                if isinstance(content, str):
                    message["content"] = content.replace(api_key, "[REDACTED]")
        arguments: dict[str, Any] = {
            "model": request.model,
            "messages": messages,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "timeout": self.config.timeout_seconds,
            "num_retries": 0,
            "drop_params": False,
        }
        if api_key:
            arguments["api_key"] = api_key
        if self.base_url:
            arguments["api_base"] = self.base_url
        if request.response_schema and self.config.capabilities.json_schema:
            arguments["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "forgeward_deliverable",
                    "strict": True,
                    "schema": request.response_schema,
                },
            }
        try:
            response = litellm.completion(**arguments)
        except Exception as exc:
            status = getattr(exc, "status_code", None)
            code, retryable = _classify_status(status)
            raise ProviderError(
                f"LiteLLM request failed ({type(exc).__name__})",
                code=code,
                retryable=retryable,
            ) from exc
        data = _response_mapping(response)
        try:
            choice = data["choices"][0]
            content = choice["message"]["content"]
            if not isinstance(content, str):
                raise TypeError("content is not text")
            _enforce_text_limit(content, self.config.max_response_bytes)
            if api_key:
                content = content.replace(api_key, "[REDACTED]")
            model = _bounded_metadata(data.get("model") or request.model, "model", 500)
            finish_value = choice.get("finish_reason")
            finish_reason = (
                _bounded_metadata(finish_value, "finish_reason", 100)
                if finish_value is not None
                else None
            )
            if api_key:
                model = model.replace(api_key, "[REDACTED]")
                if finish_reason is not None:
                    finish_reason = finish_reason.replace(api_key, "[REDACTED]")
            usage = _usage(data.get("usage", {}))
            result = CompletionResult(
                content=content,
                model=model,
                finish_reason=finish_reason,
                usage=usage,
            )
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError(
                "LiteLLM returned a malformed Chat Completions response",
                code="malformed_response",
            ) from exc
        return result


def _response_mapping(response: Any) -> Mapping[str, Any]:
    try:
        if isinstance(response, Mapping):
            return response
        model_dump = getattr(response, "model_dump", None)
        if callable(model_dump):
            value = model_dump()
            if isinstance(value, Mapping):
                return value
        json_method = getattr(response, "json", None)
        if callable(json_method):
            raw = json_method()
            value = raw if isinstance(raw, Mapping) else json.loads(raw)
            if isinstance(value, Mapping):
                return value
    except Exception as exc:
        raise ProviderError(
            "LiteLLM returned a malformed response object", code="malformed_response"
        ) from exc
    raise ProviderError(
        "LiteLLM returned an unsupported response object", code="malformed_response"
    )


def _usage(value: Any) -> Usage:
    if not isinstance(value, Mapping):
        return Usage()
    try:
        raw_input = value.get("prompt_tokens")
        if raw_input is None:
            raw_input = value.get("input_tokens")
        raw_output = value.get("completion_tokens")
        if raw_output is None:
            raw_output = value.get("output_tokens")
        raw_total = value.get("total_tokens")
    except Exception:
        return Usage()
    input_tokens = _nonnegative_integer(raw_input) or 0
    output_tokens = _nonnegative_integer(raw_output) or 0
    total_tokens = _nonnegative_integer(raw_total)
    return Usage(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=total_tokens if total_tokens is not None else input_tokens + output_tokens,
    )


def _nonnegative_integer(value: Any) -> int | None:
    try:
        if isinstance(value, bool) or value is None:
            return None
        if isinstance(value, int):
            return value if 0 <= value <= 1_000_000_000_000_000 else None
        if isinstance(value, float):
            return (
                int(value) if 0 <= value <= 1_000_000_000_000_000 and value.is_integer() else None
            )
        if isinstance(value, str):
            normalized = value.strip()
            if normalized.startswith("+"):
                normalized = normalized[1:]
            if normalized.isascii() and normalized.isdecimal() and len(normalized) <= 15:
                parsed = int(normalized)
                return parsed if parsed <= 1_000_000_000_000_000 else None
    except Exception:
        return None
    return None


def _bounded_metadata(value: Any, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise TypeError(f"{name} is not bounded text")
    return value


def _enforce_text_limit(content: str, maximum_bytes: int) -> None:
    """Bound UTF-8 response text without allocating a second full-size copy."""
    total = 0
    try:
        for offset in range(0, len(content), 8_192):
            total += len(content[offset : offset + 8_192].encode("utf-8"))
            if total > maximum_bytes:
                raise ProviderError(
                    f"Provider response exceeded the {maximum_bytes}-byte limit",
                    code="response_too_large",
                )
    except UnicodeEncodeError as exc:
        raise ProviderError(
            "LiteLLM returned malformed response text", code="malformed_response"
        ) from exc


def _classify_status(status: Any) -> tuple[str, bool]:
    if status in {401, 403}:
        return "authentication", False
    if status == 429:
        return "rate_limit", True
    if status == 408 or (isinstance(status, int) and status >= 500):
        return "provider_unavailable", True
    return "provider_error", False
