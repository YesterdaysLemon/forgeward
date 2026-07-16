"""OpenAI Chat Completions-compatible HTTP adapter."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any

import httpx

from forgeward.models import ChatMessage, CompletionRequest, CompletionResult, ProviderConfig, Usage
from forgeward.providers.base import ProviderError, chat_messages
from forgeward.providers.url_policy import validate_provider_base_url

_MAX_CREDENTIAL_CHARS = 16_384


class OpenAICompatibleProvider:
    """Call any endpoint implementing the common Chat Completions wire shape."""

    def __init__(self, config: ProviderConfig) -> None:
        self.config = config
        if config.base_url is None:
            raise ProviderError("Provider base_url is required", code="invalid_base_url")
        base_url = validate_provider_base_url(
            config.base_url, allow_insecure_http=config.allow_insecure_http
        )
        self.endpoint = f"{base_url.rstrip('/')}/chat/completions"

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
        ready = bool(result.content.strip())
        return ready, f"response received from {result.model}" if ready else "empty response"

    def complete(self, request: CompletionRequest) -> CompletionResult:
        headers = {"Content-Type": "application/json", "User-Agent": "forgeward/0.1"}
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
            headers["Authorization"] = f"Bearer {api_key}"

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
        payload: dict[str, Any] = {
            "model": request.model,
            "messages": messages,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }
        if request.response_schema and self.config.capabilities.json_schema:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "forgeward_deliverable",
                    "strict": True,
                    "schema": request.response_schema,
                },
            }
        try:
            with (
                httpx.Client(
                    timeout=self.config.timeout_seconds,
                    follow_redirects=False,
                    trust_env=False,
                ) as client,
                client.stream("POST", self.endpoint, headers=headers, json=payload) as response,
            ):
                status_code = response.status_code
                body = _read_limited_body(response, self.config.max_response_bytes)
        except ProviderError:
            raise
        except httpx.TimeoutException as exc:
            raise ProviderError(
                "Provider request timed out", code="timeout", retryable=True
            ) from exc
        except httpx.NetworkError as exc:
            raise ProviderError(
                "Provider network request failed", code="network", retryable=True
            ) from exc
        except httpx.TransportError as exc:
            raise ProviderError(
                "Provider transport failed", code="transport", retryable=True
            ) from exc

        if status_code >= 400:
            code, retryable = _status_code(status_code)
            raise ProviderError(
                f"Provider returned HTTP {status_code}",
                code=code,
                retryable=retryable,
            )
        try:
            data = json.loads(body)
            if not isinstance(data, Mapping):
                raise TypeError("response root is not an object")
            choices = data["choices"]
            choice = choices[0]
            content = _content_text(choice["message"]["content"])
            if api_key:
                content = content.replace(api_key, "[REDACTED]")
            usage = _usage(data.get("usage", {}))
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
            result = CompletionResult(
                content=content,
                model=model,
                finish_reason=finish_reason,
                usage=usage,
            )
        except (ValueError, KeyError, IndexError, TypeError, RecursionError, OverflowError) as exc:
            raise ProviderError(
                "Provider returned a malformed Chat Completions response",
                code="malformed_response",
            ) from exc
        return result


def _content_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts: list[str] = []
        for part in value:
            if isinstance(part, Mapping) and part.get("type") in {"text", "output_text"}:
                text = part.get("text")
                if isinstance(text, str):
                    parts.append(text)
        if parts:
            return "".join(parts)
    raise TypeError("message content is not text")


def _usage(value: Any) -> Usage:
    if not isinstance(value, Mapping):
        return Usage()
    input_tokens = _nonnegative_integer(value.get("prompt_tokens", value.get("input_tokens")))
    output_tokens = _nonnegative_integer(value.get("completion_tokens", value.get("output_tokens")))
    input_tokens = input_tokens or 0
    output_tokens = output_tokens or 0
    total_tokens = _nonnegative_integer(value.get("total_tokens"))
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
            candidate = value
        elif isinstance(value, float):
            if not value.is_integer():
                return None
            candidate = int(value)
        elif isinstance(value, str):
            normalized = value.strip().removeprefix("+")
            if not normalized.isascii() or not normalized.isdecimal() or len(normalized) > 15:
                return None
            candidate = int(normalized)
        else:
            return None
    except (ValueError, OverflowError):
        return None
    return candidate if 0 <= candidate <= 1_000_000_000_000_000 else None


def _bounded_metadata(value: Any, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise TypeError(f"{name} is not bounded text")
    return value


def _status_code(status: int) -> tuple[str, bool]:
    if status in {401, 403}:
        return "authentication", False
    if status == 429:
        return "rate_limit", True
    if status == 400:
        return "invalid_request", False
    if status == 408 or status >= 500:
        return "provider_unavailable", True
    return "provider_error", False


def _read_limited_body(response: httpx.Response, maximum_bytes: int) -> bytes:
    """Read HTTP-decoded bytes without allowing an unbounded response body."""
    body = bytearray()
    chunk_size = min(64 * 1_024, maximum_bytes + 1)
    for chunk in response.iter_bytes(chunk_size=chunk_size):
        if len(chunk) > maximum_bytes - len(body):
            raise ProviderError(
                f"Provider response exceeded the {maximum_bytes}-byte limit",
                code="response_too_large",
            )
        body.extend(chunk)
    return bytes(body)
