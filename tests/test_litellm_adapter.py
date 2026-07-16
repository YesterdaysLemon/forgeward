from __future__ import annotations

import builtins
import sys
from types import SimpleNamespace
from typing import Any

import pytest

from forgeward.models import (
    ChatMessage,
    CompletionRequest,
    ProviderCapabilities,
    ProviderConfig,
)
from forgeward.providers import ProviderError, create_provider
from forgeward.providers.litellm_adapter import LiteLLMProvider


def _config(**updates: Any) -> ProviderConfig:
    values: dict[str, Any] = {
        "adapter": "litellm",
        "model": "anthropic/example",
        "capabilities": ProviderCapabilities(json_schema=True),
    }
    values.update(updates)
    return ProviderConfig(**values)


def _request() -> CompletionRequest:
    return CompletionRequest(
        model="anthropic/example",
        messages=[
            ChatMessage(role="developer", content="policy"),
            ChatMessage(role="user", content="hello"),
        ],
        response_schema={"type": "object", "properties": {}},
    )


def _success() -> dict[str, Any]:
    return {
        "model": "anthropic/example-2026",
        "choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
    }


def test_factory_creates_litellm_provider() -> None:
    assert isinstance(create_provider(_config()), LiteLLMProvider)


@pytest.mark.parametrize(
    "base_url",
    [
        "not-a-url",
        "file:///tmp/gateway",
        "https://user:password@gateway.example/v1",
        "https://gateway.example/v1?credential=hidden",
    ],
)
def test_litellm_rejects_invalid_or_credentialed_gateway_url(base_url: str) -> None:
    with pytest.raises(ProviderError) as raised:
        LiteLLMProvider(_config(base_url=base_url))

    assert raised.value.code == "invalid_base_url"


def test_litellm_rejects_remote_cleartext_gateway_unless_opted_in() -> None:
    with pytest.raises(ProviderError) as raised:
        LiteLLMProvider(_config(base_url="http://gateway.example/v1"))

    assert raised.value.code == "insecure_base_url"
    provider = LiteLLMProvider(
        _config(base_url="http://gateway.example/v1", allow_insecure_http=True)
    )
    assert provider.base_url == "http://gateway.example/v1"


def test_litellm_requires_opt_in_even_for_loopback_http_gateway() -> None:
    with pytest.raises(ProviderError) as raised:
        LiteLLMProvider(_config(base_url="http://127.0.0.1:4000/v1"))
    assert raised.value.code == "insecure_base_url"

    provider = LiteLLMProvider(
        _config(base_url="http://127.0.0.1:4000/v1", allow_insecure_http=True)
    )
    assert provider.base_url == "http://127.0.0.1:4000/v1"


def test_completion_normalizes_response_and_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def completion(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return _success()

    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=completion))
    result = LiteLLMProvider(_config(base_url="https://gateway.example/v1")).complete(_request())

    assert result.content == "{}"
    assert result.model == "anthropic/example-2026"
    assert result.usage.total_tokens == 5
    assert captured["messages"][0]["role"] == "system"
    assert captured["api_base"] == "https://gateway.example/v1"
    assert captured["num_retries"] == 0
    assert captured["drop_params"] is False
    assert captured["response_format"]["type"] == "json_schema"


def test_completion_embeds_schema_when_transport_schema_is_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def completion(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return _success()

    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=completion))
    config = _config(capabilities=ProviderCapabilities(json_schema=False))

    LiteLLMProvider(config).complete(_request())

    assert "response_format" not in captured
    assert "<response-json-schema>" in captured["messages"][0]["content"]
    assert '"properties"' in captured["messages"][0]["content"]


def test_completion_passes_indirected_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def completion(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return _success()

    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=completion))
    monkeypatch.setenv("TEST_LLM_KEY", "not-a-real-secret")
    LiteLLMProvider(_config(api_key_env="TEST_LLM_KEY")).complete(_request())
    assert captured["api_key"] == "not-a-real-secret"


def test_litellm_exactly_redacts_opaque_credential_in_both_directions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    opaque_value = "opaque-native-credential-without-known-prefix"

    def completion(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        payload = _success()
        payload["model"] = f"native-{opaque_value}"
        payload["choices"][0]["message"]["content"] = f"result {opaque_value}"
        payload["choices"][0]["finish_reason"] = f"stop-{opaque_value}"
        return payload

    request = _request()
    request.messages[1].content = f"before {opaque_value} after"
    monkeypatch.setenv("OPAQUE_NATIVE_KEY", opaque_value)
    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=completion))
    result = LiteLLMProvider(_config(api_key_env="OPAQUE_NATIVE_KEY")).complete(request)

    assert opaque_value not in str(captured["messages"])
    assert opaque_value not in result.content
    assert opaque_value not in result.model
    assert opaque_value not in (result.finish_reason or "")


def test_missing_credential_fails_before_call(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(
        sys.modules,
        "litellm",
        SimpleNamespace(completion=lambda **_: pytest.fail("must not call LiteLLM")),
    )
    monkeypatch.delenv("MISSING_LLM_KEY", raising=False)
    with pytest.raises(ProviderError, match="MISSING_LLM_KEY") as raised:
        LiteLLMProvider(_config(api_key_env="MISSING_LLM_KEY")).complete(_request())
    assert raised.value.code == "missing_credential"


def test_litellm_rejects_pathologically_large_configured_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        sys.modules,
        "litellm",
        SimpleNamespace(completion=lambda **_: pytest.fail("must not call LiteLLM")),
    )
    monkeypatch.setenv("HUGE_NATIVE_KEY", "x" * 16_385)

    with pytest.raises(ProviderError) as raised:
        LiteLLMProvider(_config(api_key_env="HUGE_NATIVE_KEY")).complete(_request())

    assert raised.value.code == "invalid_credential"


def test_missing_optional_dependency_has_actionable_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_import = builtins.__import__

    def rejecting_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "litellm":
            raise ImportError("synthetic missing dependency")
        return original_import(name, *args, **kwargs)

    monkeypatch.delitem(sys.modules, "litellm", raising=False)
    monkeypatch.setattr(builtins, "__import__", rejecting_import)
    with pytest.raises(ProviderError, match="`litellm` extra") as raised:
        LiteLLMProvider(_config()).complete(_request())
    assert raised.value.code == "missing_dependency"


@pytest.mark.parametrize(
    ("status", "code", "retryable"),
    [
        (401, "authentication", False),
        (429, "rate_limit", True),
        (503, "provider_unavailable", True),
    ],
)
def test_errors_are_normalized_without_upstream_message(
    monkeypatch: pytest.MonkeyPatch, status: int, code: str, retryable: bool
) -> None:
    class UpstreamFailure(RuntimeError):
        status_code = status

    def completion(**_: Any) -> dict[str, Any]:
        raise UpstreamFailure("secret upstream response")

    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=completion))
    with pytest.raises(ProviderError) as raised:
        LiteLLMProvider(_config()).complete(_request())
    assert raised.value.code == code
    assert raised.value.retryable is retryable
    assert "secret upstream response" not in str(raised.value)


def test_model_dump_response_and_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    response = SimpleNamespace(model_dump=lambda: _success())
    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=lambda **_: response))
    ok, detail = LiteLLMProvider(_config()).probe()
    assert ok is True
    assert "anthropic/example-2026" in detail


def test_probe_reports_provider_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=lambda **_: _success()))
    monkeypatch.delenv("MISSING_LLM_KEY", raising=False)

    ok, detail = LiteLLMProvider(_config(api_key_env="MISSING_LLM_KEY")).probe()

    assert ok is False
    assert detail.startswith("missing_credential:")


def test_json_response_with_no_finish_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = _success()
    del payload["choices"][0]["finish_reason"]
    response = SimpleNamespace(json=lambda: __import__("json").dumps(payload))
    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=lambda **_: response))

    result = LiteLLMProvider(_config()).complete(_request())

    assert result.finish_reason is None


def test_json_response_may_return_mapping(monkeypatch: pytest.MonkeyPatch) -> None:
    response = SimpleNamespace(json=lambda: _success())
    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=lambda **_: response))

    result = LiteLLMProvider(_config()).complete(_request())

    assert result.content == "{}"


@pytest.mark.parametrize(
    "response",
    [
        SimpleNamespace(json=lambda: "not-json"),
        SimpleNamespace(model_dump=lambda: (_ for _ in ()).throw(RuntimeError("broken dump"))),
        SimpleNamespace(json=lambda: (_ for _ in ()).throw(RuntimeError("broken json"))),
    ],
)
def test_response_conversion_failures_are_normalized(
    monkeypatch: pytest.MonkeyPatch, response: object
) -> None:
    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=lambda **_: response))

    with pytest.raises(ProviderError, match="malformed response object") as raised:
        LiteLLMProvider(_config()).complete(_request())

    assert raised.value.code == "malformed_response"


def test_unsupported_response_object_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(
        sys.modules, "litellm", SimpleNamespace(completion=lambda **_: SimpleNamespace())
    )

    with pytest.raises(ProviderError, match="unsupported response object") as raised:
        LiteLLMProvider(_config()).complete(_request())

    assert raised.value.code == "malformed_response"


def test_unclassified_exception_is_not_retryable(monkeypatch: pytest.MonkeyPatch) -> None:
    def completion(**_: Any) -> dict[str, Any]:
        raise RuntimeError("synthetic failure")

    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=completion))

    with pytest.raises(ProviderError) as raised:
        LiteLLMProvider(_config()).complete(_request())

    assert raised.value.code == "provider_error"
    assert raised.value.retryable is False


def test_malformed_response_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(
        sys.modules, "litellm", SimpleNamespace(completion=lambda **_: {"choices": []})
    )
    with pytest.raises(ProviderError, match="malformed") as raised:
        LiteLLMProvider(_config()).complete(_request())
    assert raised.value.code == "malformed_response"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda body: body.update({"model": "m" * 501}),
        lambda body: body["choices"][0].update({"finish_reason": "f" * 101}),
    ],
)
def test_litellm_rejects_oversized_response_metadata(
    monkeypatch: pytest.MonkeyPatch, mutation: object
) -> None:
    payload = _success()
    mutation(payload)  # type: ignore[operator]
    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=lambda **_: payload))

    with pytest.raises(ProviderError) as raised:
        LiteLLMProvider(_config()).complete(_request())

    assert raised.value.code == "malformed_response"


def test_litellm_rejects_oversized_utf8_response_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _success()
    # Character length is below the limit, but UTF-8 byte length is above it.
    payload["choices"][0]["message"]["content"] = "é" * 600
    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=lambda **_: payload))

    with pytest.raises(ProviderError) as raised:
        LiteLLMProvider(_config(max_response_bytes=1_024)).complete(_request())

    assert raised.value.code == "response_too_large"


@pytest.mark.parametrize(
    ("usage", "expected"),
    [
        ({"prompt_tokens": "4", "completion_tokens": 2.0, "total_tokens": -1}, (4, 2, 6)),
        ({"prompt_tokens": "not-numeric", "completion_tokens": -8, "total_tokens": []}, (0, 0, 0)),
        ({"input_tokens": True, "output_tokens": 1.5, "total_tokens": None}, (0, 0, 0)),
        ("malformed", (0, 0, 0)),
        ({"prompt_tokens": float("inf"), "completion_tokens": True}, (0, 0, 0)),
    ],
)
def test_litellm_normalizes_untrusted_usage_values(
    monkeypatch: pytest.MonkeyPatch, usage: object, expected: tuple[int, int, int]
) -> None:
    payload = _success()
    payload["usage"] = usage
    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=lambda **_: payload))

    result = LiteLLMProvider(_config()).complete(_request())

    assert (
        result.usage.input_tokens,
        result.usage.output_tokens,
        result.usage.total_tokens,
    ) == expected
