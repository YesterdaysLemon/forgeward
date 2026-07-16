from __future__ import annotations

import gzip
import json

import httpx
import pytest
import respx

import forgeward.providers.openai_compatible as openai_module
from forgeward.models import (
    ChatMessage,
    CompletionRequest,
    ProviderCapabilities,
    ProviderConfig,
)
from forgeward.providers import ProviderError, create_provider
from forgeward.providers.demo import DemoProvider
from forgeward.providers.openai_compatible import OpenAICompatibleProvider


def _config(**overrides: object) -> ProviderConfig:
    values: dict[str, object] = {
        "adapter": "openai-compatible",
        "base_url": "https://models.example.test/v1/",
        "model": "test-model",
        "timeout_seconds": 3,
    }
    values.update(overrides)
    return ProviderConfig.model_validate(values)


def _request(*, schema: bool = True) -> CompletionRequest:
    return CompletionRequest(
        model="requested-model",
        messages=[
            ChatMessage(role="developer", content="system policy"),
            ChatMessage(role="user", content="hello"),
        ],
        response_schema={"type": "object", "properties": {"answer": {"type": "string"}}}
        if schema
        else None,
        temperature=0.25,
        max_tokens=321,
    )


def _success_response(*, content: object = "answer") -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "id": "completion-1",
            "model": "served-model",
            "choices": [
                {
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 7, "completion_tokens": 5, "total_tokens": 12},
        },
    )


def test_provider_config_defaults_to_secure_bounded_transport() -> None:
    config = _config()

    assert config.allow_insecure_http is False
    assert config.max_response_bytes == 2_000_000
    with pytest.raises(ValueError):
        _config(max_response_bytes=0)
    with pytest.raises(ValueError):
        _config(max_response_bytes=20_000_001)
    with pytest.raises(ValueError):
        _config(api_key_env="BAD\x00NAME")


def test_openai_compatible_provider_uses_chat_completions_wire_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FORGEWARD_TEST_KEY", "test-secret-value")
    provider = OpenAICompatibleProvider(_config(api_key_env="FORGEWARD_TEST_KEY"))
    with respx.mock(assert_all_called=True) as mock:
        route = mock.post("https://models.example.test/v1/chat/completions").mock(
            return_value=_success_response()
        )
        result = provider.complete(_request())

    assert result.content == "answer"
    assert result.model == "served-model"
    assert result.finish_reason == "stop"
    assert result.usage.model_dump() == {
        "input_tokens": 7,
        "output_tokens": 5,
        "total_tokens": 12,
    }
    sent = json.loads(route.calls.last.request.content)
    assert sent["model"] == "requested-model"
    assert sent["messages"] == [
        {"role": "system", "content": "system policy"},
        {"role": "user", "content": "hello"},
    ]
    assert sent["temperature"] == 0.25
    assert sent["max_tokens"] == 321
    assert sent["response_format"]["type"] == "json_schema"
    assert sent["response_format"]["json_schema"]["strict"] is True
    assert route.calls.last.request.headers["authorization"] == "Bearer test-secret-value"
    assert route.calls.last.request.headers["user-agent"] == "forgeward/0.1"


def test_openai_transport_ignores_ambient_proxy_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}
    original_client = httpx.Client

    def client(*args: object, **kwargs: object) -> httpx.Client:
        observed.update(kwargs)
        return original_client(*args, **kwargs)

    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setattr(openai_module.httpx, "Client", client)
    provider = OpenAICompatibleProvider(_config(base_url="http://127.0.0.1:11434/v1"))
    with respx.mock(assert_all_called=True) as mock:
        mock.post(provider.endpoint).mock(return_value=_success_response())
        provider.complete(_request())

    assert observed["trust_env"] is False


def test_provider_exactly_redacts_opaque_configured_credential_in_both_directions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opaque_value = "opaque-credential-sentinel-without-known-prefix"
    monkeypatch.setenv("OPAQUE_LLM_KEY", opaque_value)
    request = _request(schema=False)
    request.messages[1].content = f"before {opaque_value} after"
    response = _success_response(content=f"result {opaque_value}")
    body = json.loads(response.content)
    body["model"] = f"served-{opaque_value}"
    body["choices"][0]["finish_reason"] = f"stop-{opaque_value}"
    provider = OpenAICompatibleProvider(_config(api_key_env="OPAQUE_LLM_KEY"))
    with respx.mock(assert_all_called=True) as mock:
        route = mock.post(provider.endpoint).mock(return_value=httpx.Response(200, json=body))
        result = provider.complete(request)

    sent = json.loads(route.calls.last.request.content)
    assert opaque_value not in json.dumps(sent)
    assert opaque_value not in result.content
    assert opaque_value not in result.model
    assert opaque_value not in (result.finish_reason or "")
    assert "[REDACTED]" in result.content


def test_provider_omits_schema_when_route_does_not_support_it() -> None:
    capabilities = ProviderCapabilities(json_schema=False)
    provider = OpenAICompatibleProvider(_config(capabilities=capabilities))
    with respx.mock(assert_all_called=True) as mock:
        route = mock.post("https://models.example.test/v1/chat/completions").mock(
            return_value=_success_response()
        )
        provider.complete(_request())

    sent = json.loads(route.calls.last.request.content)
    assert "response_format" not in sent
    assert sent["messages"][0]["role"] == "system"
    assert "<response-json-schema>" in sent["messages"][0]["content"]
    assert '"answer"' in sent["messages"][0]["content"]


def test_provider_accepts_openai_content_parts_and_alternate_usage_names() -> None:
    response = httpx.Response(
        200,
        json={
            "choices": [
                {
                    "message": {
                        "content": [
                            {"type": "text", "text": "hello "},
                            {"type": "image", "image_url": "ignored"},
                            {"type": "output_text", "text": "world"},
                        ]
                    }
                }
            ],
            "usage": {"input_tokens": 2, "output_tokens": 3},
        },
    )
    provider = OpenAICompatibleProvider(_config())
    with respx.mock(assert_all_called=True) as mock:
        mock.post(provider.endpoint).mock(return_value=response)
        result = provider.complete(_request(schema=False))

    assert result.content == "hello world"
    assert result.model == "requested-model"
    assert result.finish_reason is None
    assert result.usage.total_tokens == 5


def test_provider_requires_configured_credential_before_network_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FORGEWARD_MISSING_KEY", raising=False)
    provider = OpenAICompatibleProvider(_config(api_key_env="FORGEWARD_MISSING_KEY"))

    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(provider.endpoint).mock(return_value=_success_response())
        with pytest.raises(ProviderError) as error:
            provider.complete(_request())

    assert error.value.code == "missing_credential"
    assert error.value.retryable is False
    assert not route.called


@pytest.mark.parametrize(
    "base_url",
    [
        "models.example.test/v1",
        "file:///tmp/models",
        "https:///missing-host",
        "https://user:password@models.example.test/v1",
        "https://@models.example.test/v1",
        "https://models.example.test/v1?secret=value",
        "https://models.example.test/v1#fragment",
        "https://models.example.test:invalid/v1",
        "https://models.example.test\\v1",
    ],
)
def test_provider_rejects_invalid_or_credentialed_base_urls(base_url: str) -> None:
    with pytest.raises(ProviderError) as error:
        OpenAICompatibleProvider(_config(base_url=base_url))

    assert error.value.code == "invalid_base_url"


def test_provider_rejects_remote_cleartext_http_unless_explicitly_allowed() -> None:
    with pytest.raises(ProviderError) as error:
        OpenAICompatibleProvider(_config(base_url="http://models.example.test/v1"))

    assert error.value.code == "insecure_base_url"
    provider = OpenAICompatibleProvider(
        _config(base_url="http://models.example.test/v1", allow_insecure_http=True)
    )
    assert provider.endpoint == "http://models.example.test/v1/chat/completions"


@pytest.mark.parametrize(
    "base_url",
    [
        "http://localhost:11434/v1",
        "http://worker.localhost:11434/v1",
        "http://127.0.0.1:11434/v1",
        "http://127.99.42.7:11434/v1",
        "http://[::1]:11434/v1",
        "http://[::ffff:127.0.0.1]:11434/v1",
    ],
)
def test_provider_allows_loopback_http_by_default(base_url: str) -> None:
    assert OpenAICompatibleProvider(_config(base_url=base_url)).endpoint.endswith(
        "/v1/chat/completions"
    )


def test_provider_limits_http_decoded_response_bytes_before_json_parsing() -> None:
    provider = OpenAICompatibleProvider(_config(max_response_bytes=1_024))
    raw_body = json.dumps(
        {
            "choices": [{"message": {"content": "x" * 4_096}}],
            "model": "compressed-model",
        }
    ).encode()
    compressed_body = gzip.compress(raw_body)
    assert len(compressed_body) < provider.config.max_response_bytes < len(raw_body)

    with respx.mock(assert_all_called=True) as mock:
        mock.post(provider.endpoint).mock(
            return_value=httpx.Response(
                200,
                content=compressed_body,
                headers={"content-encoding": "gzip", "content-type": "application/json"},
            )
        )
        with pytest.raises(ProviderError) as error:
            provider.complete(_request())

    assert error.value.code == "response_too_large"


@pytest.mark.parametrize(
    ("status", "expected_code", "retryable"),
    [
        (400, "invalid_request", False),
        (401, "authentication", False),
        (403, "authentication", False),
        (404, "provider_error", False),
        (408, "provider_unavailable", True),
        (429, "rate_limit", True),
        (500, "provider_unavailable", True),
        (503, "provider_unavailable", True),
    ],
)
def test_provider_maps_http_errors(status: int, expected_code: str, retryable: bool) -> None:
    provider = OpenAICompatibleProvider(_config())
    with respx.mock(assert_all_called=True) as mock:
        mock.post(provider.endpoint).mock(
            return_value=httpx.Response(
                status,
                json={"error": {"message": "api_key=do-not-echo-this-value"}},
            )
        )
        with pytest.raises(ProviderError) as error:
            provider.complete(_request())

    assert error.value.code == expected_code
    assert error.value.retryable is retryable
    assert "do-not-echo-this-value" not in str(error.value)
    assert str(error.value) == f"Provider returned HTTP {status}"


@pytest.mark.parametrize(
    ("exception", "code"),
    [
        (httpx.ReadTimeout("slow provider"), "timeout"),
        (httpx.ConnectError("offline provider"), "network"),
        (httpx.RemoteProtocolError("invalid upstream protocol"), "transport"),
    ],
)
def test_provider_normalizes_transport_failures(exception: Exception, code: str) -> None:
    provider = OpenAICompatibleProvider(_config())
    with respx.mock(assert_all_called=True) as mock:
        mock.post(provider.endpoint).mock(side_effect=exception)
        with pytest.raises(ProviderError) as error:
            provider.complete(_request())

    assert error.value.code == code
    assert error.value.retryable is True


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"choices": []},
        {"choices": [{"message": {}}]},
        {"choices": [{"message": {"content": [{"type": "image"}]}}]},
        {"choices": "not-a-list"},
    ],
)
def test_provider_rejects_malformed_success_response(body: object) -> None:
    provider = OpenAICompatibleProvider(_config())
    with respx.mock(assert_all_called=True) as mock:
        mock.post(provider.endpoint).mock(return_value=httpx.Response(200, json=body))
        with pytest.raises(ProviderError) as error:
            provider.complete(_request())

    assert error.value.code == "malformed_response"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda body: body.update({"model": "m" * 501}),
        lambda body: body["choices"][0].update({"finish_reason": "f" * 101}),
    ],
)
def test_provider_rejects_oversized_response_metadata(mutation: object) -> None:
    body = json.loads(_success_response().content)
    mutation(body)  # type: ignore[operator]
    provider = OpenAICompatibleProvider(_config())
    with respx.mock(assert_all_called=True) as mock:
        mock.post(provider.endpoint).mock(return_value=httpx.Response(200, json=body))
        with pytest.raises(ProviderError) as error:
            provider.complete(_request())

    assert error.value.code == "malformed_response"


@pytest.mark.parametrize(
    ("usage", "expected"),
    [
        ({"prompt_tokens": float("inf"), "completion_tokens": True}, (0, 0, 0)),
        ({"prompt_tokens": -1, "completion_tokens": 2, "total_tokens": -5}, (0, 2, 2)),
        ({"input_tokens": "4", "output_tokens": 3.0}, (4, 3, 7)),
    ],
)
def test_provider_normalizes_untrusted_usage_values(
    usage: object, expected: tuple[int, int, int]
) -> None:
    body = json.loads(_success_response().content)
    body["usage"] = usage
    provider = OpenAICompatibleProvider(_config())
    with respx.mock(assert_all_called=True) as mock:
        mock.post(provider.endpoint).mock(
            return_value=httpx.Response(200, content=json.dumps(body, allow_nan=True).encode())
        )
        result = provider.complete(_request())

    assert (
        result.usage.input_tokens,
        result.usage.output_tokens,
        result.usage.total_tokens,
    ) == expected


def test_provider_rejects_pathologically_large_configured_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HUGE_LLM_KEY", "x" * 16_385)
    provider = OpenAICompatibleProvider(_config(api_key_env="HUGE_LLM_KEY"))

    with pytest.raises(ProviderError) as error:
        provider.complete(_request())

    assert error.value.code == "invalid_credential"


def test_provider_probe_reports_readiness_and_normalized_failure() -> None:
    provider = OpenAICompatibleProvider(_config())
    with respx.mock(assert_all_called=True) as mock:
        mock.post(provider.endpoint).mock(return_value=_success_response(content="ready"))
        assert provider.probe() == (True, "response received from served-model")

    with respx.mock(assert_all_called=True) as mock:
        mock.post(provider.endpoint).mock(return_value=httpx.Response(503))
        ok, detail = provider.probe()
    assert ok is False
    assert detail.startswith("provider_unavailable:")


def test_demo_provider_is_deterministic_and_role_specific() -> None:
    provider = DemoProvider(ProviderConfig(adapter="demo", model="offline-test"))
    product = provider.complete(
        CompletionRequest(
            model="offline-test",
            messages=[],
            metadata={"role": "product", "objective": "ship safely"},
        )
    )
    repeated = provider.complete(
        CompletionRequest(
            model="offline-test",
            messages=[],
            metadata={"role": "product", "objective": "ship safely"},
        )
    )
    security = provider.complete(
        CompletionRequest(
            model="offline-test",
            messages=[],
            metadata={"role": "security", "objective": "ship safely"},
        )
    )

    assert product == repeated
    product_body = json.loads(product.content)
    security_body = json.loads(security.content)
    assert len(product_body["acceptance_criteria"]) == 3
    assert product_body["proposed_changes"] == []
    assert security_body["findings"][0]["severity"] == "info"
    assert provider.probe()[0] is True


def test_provider_factory_selects_adapters_and_rejects_unknown_adapter() -> None:
    assert isinstance(create_provider(ProviderConfig(adapter="demo")), DemoProvider)
    assert isinstance(create_provider(_config()), OpenAICompatibleProvider)

    unsupported = ProviderConfig.model_construct(adapter="unknown", model="x")
    with pytest.raises(ProviderError) as error:
        create_provider(unsupported)
    assert error.value.code == "unsupported_adapter"
