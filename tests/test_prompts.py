from __future__ import annotations

import json
from pathlib import Path

import pytest

from forgeward.models import RoleSpec
from forgeward.prompts import build_request, load_role_prompt, parse_deliverable
from forgeward.providers import ProviderError


def _role(prompt: str = "builder.md") -> RoleSpec:
    return RoleSpec(
        id="builder",
        mission="Build only the approved and bounded implementation.",
        prompt=prompt,
        allowed_tools=["repository.read", "workspace.propose"],
    )


def _deliverable() -> dict[str, object]:
    return {
        "summary": "Implemented the requested behavior.",
        "artifact": "# Build note\n\nEvidence-backed work.",
        "acceptance_criteria": ["The behavior is tested."],
        "proposed_changes": [
            {
                "operation": "create",
                "path": "src/new.py",
                "content": "VALUE = 1\n",
                "rationale": "Adds the requested capability.",
            }
        ],
        "findings": [],
        "proposed_transition": "continue",
    }


def test_load_role_prompt_reads_only_beneath_prompt_root(project: Path) -> None:
    content = load_role_prompt(project, _role())
    assert "Implement only the approved objective" in content

    with pytest.raises(ProviderError) as error:
        load_role_prompt(project, _role("../firm.yaml"))
    assert error.value.code == "unsafe_prompt"


def test_load_role_prompt_rejects_missing_file(project: Path) -> None:
    with pytest.raises(ProviderError) as error:
        load_role_prompt(project, _role("missing.md"))
    assert error.value.code == "missing_prompt"


def test_load_role_prompt_rejects_oversized_and_device_named_paths(project: Path) -> None:
    oversized = project / ".forgeward" / "prompts" / "oversized.md"
    oversized.write_text("x" * 64_001, encoding="utf-8")

    with pytest.raises(ProviderError) as error:
        load_role_prompt(project, _role("oversized.md"))
    assert error.value.code == "prompt_too_large"

    with pytest.raises(ProviderError) as error:
        load_role_prompt(project, _role("NUL.md"))
    assert error.value.code == "unsafe_prompt"


def test_load_role_prompt_rejects_symlink_even_when_target_is_in_prompt_root(project: Path) -> None:
    prompt_root = project / ".forgeward" / "prompts"
    link = prompt_root / "linked.md"
    try:
        link.symlink_to(prompt_root / "builder.md")
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    with pytest.raises(ProviderError) as error:
        load_role_prompt(project, _role("linked.md"))
    assert error.value.code == "unsafe_prompt"


def test_build_request_separates_policy_from_untrusted_context(project: Path) -> None:
    request = build_request(
        root=project,
        role=_role(),
        model="route-model",
        objective="Add a safe parser",
        repository_context=(
            '<repository-file path="README.md" trust="untrusted">data</repository-file>'
        ),
        prior_evidence="# Requirements\nDo the bounded thing.",
        max_tokens=777,
    )

    assert request.model == "route-model"
    assert [message.role for message in request.messages] == ["system", "user"]
    assert "untrusted proposal engine" in request.messages[0].content
    assert "Implement only the approved objective" in request.messages[0].content
    assert '<prior-evidence trust="untrusted-model-output">' in request.messages[1].content
    assert '<repository-file path="README.md" trust="untrusted">' in request.messages[1].content
    assert request.response_schema is not None
    assert request.response_schema["additionalProperties"] is False
    assert request.temperature == 0.2
    assert request.max_tokens == 777
    assert request.metadata == {"role": "builder", "objective": "Add a safe parser"}


def test_build_request_accepts_max_policy_context_envelope(project: Path) -> None:
    request = build_request(
        root=project,
        role=_role(),
        model="route-model",
        objective="o" * 20_000,
        repository_context="r" * 2_600_000,
        prior_evidence="e" * 80_000,
    )

    assert len(request.messages[1].content) < 3_000_000


@pytest.mark.parametrize(
    "render",
    [
        lambda value: value,
        lambda value: f"```json\n{value}\n```",
        lambda value: f"```JSON\n{value}\n```",
        lambda value: f"Here is the result:\n{value}\nDone.",
    ],
)
def test_parse_deliverable_accepts_plain_fenced_and_embedded_json(render: object) -> None:
    encoded = json.dumps(_deliverable())
    parsed = parse_deliverable(render(encoded))  # type: ignore[operator]

    assert parsed.summary == "Implemented the requested behavior."
    assert parsed.proposed_changes[0].path == "src/new.py"
    assert parsed.acceptance_criteria == ["The behavior is tested."]


def test_parse_deliverable_rejects_response_without_json_object() -> None:
    with pytest.raises(ProviderError) as error:
        parse_deliverable("I cannot produce that output")
    assert error.value.code == "invalid_deliverable"
    assert "did not contain" in str(error.value)


def test_parse_deliverable_rejects_malformed_json_object() -> None:
    with pytest.raises(ProviderError) as error:
        parse_deliverable('prefix {"summary": invalid} suffix')
    assert error.value.code == "invalid_deliverable"
    assert "invalid JSON" in str(error.value)


@pytest.mark.parametrize(
    "content",
    [
        "[" * 1_500 + "]" * 1_500,
        (
            '{"summary":"ok","artifact":"ok","acceptance_criteria":[],"proposed_changes":[],'
            '"findings":[],"proposed_transition":' + "9" * 5_000 + "}"
        ),
    ],
)
def test_parse_deliverable_normalizes_pathological_json(content: str) -> None:
    with pytest.raises(ProviderError) as error:
        parse_deliverable(content)

    assert error.value.code == "invalid_deliverable"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.pop("summary"),
        lambda value: value.update({"unexpected": True}),
        lambda value: value.update({"summary": ""}),
        lambda value: value["proposed_changes"][0].update({"path": "/absolute.py"}),
    ],
)
def test_parse_deliverable_enforces_strict_typed_schema(mutation: object) -> None:
    body = _deliverable()
    mutation(body)  # type: ignore[operator]

    with pytest.raises(ProviderError) as error:
        parse_deliverable(json.dumps(body))
    assert error.value.code == "invalid_deliverable"
    assert "deliverable schema" in str(error.value)
