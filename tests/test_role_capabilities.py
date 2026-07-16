from __future__ import annotations

import json
from pathlib import Path

import pytest

import forgeward.context as context_module
import forgeward.orchestrator as orchestrator_module
from forgeward.models import (
    CompletionRequest,
    CompletionResult,
    ForgeWardConfig,
    RoleSpec,
    RunState,
)
from forgeward.orchestrator import ForgeWardEngine, OrchestrationError
from forgeward.reporting import markdown_report


class CapturingProvider:
    def __init__(self, *, builder_content_size: int = 24) -> None:
        self.builder_content_size = builder_content_size
        self.requests: list[CompletionRequest] = []

    def complete(self, request: CompletionRequest) -> CompletionResult:
        self.requests.append(request)
        role = request.metadata["role"]
        proposed_changes: list[dict[str, str]] = []
        if role == "builder":
            proposed_changes = [
                {
                    "operation": "create",
                    "path": "src/review-sentinel.py",
                    "content": "REVIEW_SENTINEL_" + "x" * self.builder_content_size,
                    "rationale": "Exercise independent review evidence.",
                }
            ]
        body = {
            "summary": f"{role} completed its bounded assignment.",
            "artifact": f"# {role}\n\nCaptured role artifact.\n",
            "acceptance_criteria": ["The review sentinel is handled safely."],
            "proposed_changes": proposed_changes,
            "findings": [
                {
                    "severity": "low",
                    "title": f"LOW_FINDING_{role}",
                    "detail": "LOW_FINDING_DETAIL_SURVIVES",
                    "evidence": "LOW_FINDING_EVIDENCE_SURVIVES",
                }
            ],
            "proposed_transition": None,
        }
        return CompletionResult(
            content=json.dumps(body),
            model="capture-model",
            finish_reason="stop",
        )

    def probe(self) -> tuple[bool, str]:
        return True, "capture provider ready"


def _engine_with_capture(
    project: Path,
    config: ForgeWardConfig,
    monkeypatch: pytest.MonkeyPatch,
    *,
    builder_content_size: int = 24,
) -> tuple[ForgeWardEngine, CapturingProvider]:
    provider = CapturingProvider(builder_content_size=builder_content_size)
    monkeypatch.setattr(orchestrator_module, "create_provider", lambda _config: provider)
    return ForgeWardEngine(project, config), provider


def _request_text(request: CompletionRequest) -> str:
    return "\n".join(message.content for message in request.messages)


def test_repository_context_is_withheld_or_granted_per_role_capability(
    project: Path, config: ForgeWardConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    (project / "source-sentinel.txt").write_text("SOURCE_DISCLOSURE_SENTINEL", encoding="utf-8")
    (project / ".npmrc").write_text("NPM_CONTEXT_SECRET_SENTINEL", encoding="utf-8")
    (project / "redacted-source.txt").write_text(
        "password=CONTENT_CONTEXT_SECRET_SENTINEL", encoding="utf-8"
    )
    monkeypatch.setattr(
        context_module,
        "_candidate_paths",
        lambda _root: (
            ["source-sentinel.txt", ".npmrc", "redacted-source.txt"],
            {"source": "test", "status": "ok", "scope": "tracked"},
        ),
    )
    engine, provider = _engine_with_capture(project, config, monkeypatch)

    withheld = engine.store.create(
        "Check withheld source context", provider="demo", apply_changes=False, base_commit=None
    )
    engine._call_role(withheld, "scrum-master", "planning/scrum-capture.md")
    withheld_request = provider.requests[-1]
    withheld_manifest = json.loads(
        engine.store.read_artifact(withheld, "artifacts/context/scrum-master-1.json")
    )

    assert "SOURCE_DISCLOSURE_SENTINEL" not in _request_text(withheld_request)
    assert withheld_manifest["access"] == "withheld-by-role-policy"
    assert withheld_manifest["files"] == []

    granted = engine.store.create(
        "Check granted source context", provider="demo", apply_changes=False, base_commit=None
    )
    engine._call_role(granted, "product", "planning/product-capture.md")
    granted_request = provider.requests[-1]
    granted_manifest = json.loads(
        engine.store.read_artifact(granted, "artifacts/context/product-1.json")
    )

    assert "SOURCE_DISCLOSURE_SENTINEL" in _request_text(granted_request)
    assert "NPM_CONTEXT_SECRET_SENTINEL" not in _request_text(granted_request)
    assert "CONTENT_CONTEXT_SECRET_SENTINEL" not in _request_text(granted_request)
    assert "[REDACTED]" in _request_text(granted_request)
    assert granted_manifest["access"] == "granted"
    assert "source-sentinel.txt" in {item["path"] for item in granted_manifest["files"]}
    assert granted_manifest["redactions"] == 1
    assert ".npmrc" in {item["path"] for item in granted_manifest["omitted"]}


def test_diff_and_check_artifacts_are_withheld_without_capabilities(
    project: Path, config: ForgeWardConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, provider = _engine_with_capture(project, config, monkeypatch)
    record = engine.store.create(
        "Check evidence routing", provider="demo", apply_changes=False, base_commit=None
    )
    engine.store.write_artifact(
        record,
        "build/proposed-changes.json",
        "DIFF_CAPABILITY_SENTINEL",
        author="builder",
        kind="change-proposal",
    )
    engine.store.write_artifact(
        record,
        "evidence/check.log",
        "CHECK_CAPABILITY_SENTINEL",
        author="orchestrator",
        kind="check-output",
    )

    engine._call_role(record, "scrum-master", "planning/scrum-evidence.md")
    text = _request_text(provider.requests[-1])

    assert "DIFF_CAPABILITY_SENTINEL" not in text
    assert "CHECK_CAPABILITY_SENTINEL" not in text


def test_prior_artifact_secrets_are_redacted_only_in_outbound_prompt(
    project: Path, config: ForgeWardConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, provider = _engine_with_capture(project, config, monkeypatch)
    record = engine.store.create(
        "Redact outbound prior evidence", provider="demo", apply_changes=False, base_commit=None
    )
    original = "password=PRIOR_ARTIFACT_SECRET_SENTINEL"
    engine.store.write_artifact(
        record,
        "planning/sensitive-input.md",
        original,
        author="product",
        kind="role-deliverable",
    )

    engine._call_role(record, "designer", "design/redaction-capture.md")

    request_text = _request_text(provider.requests[-1])
    assert "PRIOR_ARTIFACT_SECRET_SENTINEL" not in request_text
    assert "[REDACTED]" in request_text
    assert engine.store.read_artifact(record, "artifacts/planning/sensitive-input.md") == original
    manifest = json.loads(engine.store.read_artifact(record, "artifacts/context/designer-1.json"))
    assert manifest["outbound_redactions"] >= 1


def test_default_verifiers_receive_complete_non_apply_change_proposal(
    project: Path, config: ForgeWardConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, provider = _engine_with_capture(project, config, monkeypatch)
    record = engine.advance(engine.create_run("Review a non-apply proposal"))
    engine.approve_gate(record, "plan", actor="human:test")

    record = engine.advance(record)

    assert record.state == RunState.RELEASE_GATE
    for role in config.workflow.verification_roles:
        request = next(
            item for item in reversed(provider.requests) if item.metadata.get("role") == role
        )
        text = _request_text(request)
        assert 'path="artifacts/build/proposed-changes.json"' in text
        assert "REVIEW_SENTINEL_" + "x" * 24 in text


def test_structured_findings_persist_and_render_at_all_severities(
    project: Path, config: ForgeWardConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, _provider = _engine_with_capture(project, config, monkeypatch)
    record = engine.advance(engine.create_run("Preserve structured findings"))
    engine.approve_gate(record, "plan", actor="human:test")
    record = engine.advance(record)

    assert record.blockers == []
    assert len(record.findings) == record.calls_made == 10
    assert all(item.severity.value == "low" for item in record.findings)
    finding_artifacts = [item for item in record.artifacts if item.kind == "finding-set"]
    assert len(finding_artifacts) == 10
    report = markdown_report(record, engine.store)
    assert "LOW\\_FINDING\\_DETAIL\\_SURVIVES" in report
    assert "LOW\\_FINDING\\_EVIDENCE\\_SURVIVES" in report
    assert "artifacts/findings/" in report


def test_oversized_change_proposal_cannot_reach_release_gate_unreviewed(
    project: Path, config: ForgeWardConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, provider = _engine_with_capture(
        project, config, monkeypatch, builder_content_size=70_000
    )
    record = engine.advance(engine.create_run("Reject incomplete review context"))
    engine.approve_gate(record, "plan", actor="human:test")

    with pytest.raises(OrchestrationError, match="Required review evidence"):
        engine.advance(record)

    loaded = engine.store.load(record.id)
    assert loaded.state == RunState.VERIFICATION
    assert "release" not in loaded.gates
    assert loaded.calls_made == 6
    assert len(provider.requests) == 6
    assert not any(
        request.metadata.get("role") in {"reviewer", "tester"} for request in provider.requests
    )


def test_custom_planning_role_drives_configured_workflow(
    project: Path, config: ForgeWardConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = config.model_dump(mode="json")
    raw["team"].append(
        RoleSpec(
            id="custom-planner",
            mission="Create a custom plan for this engagement.",
            prompt="product.md",
            allowed_tools=["repository.read", "artifact.read"],
        ).model_dump(mode="json")
    )
    raw["workflow"]["plan_roles"] = ["custom-planner"]
    custom_config = ForgeWardConfig.model_validate(raw)
    engine, _provider = _engine_with_capture(project, custom_config, monkeypatch)

    record = engine.advance(engine.create_run("Use the configured planning team"))

    assert record.state == RunState.PLAN_GATE
    assert record.calls_made == 1
    assert "artifacts/planning/custom-planner.md" in {
        artifact.path for artifact in record.artifacts
    }
