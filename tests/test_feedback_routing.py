from __future__ import annotations

import json
from pathlib import Path

import pytest

import forgeward.orchestrator as orchestrator_module
from forgeward.models import (
    CompletionRequest,
    CompletionResult,
    ForgeWardConfig,
    GateDecision,
    RunState,
)
from forgeward.orchestrator import ForgeWardEngine, OrchestrationError
from forgeward.reporting import markdown_report


class CorrectiveIterationProvider:
    """Capture prompts while returning valid, low-risk deliverables."""

    def __init__(
        self,
        *,
        builder_payloads: list[str] | None = None,
        builder_operations: list[str] | None = None,
        product_criteria: list[list[str]] | None = None,
    ) -> None:
        self.requests: list[CompletionRequest] = []
        self.builder_payloads = builder_payloads or ["SMALL_PROPOSAL_SENTINEL"]
        self.builder_operations = builder_operations or ["create"]
        self.builder_calls = 0
        self.product_criteria = product_criteria
        self.product_calls = 0

    def complete(self, request: CompletionRequest) -> CompletionResult:
        self.requests.append(request)
        role = request.metadata["role"]
        proposed_changes: list[dict[str, str]] = []
        if role == "builder":
            payload_index = min(self.builder_calls, len(self.builder_payloads) - 1)
            operation_index = min(self.builder_calls, len(self.builder_operations) - 1)
            proposed_changes = [
                {
                    "operation": self.builder_operations[operation_index],
                    "path": "src/corrective-iteration.py",
                    "content": self.builder_payloads[payload_index],
                    "rationale": "Exercise corrective iteration evidence routing.",
                }
            ]
            self.builder_calls += 1
        acceptance_criteria = ["Corrective feedback is implemented and reviewed."]
        if role == "product" and self.product_criteria is not None:
            criteria_index = min(self.product_calls, len(self.product_criteria) - 1)
            acceptance_criteria = self.product_criteria[criteria_index]
            self.product_calls += 1
        body = {
            "summary": f"{role} completed its bounded assignment.",
            "artifact": f"# {role}\n\nCorrective iteration artifact.\n",
            "acceptance_criteria": acceptance_criteria,
            "proposed_changes": proposed_changes,
            "findings": [
                {
                    "severity": "low",
                    "title": f"LOW_FINDING_{role}",
                    "detail": "No release-blocking issue was found.",
                    "evidence": "captured-provider",
                }
            ],
            "proposed_transition": None,
        }
        return CompletionResult(
            content=json.dumps(body),
            model="corrective-iteration-model",
            finish_reason="stop",
        )

    def probe(self) -> tuple[bool, str]:
        return True, "corrective iteration provider ready"


def _engine_with_provider(
    project: Path,
    config: ForgeWardConfig,
    monkeypatch: pytest.MonkeyPatch,
    *,
    builder_payloads: list[str] | None = None,
    builder_operations: list[str] | None = None,
    product_criteria: list[list[str]] | None = None,
) -> tuple[ForgeWardEngine, CorrectiveIterationProvider]:
    provider = CorrectiveIterationProvider(
        builder_payloads=builder_payloads,
        builder_operations=builder_operations,
        product_criteria=product_criteria,
    )
    monkeypatch.setattr(orchestrator_module, "create_provider", lambda _config: provider)
    return ForgeWardEngine(project, config), provider


def _request_text(request: CompletionRequest) -> str:
    return "\n".join(message.content for message in request.messages)


def _markdown_escaped(value: str) -> str:
    return value.replace("_", "\\_")


def _requests_after(
    provider: CorrectiveIterationProvider, offset: int, role: str
) -> list[CompletionRequest]:
    return [
        request for request in provider.requests[offset:] if request.metadata.get("role") == role
    ]


def test_plan_rejection_feedback_reaches_corrective_planners_and_report(
    project: Path, config: ForgeWardConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, provider = _engine_with_provider(project, config, monkeypatch)
    record = engine.advance(engine.create_run("Plan a corrective iteration"))
    request_offset = len(provider.requests)
    reason = "PLAN_FEEDBACK_SENTINEL: document rollback and recovery ownership."

    engine.reject_gate(record, "plan", actor="human:test", reason=reason)
    record = engine.advance(record, plan_only=True)

    assert record.state == RunState.PLAN_GATE
    assert record.gates["plan"].decision == GateDecision.PENDING
    assert record.gates["plan"].reason is None
    for role in config.workflow.plan_roles:
        requests = _requests_after(provider, request_offset, role)
        assert len(requests) == 1
        assert reason in _request_text(requests[0])
        assert 'kind="human-feedback"' in _request_text(requests[0])

    assert [(item.gate, item.reason) for item in record.feedback] == [("plan", reason)]
    feedback_artifact = engine.store.read_artifact(record, "artifacts/feedback/plan-01.json")
    assert reason in feedback_artifact
    report = markdown_report(record, engine.store)
    assert "Human feedback history" in report
    assert _markdown_escaped(reason) in report
    assert "artifacts/feedback/plan-01.json" in report


def test_release_rejection_resumes_full_review_within_default_call_budget(
    project: Path, config: ForgeWardConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, provider = _engine_with_provider(project, config, monkeypatch)
    record = engine.advance(engine.create_run("Build then correct a releasable change"))
    engine.approve_gate(record, "plan", actor="human:test")
    record = engine.advance(record)
    assert record.state == RunState.RELEASE_GATE
    request_offset = len(provider.requests)
    reason = "RELEASE_FEEDBACK_SENTINEL: add a verified rollback guard."

    engine.reject_gate(record, "release", actor="human:test", reason=reason)
    record = engine.advance(record)

    assert record.state == RunState.RELEASE_GATE
    assert record.gates["release"].decision == GateDecision.PENDING
    assert record.gates["release"].reason is None
    assert record.blockers == []
    assert record.calls_made <= config.policy.max_provider_calls
    for role in (
        config.workflow.build_role,
        *config.workflow.verification_roles,
        config.workflow.release_role,
    ):
        requests = _requests_after(provider, request_offset, role)
        assert len(requests) == 1
        assert reason in _request_text(requests[0])
        assert 'kind="human-feedback"' in _request_text(requests[0])
    corrective_builder = _requests_after(provider, request_offset, config.workflow.build_role)[0]
    assert "SMALL_PROPOSAL_SENTINEL" in _request_text(corrective_builder)
    assert 'kind="change-proposal"' in _request_text(corrective_builder)

    assert [(item.gate, item.reason) for item in record.feedback] == [("release", reason)]
    assert _markdown_escaped(reason) in markdown_report(record, engine.store)


def test_plan_and_release_corrections_fit_exactly_within_default_budget(
    project: Path, config: ForgeWardConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, _provider = _engine_with_provider(project, config, monkeypatch)
    record = engine.advance(engine.create_run("Exercise both corrective feedback loops"))
    engine.reject_gate(
        record,
        "plan",
        actor="human:test",
        reason="Correct the complete planning package.",
    )
    record = engine.advance(record, plan_only=True)
    assert record.calls_made == 10

    engine.approve_gate(record, "plan", actor="human:test")
    record = engine.advance(record)
    assert record.state == RunState.RELEASE_GATE
    assert record.calls_made == 15
    engine.reject_gate(
        record,
        "release",
        actor="human:test",
        reason="Correct the implementation and repeat verification.",
    )
    record = engine.advance(record)

    assert record.state == RunState.RELEASE_GATE
    assert record.calls_made == config.policy.max_provider_calls == 20
    engine.approve_gate(record, "release", actor="human:test")
    record = engine.advance(record)
    assert record.state == RunState.COMPLETE
    assert record.calls_made == 20


def test_applied_release_correction_updates_the_previously_created_file(
    project: Path, config: ForgeWardConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = project / "src" / "corrective-iteration.py"
    monkeypatch.setattr(orchestrator_module, "git_commit", lambda _root: "base-commit")
    monkeypatch.setattr(
        orchestrator_module,
        "git_dirty_paths",
        lambda _root: ["src/corrective-iteration.py"] if destination.exists() else [],
    )
    engine, _provider = _engine_with_provider(
        project,
        config,
        monkeypatch,
        builder_payloads=["INITIAL_APPLIED_CONTENT", "CORRECTED_APPLIED_CONTENT"],
        builder_operations=["create", "update"],
    )
    record = engine.advance(
        engine.create_run("Apply and correct one created file", apply_changes=True)
    )
    engine.approve_gate(record, "plan", actor="human:test")
    record = engine.advance(record)
    assert destination.read_text(encoding="utf-8") == "INITIAL_APPLIED_CONTENT"

    engine.reject_gate(
        record,
        "release",
        actor="human:test",
        reason="Update the created file before release.",
    )
    record = engine.advance(record)

    assert record.state == RunState.RELEASE_GATE
    assert destination.read_text(encoding="utf-8") == "CORRECTED_APPLIED_CONTENT"
    engine.approve_gate(record, "release", actor="human:test")
    assert engine.advance(record).state == RunState.COMPLETE


def test_human_feedback_secret_is_redacted_outbound_but_preserved_locally(
    project: Path, config: ForgeWardConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, provider = _engine_with_provider(project, config, monkeypatch)
    record = engine.advance(engine.create_run("Correct a plan without leaking feedback"))
    reason = "password=HUMAN_FEEDBACK_SECRET_SENTINEL"
    request_offset = len(provider.requests)

    engine.reject_gate(record, "plan", actor="human:test", reason=reason)
    record = engine.advance(record, plan_only=True)

    for role in config.workflow.plan_roles:
        request = _requests_after(provider, request_offset, role)[0]
        text = _request_text(request)
        assert "HUMAN_FEEDBACK_SECRET_SENTINEL" not in text
        assert "[REDACTED]" in text
    assert reason in engine.store.read_artifact(record, "artifacts/feedback/plan-01.json")
    rendered_report = markdown_report(record, engine.store)
    assert "HUMAN_FEEDBACK_SECRET_SENTINEL" not in rendered_report
    assert r"\[REDACTED\]" in rendered_report
    manifests = [
        json.loads(engine.store.read_artifact(record, artifact.path))
        for artifact in record.artifacts
        if artifact.kind == "context-manifest"
        and artifact.path.endswith(
            (
                "product-6.json",
                "designer-7.json",
                "security-8.json",
                "architect-9.json",
                "scrum-master-10.json",
            )
        )
    ]
    assert len(manifests) == len(config.workflow.plan_roles)
    assert all(item["outbound_redactions"] >= 1 for item in manifests)


def test_missing_intake_criteria_stays_correctable_before_plan_gate(
    project: Path, config: ForgeWardConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, _provider = _engine_with_provider(
        project,
        config,
        monkeypatch,
        product_criteria=[[], ["A corrected criterion is measurable."]],
    )
    record = engine.create_run("Require criteria before planning")

    with pytest.raises(OrchestrationError, match="at least one acceptance criterion"):
        engine.advance(record)

    record = engine.store.load(record.id)
    assert record.state == RunState.INTAKE
    assert "plan" not in record.gates
    record = engine.advance(record, plan_only=True)

    assert record.state == RunState.PLAN_GATE
    assert record.gates["plan"].decision == GateDecision.PENDING
    assert record.failure is None
    criteria = engine.store.read_artifact(record, "artifacts/planning/acceptance-criteria.md")
    assert "A corrected criterion is measurable." in criteria


def test_near_budget_feedback_and_proposal_are_complete_or_review_fails_closed(
    project: Path, config: ForgeWardConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    config.policy.max_context_bytes = 12_000
    config.policy.max_provider_calls = 20
    large_proposal = "PROPOSAL_START_SENTINEL_" + "x" * 3_500 + "_PROPOSAL_END_SENTINEL"
    engine, provider = _engine_with_provider(
        project,
        config,
        monkeypatch,
        builder_payloads=["INITIAL_SMALL_PROPOSAL", large_proposal],
    )
    record = engine.advance(engine.create_run("Review a context-bound correction"))
    engine.approve_gate(record, "plan", actor="human:test")
    record = engine.advance(record)
    assert record.state == RunState.RELEASE_GATE
    reason = "HUMAN_CONTEXT_START_SENTINEL_" + "y" * 3_000 + "_HUMAN_CONTEXT_END_SENTINEL"
    engine.reject_gate(record, "release", actor="human:test", reason=reason)
    request_offset = len(provider.requests)

    try:
        record = engine.advance(record)
    except OrchestrationError as exc:
        assert "Required review evidence" in str(exc)
        corrective_requests = provider.requests[request_offset:]
        assert [request.metadata.get("role") for request in corrective_requests] == [
            config.workflow.build_role
        ]
        return

    assert record.state == RunState.RELEASE_GATE
    for role in config.workflow.verification_roles:
        requests = _requests_after(provider, request_offset, role)
        assert len(requests) == 1
        text = _request_text(requests[0])
        assert reason in text
        assert large_proposal in text
        assert 'kind="human-feedback"' in text
        assert 'kind="change-proposal"' in text
