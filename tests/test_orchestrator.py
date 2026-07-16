from __future__ import annotations

import json
from pathlib import Path

import pytest

import forgeward.orchestrator as orchestrator_module
from forgeward.models import (
    CheckSpec,
    CompletionResult,
    Deliverable,
    Finding,
    GateDecision,
    ProposedChange,
    RunState,
    Severity,
)
from forgeward.orchestrator import ForgeWardEngine, OrchestrationError
from forgeward.providers import ProviderError
from forgeward.security import sha256_text


def _engine(project: Path, config) -> ForgeWardEngine:
    return ForgeWardEngine(project, config)


def _advance_to_plan_gate(engine: ForgeWardEngine):
    record = engine.create_run("Deliver a small secure feature")
    result = engine.advance(record)
    assert result.state == RunState.PLAN_GATE
    return result


def test_demo_engine_plans_then_pauses_at_human_gate(project: Path, config) -> None:
    engine = _engine(project, config)
    record = _advance_to_plan_gate(engine)

    assert record.provider == "demo"
    assert record.calls_made == 5
    assert record.gates["plan"].decision == GateDecision.PENDING
    assert record.gates["plan"].evidence_sha256 == engine._evidence_digest(record)
    paths = {artifact.path for artifact in record.artifacts}
    assert {
        "artifacts/request.md",
        "artifacts/planning/requirements.md",
        "artifacts/planning/acceptance-criteria.md",
        "artifacts/design/experience.md",
        "artifacts/security/threat-model.md",
        "artifacts/design/architecture.md",
        "artifacts/planning/backlog.md",
    }.issubset(paths)
    assert len([path for path in paths if path.startswith("artifacts/context/")]) == 5
    engine.store.events(record.id, verify=True)
    engine.store.verify_artifacts(record)


def test_demo_engine_completes_full_two_gate_lifecycle(project: Path, config) -> None:
    engine = _engine(project, config)
    record = _advance_to_plan_gate(engine)

    engine.approve_gate(record, "plan", actor="human:test")
    record = engine.advance(record)
    assert record.state == RunState.RELEASE_GATE
    assert record.gates["release"].decision == GateDecision.PENDING
    assert record.calls_made == 10
    assert "artifacts/release/release-notes.md" in {artifact.path for artifact in record.artifacts}
    assert record.blockers == []
    assert record.checks == []
    approved_evidence = record.gates["release"].evidence_sha256
    assert approved_evidence == engine._evidence_digest(record)

    engine.approve_gate(record, "release", actor="human:test")
    record = engine.advance(record)
    assert record.state == RunState.COMPLETE
    assert record.calls_made == 10
    assert engine._evidence_digest(record) == approved_evidence
    assert {gate: item.decision for gate, item in record.gates.items()} == {
        "plan": GateDecision.APPROVED,
        "release": GateDecision.APPROVED,
    }
    assert "artifacts/release/release-notes.md" in {artifact.path for artifact in record.artifacts}
    assert record.workspace_changes == {}
    assert engine.store.load(record.id).state == RunState.COMPLETE
    events = engine.store.events(record.id, verify=True)
    assert events[-1]["type"] == "run.state_changed"
    assert events[-1]["data"]["to"] == "complete"
    assert [event["type"] for event in events].count("gate.approved") == 2
    engine.store.verify_artifacts(record)


def test_plan_only_stops_even_if_plan_gate_was_already_approved(project: Path, config) -> None:
    engine = _engine(project, config)
    record = _advance_to_plan_gate(engine)
    engine.approve_gate(record, "plan", actor="human:test")

    record = engine.advance(record, plan_only=True)

    assert record.state == RunState.PLAN_GATE
    assert record.gates["plan"].decision == GateDecision.APPROVED
    assert record.calls_made == 5


def test_rejected_plan_reruns_all_planners_and_opens_fresh_gate(project: Path, config) -> None:
    engine = _engine(project, config)
    record = _advance_to_plan_gate(engine)
    old_digest = record.gates["plan"].evidence_sha256
    engine.reject_gate(record, "plan", actor="human:test", reason="Clarify rollback behavior")

    record = engine.advance(record, plan_only=True)

    assert record.state == RunState.PLAN_GATE
    assert record.gates["plan"].decision == GateDecision.PENDING
    assert record.gates["plan"].reason is None
    assert record.calls_made == 10
    assert record.gates["plan"].evidence_sha256 != old_digest


def test_auto_approved_policy_can_complete_demo_without_human_pause(project: Path, config) -> None:
    config.policy.human_gates = []
    engine = _engine(project, config)

    record = engine.advance(engine.create_run("Exercise deterministic auto gates"))

    assert record.state == RunState.COMPLETE
    assert record.gates["plan"].actor == "policy:auto"
    assert record.gates["release"].actor == "policy:auto"
    assert record.gates["plan"].decision == GateDecision.APPROVED
    assert record.gates["release"].decision == GateDecision.APPROVED


@pytest.mark.parametrize(
    ("objective", "provider", "message"),
    [
        ("   ", None, "Objective must not be empty"),
        ("valid", "unknown", "Unknown provider"),
        ("valid", "local", "Provider is disabled"),
    ],
)
def test_create_run_validates_objective_and_provider(
    project: Path, config, objective: str, provider: str | None, message: str
) -> None:
    with pytest.raises(OrchestrationError, match=message):
        _engine(project, config).create_run(objective, provider=provider)


def test_provider_call_budget_interrupts_and_records_failure(project: Path, config) -> None:
    config.policy.max_provider_calls = 1
    engine = _engine(project, config)
    record = engine.create_run("Exceed the deliberately tiny budget")

    with pytest.raises(OrchestrationError, match="Provider-call budget exhausted"):
        engine.advance(record)

    loaded = engine.store.load(record.id)
    assert loaded.calls_made == 1
    assert "Provider-call budget exhausted" in (loaded.failure or "")
    assert engine.store.events(record.id)[-1]["type"] == "run.interrupted"


@pytest.mark.parametrize("failure_mode", ["timeout", "malformed"])
def test_failed_provider_attempt_consumes_budget_before_resume(
    project: Path,
    config,
    monkeypatch: pytest.MonkeyPatch,
    failure_mode: str,
) -> None:
    config.policy.max_provider_calls = 1

    class FailingProvider:
        def __init__(self) -> None:
            self.calls = 0

        def complete(self, _request):
            self.calls += 1
            if failure_mode == "timeout":
                raise ProviderError("synthetic timeout", code="timeout", retryable=True)
            return CompletionResult(content="not valid JSON", model="synthetic")

        def probe(self) -> tuple[bool, str]:
            return False, "not used"

    provider = FailingProvider()
    monkeypatch.setattr(orchestrator_module, "create_provider", lambda _config: provider)
    engine = _engine(project, config)
    record = engine.create_run("Consume failed provider attempts")

    with pytest.raises(OrchestrationError):
        engine.advance(record)

    loaded = engine.store.load(record.id)
    assert loaded.calls_made == 1
    assert provider.calls == 1
    started = [
        event for event in engine.store.events(record.id) if event["type"] == "worker.started"
    ]
    assert started[-1]["data"]["call_attempt"] == 1

    with pytest.raises(OrchestrationError, match="Provider-call budget exhausted"):
        engine.advance(loaded)

    assert provider.calls == 1


def test_non_builder_deliverable_cannot_propose_workspace_changes(project: Path, config) -> None:
    engine = _engine(project, config)
    deliverable = Deliverable(
        summary="A review attempted a write.",
        artifact="Review output",
        proposed_changes=[
            ProposedChange(
                operation="create",
                path="unexpected.txt",
                content="bad",
                rationale="should be rejected",
            )
        ],
    )

    with pytest.raises(OrchestrationError, match="not allowed to propose"):
        engine._validate_deliverable(deliverable, "reviewer")


def test_required_skipped_check_blocks_release_gate(project: Path, config) -> None:
    config.checks = [
        CheckSpec(
            name="not allowlisted",
            command=["definitely-not-allowed", "--version"],
            required=True,
        )
    ]
    engine = _engine(project, config)
    record = _advance_to_plan_gate(engine)
    engine.approve_gate(record, "plan", actor="human:test")

    record = engine.advance(record)

    assert record.state == RunState.RELEASE_GATE
    assert record.checks[0].status == "skipped"
    assert record.checks[0].report_path is not None
    assert record.blockers == ["required check 'not allowlisted' is skipped"]
    with pytest.raises(OrchestrationError, match="Release gate is blocked"):
        engine.approve_gate(record, "release", actor="human:test")


def test_finding_threshold_is_deterministic_and_inclusive(project: Path, config) -> None:
    config.policy.fail_on_severity = Severity.MEDIUM
    engine = _engine(project, config)
    record = engine.create_run("Calculate release findings")
    findings = [
        Finding(severity=Severity.LOW, title="low", detail="below threshold"),
        Finding(severity=Severity.MEDIUM, title="medium", detail="at threshold"),
        Finding(severity=Severity.CRITICAL, title="critical", detail="above threshold"),
    ]

    engine._calculate_blockers(record, findings)

    assert record.blockers == [
        "medium finding: medium",
        "critical finding: critical",
    ]


def test_release_draft_finding_blocks_before_human_gate(
    project: Path, config, monkeypatch: pytest.MonkeyPatch
) -> None:
    class ReleaseFindingProvider:
        def complete(self, request):
            role = request.metadata["role"]
            findings = []
            if role == config.workflow.release_role:
                findings = [
                    {
                        "severity": "critical",
                        "title": "Release handoff found an unsafe rollback",
                        "detail": "The draft cannot support safe release.",
                        "evidence": "release draft",
                    }
                ]
            return CompletionResult(
                content=json.dumps(
                    {
                        "summary": f"{role} completed",
                        "artifact": f"# {role}\n\nBounded deliverable.",
                        "acceptance_criteria": ["The change remains reviewable."],
                        "proposed_changes": [],
                        "findings": findings,
                        "proposed_transition": None,
                    }
                ),
                model="release-finding-model",
            )

        def probe(self) -> tuple[bool, str]:
            return True, "ready"

    monkeypatch.setattr(
        orchestrator_module, "create_provider", lambda _config: ReleaseFindingProvider()
    )
    engine = _engine(project, config)
    record = _advance_to_plan_gate(engine)
    engine.approve_gate(record, "plan", actor="human:test")

    record = engine.advance(record)

    assert record.state == RunState.RELEASE_GATE
    assert "artifacts/release/release-notes.md" in {artifact.path for artifact in record.artifacts}
    assert record.blockers == ["critical finding: Release handoff found an unsafe rollback"]
    with pytest.raises(OrchestrationError, match="Release gate is blocked"):
        engine.approve_gate(record, "release", actor="human:test")


def test_gate_approval_is_bound_to_evidence_snapshot(project: Path, config) -> None:
    engine = _engine(project, config)
    record = _advance_to_plan_gate(engine)
    opened_digest = record.gates["plan"].evidence_sha256
    engine.store.write_artifact(
        record,
        "planning/late-evidence.md",
        "This appeared after the review snapshot.",
        author="orchestrator",
        kind="role-deliverable",
    )

    assert engine._evidence_digest(record) != opened_digest
    with pytest.raises(OrchestrationError, match="Evidence changed after gate plan opened"):
        engine.approve_gate(record, "plan", actor="human:test")


def test_report_artifact_does_not_change_gate_evidence_digest(project: Path, config) -> None:
    engine = _engine(project, config)
    record = _advance_to_plan_gate(engine)
    opened_digest = record.gates["plan"].evidence_sha256
    engine.store.write_artifact(
        record,
        "reports/preview.md",
        "A derived report over existing evidence.",
        author="orchestrator",
        kind="report",
    )

    assert engine._evidence_digest(record) == opened_digest
    engine.approve_gate(record, "plan", actor="human:test")
    assert record.gates["plan"].decision == GateDecision.APPROVED


def test_gate_approval_refuses_modified_artifact_even_if_projection_digest_is_unchanged(
    project: Path, config
) -> None:
    engine = _engine(project, config)
    record = _advance_to_plan_gate(engine)
    artifact = next(item for item in record.artifacts if item.kind == "role-deliverable")
    destination = engine.store.directory(record.id) / artifact.path
    destination.write_text("tampered", encoding="utf-8")

    assert artifact.sha256 != sha256_text("tampered")
    with pytest.raises(OrchestrationError, match="Evidence integrity check failed"):
        engine.approve_gate(record, "plan", actor="human:test")


def test_gate_decisions_require_existing_gate_expected_state_and_nonempty_reason(
    project: Path, config
) -> None:
    engine = _engine(project, config)
    created = engine.create_run("Validate gate state")
    with pytest.raises(OrchestrationError, match="Gate does not exist"):
        engine.approve_gate(created, "plan", actor="human:test")

    record = _advance_to_plan_gate(engine)
    with pytest.raises(OrchestrationError, match="rejection reason is required"):
        engine.reject_gate(record, "plan", actor="human:test", reason="  ")
    engine.approve_gate(record, "plan", actor="human:test")
    with pytest.raises(OrchestrationError, match="already approved"):
        engine.approve_gate(record, "plan", actor="human:test")
