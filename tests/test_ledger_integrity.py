from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import forgeward.orchestrator as orchestrator_module
import forgeward.security as security_module
from forgeward.models import CheckSpec, ForgeWardConfig, RunState
from forgeward.orchestrator import ForgeWardEngine, OrchestrationError, git_dirty_paths
from forgeward.state import RunStore, StateError

ProjectionMutation = Callable[[dict[str, Any]], None]


def _engine(project: Path, config: ForgeWardConfig) -> ForgeWardEngine:
    return ForgeWardEngine(project, config)


def _plan_gate(engine: ForgeWardEngine):
    record = engine.create_run("Exercise ledger-backed gate integrity")
    record = engine.advance(record)
    assert record.state == RunState.PLAN_GATE
    return record


def _release_gate_with_blocker(engine: ForgeWardEngine):
    record = _plan_gate(engine)
    engine.approve_gate(record, "plan", actor="human:test")
    record = engine.advance(record)
    assert record.state == RunState.RELEASE_GATE
    assert record.checks
    assert record.blockers
    return record


def _mutate_run_json(
    store: RunStore,
    run_id: str,
    mutation: ProjectionMutation,
):
    path = store.directory(run_id) / "run.json"
    projection = json.loads(path.read_text(encoding="utf-8"))
    mutation(projection)
    path.write_text(json.dumps(projection, indent=2), encoding="utf-8")
    return store.load(run_id)


def test_hash_chained_event_binds_the_semantic_run_projection(project: Path) -> None:
    store = RunStore(project)
    record = store.create(
        "Preserve semantic history",
        provider="demo",
        apply_changes=False,
        base_commit=None,
    )
    events = store.events(record.id)

    assert events[-1]["projection_sha256"] == store.projection_sha256(record)

    forged = _mutate_run_json(
        store,
        record.id,
        lambda value: value.__setitem__("objective", "Forged objective"),
    )
    with pytest.raises(StateError, match="hash-chained semantic checkpoint"):
        store.verify_projection(forged)


def test_advance_rejects_run_json_only_state_tampering_without_extending_ledger(
    project: Path, config: ForgeWardConfig
) -> None:
    engine = _engine(project, config)
    record = _plan_gate(engine)
    ledger_path = engine.store.directory(record.id) / "events.jsonl"
    original_lines = ledger_path.read_text(encoding="utf-8").splitlines()
    forged = _mutate_run_json(
        engine.store,
        record.id,
        lambda value: value.__setitem__("state", "complete"),
    )

    with pytest.raises(OrchestrationError, match="hash-chained semantic checkpoint"):
        engine.advance(forged)

    assert ledger_path.read_text(encoding="utf-8").splitlines() == original_lines


def _remove_plan_gate(value: dict[str, Any]) -> None:
    value["gates"].pop("plan")


def _forge_plan_decision(value: dict[str, Any]) -> None:
    value["gates"]["plan"]["decision"] = "approved"
    value["gates"]["plan"]["actor"] = "attacker"


def _forge_plan_evidence(value: dict[str, Any]) -> None:
    value["gates"]["plan"]["evidence_sha256"] = "0" * 64


def _remove_artifact_record(value: dict[str, Any]) -> None:
    value["artifacts"].pop()


@pytest.mark.parametrize(
    "mutation",
    [
        _remove_plan_gate,
        _forge_plan_decision,
        _forge_plan_evidence,
        _remove_artifact_record,
    ],
    ids=["gate-open", "gate-decision", "gate-evidence", "artifact-record"],
)
def test_gate_approval_rejects_forged_projection_records(
    project: Path,
    config: ForgeWardConfig,
    mutation: ProjectionMutation,
) -> None:
    engine = _engine(project, config)
    record = _plan_gate(engine)
    forged = _mutate_run_json(engine.store, record.id, mutation)

    with pytest.raises(OrchestrationError, match="hash-chained semantic checkpoint"):
        engine.approve_gate(forged, "plan", actor="human:test")


def _remove_checks(value: dict[str, Any]) -> None:
    value["checks"] = []


def _remove_blockers(value: dict[str, Any]) -> None:
    value["blockers"] = []


def _forge_workspace_record(value: dict[str, Any]) -> None:
    value["workspace_changes"] = {"src/forged.py": "0" * 64}


@pytest.mark.parametrize(
    "mutation",
    [_remove_checks, _remove_blockers, _forge_workspace_record],
    ids=["checks", "blockers", "workspace-changes"],
)
def test_release_decision_rejects_run_json_only_evidence_bypass(
    project: Path,
    config: ForgeWardConfig,
    mutation: ProjectionMutation,
) -> None:
    config.checks = [
        CheckSpec(
            name="blocked command",
            command=["definitely-not-allowlisted", "--version"],
            required=True,
        )
    ]
    engine = _engine(project, config)
    record = _release_gate_with_blocker(engine)
    forged = _mutate_run_json(engine.store, record.id, mutation)

    with pytest.raises(OrchestrationError, match="hash-chained semantic checkpoint"):
        engine.approve_gate(forged, "release", actor="human:test")


def test_rejection_cannot_ratify_in_memory_projection_tampering(
    project: Path, config: ForgeWardConfig
) -> None:
    engine = _engine(project, config)
    record = _plan_gate(engine)
    record.blockers.append("in-memory forged blocker")

    with pytest.raises(OrchestrationError, match="hash-chained semantic checkpoint"):
        engine.reject_gate(record, "plan", actor="human:test", reason="retry")


def test_apply_creation_fails_closed_when_git_is_missing(
    project: Path,
    config: ForgeWardConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        orchestrator_module, "resolve_external_executable", lambda _root, _name: None
    )

    with pytest.raises(OrchestrationError, match="Git repository with at least one commit"):
        _engine(project, config).create_run("Apply safely", apply_changes=True)


def test_apply_creation_never_executes_project_local_git(
    project: Path,
    config: ForgeWardConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_git = project / "git.exe"
    fake_git.write_text("FAKE_GIT_EXECUTION_SENTINEL", encoding="utf-8")
    monkeypatch.setattr(security_module.shutil, "which", lambda _name: str(fake_git))
    monkeypatch.setattr(
        orchestrator_module.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("project-local Git must not execute"),
    )

    with pytest.raises(OrchestrationError, match="Git repository with at least one commit"):
        _engine(project, config).create_run("Apply safely", apply_changes=True)


@pytest.mark.parametrize(
    "failure",
    [
        subprocess.CalledProcessError(1, ["git", "status"]),
        subprocess.TimeoutExpired(["git", "status"], 10),
    ],
    ids=["nonzero", "timeout"],
)
def test_apply_creation_fails_closed_when_git_status_cannot_be_inspected(
    project: Path,
    config: ForgeWardConfig,
    monkeypatch: pytest.MonkeyPatch,
    failure: subprocess.SubprocessError,
) -> None:
    monkeypatch.setattr(orchestrator_module, "git_commit", lambda _root: "abc123")
    monkeypatch.setattr(
        orchestrator_module,
        "resolve_external_executable",
        lambda _root, _name: Path("git"),
    )

    def fail_status(*_args: Any, **_kwargs: Any) -> None:
        raise failure

    monkeypatch.setattr(orchestrator_module.subprocess, "run", fail_status)

    with pytest.raises(OrchestrationError, match="refusing to treat the worktree as clean"):
        _engine(project, config).create_run("Apply safely", apply_changes=True)


def test_release_workspace_integrity_fails_closed_on_git_status_timeout(
    project: Path,
    config: ForgeWardConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _engine(project, config)
    record = engine.store.create(
        "Verify a release worktree",
        provider="demo",
        apply_changes=True,
        base_commit="abc123",
    )
    monkeypatch.setattr(orchestrator_module, "git_commit", lambda _root: "abc123")
    monkeypatch.setattr(
        orchestrator_module,
        "resolve_external_executable",
        lambda _root, _name: Path("git"),
    )

    monkeypatch.setattr(
        orchestrator_module,
        "_bounded_git_status",
        lambda *_args, **_kwargs: (None, "timeout"),
    )

    with pytest.raises(OrchestrationError, match="refusing to treat the worktree as clean"):
        engine._assert_workspace_integrity(record)


def test_approved_release_rechecks_workspace_before_completion(
    project: Path,
    config: ForgeWardConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(orchestrator_module, "git_commit", lambda _root: "abc123")
    monkeypatch.setattr(orchestrator_module, "git_dirty_paths", lambda _root: [])
    engine = _engine(project, config)
    record = engine.store.create(
        "Recheck an approved release",
        provider="demo",
        apply_changes=True,
        base_commit="abc123",
    )
    record = engine.advance(record)
    engine.approve_gate(record, "plan", actor="human:test")
    record = engine.advance(record)
    engine.approve_gate(record, "release", actor="human:test")
    calls_before_release = record.calls_made

    def fail_closed(_root: Path) -> list[str]:
        raise OrchestrationError(
            "Git worktree inspection failed; refusing to treat the worktree as clean"
        )

    monkeypatch.setattr(orchestrator_module, "git_dirty_paths", fail_closed)

    with pytest.raises(OrchestrationError, match="refusing to treat the worktree as clean"):
        engine.advance(record)

    assert record.calls_made == calls_before_release
    assert "artifacts/release/release-notes.md" in {artifact.path for artifact in record.artifacts}


def test_git_dirty_paths_fails_closed_without_git(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        orchestrator_module, "resolve_external_executable", lambda _root, _name: None
    )

    with pytest.raises(OrchestrationError, match="Git is unavailable"):
        git_dirty_paths(project)


def test_git_dirty_paths_fails_closed_on_bounded_status_overflow(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        orchestrator_module,
        "resolve_external_executable",
        lambda _root, _name: Path("C:/trusted/git.exe"),
    )
    monkeypatch.setattr(
        orchestrator_module,
        "_bounded_git_status",
        lambda *_args, **_kwargs: (None, "overflow"),
    )

    with pytest.raises(OrchestrationError, match="refusing to treat the worktree as clean"):
        git_dirty_paths(project)


def test_git_dirty_paths_parses_nul_delimited_rename_without_line_ambiguity(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        orchestrator_module,
        "resolve_external_executable",
        lambda _root, _name: Path("C:/trusted/git.exe"),
    )
    output = b" M ordinary.txt\x00R  renamed\nfile.txt\x00old.txt\x00"
    monkeypatch.setattr(
        orchestrator_module,
        "_bounded_git_status",
        lambda *_args, **_kwargs: (output, "ok"),
    )

    assert git_dirty_paths(project) == ["ordinary.txt", "renamed\nfile.txt", "old.txt"]
