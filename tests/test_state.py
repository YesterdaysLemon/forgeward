from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from forgeward.models import ArtifactRecord, RunState
from forgeward.security import sha256_text
from forgeward.state import RunStore, StateError


def _run(store: RunStore):
    return store.create(
        "Build a secure feature",
        provider="demo",
        apply_changes=False,
        base_commit=None,
    )


def _ledger_path(store: RunStore, run_id: str) -> Path:
    return store.directory(run_id) / "events.jsonl"


def _make_symlink(link: Path, target: Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")


def test_store_create_persists_projection_and_hash_chained_event(project: Path) -> None:
    store = RunStore(project)
    record = _run(store)

    loaded = store.load(record.id)
    events = store.events(record.id)
    assert loaded.id == record.id
    assert loaded.event_count == 1
    assert loaded.last_event_hash == events[0]["hash"]
    assert events[0]["seq"] == 1
    assert events[0]["previous_hash"] is None
    assert events[0]["type"] == "run.created"
    assert events[0]["data"]["objective_sha256"] == sha256_text(record.objective)

    store.set_state(record, RunState.INTAKE)
    events = store.events(record.id)
    assert events[1]["seq"] == 2
    assert events[1]["previous_hash"] == events[0]["hash"]
    assert store.load(record.id).state == RunState.INTAKE


def test_event_verification_detects_payload_tampering(project: Path) -> None:
    store = RunStore(project)
    record = _run(store)
    path = _ledger_path(store, record.id)
    event = json.loads(path.read_text(encoding="utf-8"))
    event["actor"] = "attacker"
    path.write_text(json.dumps(event) + "\n", encoding="utf-8")

    with pytest.raises(StateError, match="Event hash failed at event 1"):
        store.events(record.id, verify=True)
    assert store.events(record.id, verify=False)[0]["actor"] == "attacker"


def test_event_verification_detects_reordering_and_broken_previous_hash(project: Path) -> None:
    store = RunStore(project)
    record = _run(store)
    store.set_state(record, RunState.INTAKE)
    path = _ledger_path(store, record.id)
    lines = path.read_text(encoding="utf-8").splitlines()

    path.write_text("\n".join(reversed(lines)) + "\n", encoding="utf-8")
    with pytest.raises(StateError, match="Event chain order failed at event 1"):
        store.events(record.id)

    second = json.loads(lines[1])
    second["previous_hash"] = "0" * 64
    path.write_text(lines[0] + "\n" + json.dumps(second) + "\n", encoding="utf-8")
    with pytest.raises(StateError, match="Event chain order failed at event 2"):
        store.events(record.id)


def test_event_verification_detects_malformed_json(project: Path) -> None:
    store = RunStore(project)
    record = _run(store)
    _ledger_path(store, record.id).write_text("{not-json}\n", encoding="utf-8")

    with pytest.raises(StateError, match="Malformed event 1"):
        store.events(record.id)


def test_event_verification_rejects_a_truncated_valid_prefix(project: Path) -> None:
    store = RunStore(project)
    record = _run(store)
    store.set_state(record, RunState.INTAKE)
    path = _ledger_path(store, record.id)
    first = path.read_text(encoding="utf-8").splitlines()[0]
    path.write_text(first + "\n", encoding="utf-8")

    with pytest.raises(StateError, match=r"(?:event count|projection|truncated)"):
        store.events(record.id, verify=True)


def test_write_artifact_records_digest_event_and_optional_redaction(project: Path) -> None:
    store = RunStore(project)
    record = _run(store)
    artifact = store.write_artifact(
        record,
        "logs/provider.txt",
        "token=super-secret-value\nnormal output",
        author="orchestrator",
        kind="check-output",
        redact=True,
    )

    value = store.read_artifact(record, artifact.path)
    assert "super-secret-value" not in value
    assert "[REDACTED]" in value
    assert artifact.sha256 == sha256_text(value)
    assert store.events(record.id)[-1]["data"]["sha256"] == artifact.sha256
    store.verify_artifacts(record)


def test_write_artifact_replaces_projection_entry_for_same_path(project: Path) -> None:
    store = RunStore(project)
    record = _run(store)
    first = store.write_artifact(record, "notes.md", "first", author="a", kind="note")
    second = store.write_artifact(record, "notes.md", "second", author="b", kind="note")

    assert first.sha256 != second.sha256
    assert [artifact.path for artifact in record.artifacts] == ["artifacts/notes.md"]
    assert store.read_artifact(record, second.path) == "second"


@pytest.mark.parametrize("path", ["", "../escape", "nested/../../escape", "bad\x00name"])
def test_write_artifact_rejects_unsafe_path(project: Path, path: str) -> None:
    store = RunStore(project)
    record = _run(store)

    with pytest.raises(StateError, match="Unsafe artifact path"):
        store.write_artifact(record, path, "x", author="test", kind="test")


def test_verify_artifacts_detects_modified_missing_and_escaping_evidence(project: Path) -> None:
    store = RunStore(project)
    record = _run(store)
    artifact = store.write_artifact(record, "proof.txt", "original", author="test", kind="proof")
    destination = store.directory(record.id) / artifact.path
    destination.write_text("modified", encoding="utf-8")
    with pytest.raises(StateError, match="Artifact integrity failed"):
        store.verify_artifacts(record)

    destination.unlink()
    with pytest.raises(StateError, match="Artifact is missing"):
        store.verify_artifacts(record)

    record.artifacts = [ArtifactRecord(path="../../outside", sha256="0" * 64, author="x", kind="x")]
    with pytest.raises(StateError, match="escapes run directory"):
        store.verify_artifacts(record)


def test_verify_artifacts_rejects_symlink_even_when_bytes_match(project: Path) -> None:
    store = RunStore(project)
    record = _run(store)
    artifact = store.write_artifact(record, "proof.txt", "original", author="test", kind="proof")
    destination = store.directory(record.id) / artifact.path
    external = project / "external-proof.txt"
    external.write_text("original", encoding="utf-8")
    destination.unlink()
    _make_symlink(destination, external)

    with pytest.raises(StateError, match="Linked/reparse state path"):
        store.verify_artifacts(record)


@pytest.mark.parametrize("directory_name", ["runs", "exports"])
def test_store_rejects_linked_state_directories(project: Path, directory_name: str) -> None:
    state_directory = project / ".forgeward" / directory_name
    state_directory.rmdir()
    external = project / f"external-{directory_name}"
    external.mkdir()
    sentinel = external / "sentinel.txt"
    sentinel.write_text("do not touch", encoding="utf-8")
    _make_symlink(state_directory, external, directory=True)

    with pytest.raises(StateError, match="Linked/reparse state path"):
        RunStore(project)

    assert sentinel.read_text(encoding="utf-8") == "do not touch"


def test_save_does_not_follow_predictable_legacy_temp_symlink(project: Path) -> None:
    store = RunStore(project)
    record = _run(store)
    external = project / "external-run-state.json"
    external.write_text("external sentinel", encoding="utf-8")
    legacy_temp = store.directory(record.id) / "run.json.tmp"
    _make_symlink(legacy_temp, external)

    store.set_state(record, RunState.INTAKE)

    assert external.read_text(encoding="utf-8") == "external sentinel"
    assert store.load(record.id).state == RunState.INTAKE


def test_export_redacted_includes_text_evidence_without_secret(project: Path) -> None:
    store = RunStore(project)
    record = _run(store)
    store.write_artifact(
        record,
        "provider.log",
        "api_key=must-not-leak",
        author="test",
        kind="log",
    )

    output = store.export_redacted(record)
    with zipfile.ZipFile(output) as archive:
        names = archive.namelist()
        assert "run.json" in names
        assert "events.jsonl" in names
        value = archive.read("artifacts/provider.log").decode()
    assert "must-not-leak" not in value
    assert "[REDACTED]" in value


def test_export_rejects_symlinked_output_without_touching_target(project: Path) -> None:
    store = RunStore(project)
    record = _run(store)
    external = project / "external-export.zip"
    external.write_text("external sentinel", encoding="utf-8")
    output = store.exports / f"{record.id}-evidence.zip"
    _make_symlink(output, external)

    with pytest.raises(StateError, match=r"Linked/reparse state path|symlinked evidence export"):
        store.export_redacted(record)

    assert external.read_text(encoding="utf-8") == "external sentinel"


@pytest.mark.parametrize("run_id", ["run-1", "fw-../../escape", "fw-bad/name", "fw-bad\\name"])
def test_store_rejects_invalid_run_ids(project: Path, run_id: str) -> None:
    with pytest.raises(StateError, match="Invalid run id"):
        RunStore(project).directory(run_id)


def test_latest_returns_a_run_and_list_runs_ignores_invalid_records(project: Path) -> None:
    store = RunStore(project)
    first = _run(store)
    second = _run(store)
    assert store.latest().id in {first.id, second.id}

    invalid = store.base / "fw-invalid" / "run.json"
    invalid.parent.mkdir()
    invalid.write_text("not json", encoding="utf-8")

    assert {record.id for record in store.list_runs()} == {first.id, second.id}


def test_latest_errors_when_no_runs_exist(project: Path) -> None:
    with pytest.raises(StateError, match="No ForgeWard engagements"):
        RunStore(project).latest()
