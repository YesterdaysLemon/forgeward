"""Append-only run events and atomic run projections."""

from __future__ import annotations

import json
import os
import secrets
import tempfile
import zipfile
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from forgeward.models import ArtifactRecord, RunRecord, RunState, utc_now
from forgeward.security import linked_path_component, redact_text, sha256_bytes, sha256_text


class StateError(RuntimeError):
    pass


class RunStore:
    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root.resolve()
        self.base = self.project_root / ".forgeward" / "runs"
        self.exports = self.project_root / ".forgeward" / "exports"
        _reject_symlink_components(self.project_root, self.project_root / ".forgeward")
        _reject_symlink_components(self.project_root, self.base)
        _reject_symlink_components(self.project_root, self.exports)
        self.base.mkdir(parents=True, exist_ok=True)
        self.exports.mkdir(parents=True, exist_ok=True)

    def create(
        self,
        objective: str,
        *,
        provider: str,
        apply_changes: bool,
        base_commit: str | None,
    ) -> RunRecord:
        timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        run_id = f"fw-{timestamp}-{secrets.token_hex(3)}"
        directory = self.directory(run_id)
        directory.mkdir(parents=True, exist_ok=False)
        (directory / "artifacts").mkdir()
        (directory / "evidence").mkdir()
        record = RunRecord(
            id=run_id,
            objective=objective,
            provider=provider,
            apply_changes=apply_changes,
            base_commit=base_commit,
        )
        self.save(record)
        self.append_event(
            record,
            "run.created",
            actor="human",
            data={
                "objective_sha256": sha256_text(objective),
                "provider": provider,
                "apply_changes": apply_changes,
                "base_commit": base_commit,
            },
        )
        return record

    def directory(self, run_id: str) -> Path:
        if not run_id.startswith("fw-") or any(char in run_id for char in "/\\\x00"):
            raise StateError(f"Invalid run id: {run_id}")
        return self.base / run_id

    def load(self, run_id: str) -> RunRecord:
        path = self.directory(run_id) / "run.json"
        _reject_symlink_components(self.project_root, path)
        try:
            return RunRecord.model_validate_json(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise StateError(f"Run not found: {run_id}") from exc
        except ValueError as exc:
            raise StateError(f"Run state is invalid: {run_id}") from exc

    def latest(self) -> RunRecord:
        candidates = sorted(
            (path for path in self.base.glob("fw-*/run.json") if path.is_file()),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        if not candidates:
            raise StateError("No ForgeWard engagements found")
        return RunRecord.model_validate_json(candidates[0].read_text(encoding="utf-8"))

    def list_runs(self) -> list[RunRecord]:
        records: list[RunRecord] = []
        for path in self.base.glob("fw-*/run.json"):
            try:
                records.append(RunRecord.model_validate_json(path.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                continue
        return sorted(records, key=lambda item: item.created_at, reverse=True)

    def save(self, record: RunRecord) -> None:
        record.updated_at = utc_now()
        path = self.directory(record.id) / "run.json"
        _reject_symlink_components(self.project_root, path)
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".run-", suffix=".json.tmp", dir=path.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(record.model_dump_json(indent=2))
                handle.flush()
                os.fsync(handle.fileno())
            temporary.replace(path)
        except Exception:
            with suppress(OSError):
                os.close(descriptor)
            temporary.unlink(missing_ok=True)
            raise

    def append_event(
        self,
        record: RunRecord,
        event_type: str,
        *,
        actor: str,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        event: dict[str, Any] = {
            "seq": record.event_count + 1,
            "timestamp": utc_now().isoformat(),
            "type": event_type,
            "actor": actor,
            "data": data or {},
            "previous_hash": record.last_event_hash,
            "projection_sha256": self.projection_sha256(record),
        }
        canonical = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        event["hash"] = sha256_text(canonical)
        path = self.directory(record.id) / "events.jsonl"
        _reject_symlink_components(self.project_root, path)
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n")
        record.event_count = int(event["seq"])
        record.last_event_hash = str(event["hash"])
        self.save(record)
        return event

    def events(self, run_id: str, *, verify: bool = True) -> list[dict[str, Any]]:
        path = self.directory(run_id) / "events.jsonl"
        _reject_symlink_components(self.project_root, path)
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise StateError(f"Event ledger missing for {run_id}") from exc
        events: list[dict[str, Any]] = []
        previous: str | None = None
        for expected_seq, line in enumerate(lines, start=1):
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise StateError(f"Malformed event {expected_seq} in {run_id}") from exc
            if verify:
                claimed = event.pop("hash", None)
                canonical = json.dumps(
                    event, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                )
                calculated = sha256_text(canonical)
                event["hash"] = claimed
                if event.get("seq") != expected_seq or event.get("previous_hash") != previous:
                    raise StateError(f"Event chain order failed at event {expected_seq}")
                if claimed != calculated:
                    raise StateError(f"Event hash failed at event {expected_seq}")
                previous = claimed
            events.append(event)
        if verify:
            projection = self.load(run_id)
            if len(events) != projection.event_count:
                raise StateError(
                    f"Event ledger length is {len(events)}; projection expects "
                    f"{projection.event_count}"
                )
            if previous != projection.last_event_hash:
                raise StateError("Event ledger head does not match the run projection")
            self._verify_projection_checkpoint(projection, events)
        return events

    def projection_sha256(self, record: RunRecord) -> str:
        """Digest semantic run state while excluding mutable ledger bookkeeping."""
        projection = record.model_dump(
            mode="json",
            exclude={"updated_at", "event_count", "last_event_hash"},
        )
        canonical = json.dumps(
            projection,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return sha256_text(canonical)

    def verify_projection(self, record: RunRecord) -> None:
        """Bind a supplied/in-memory projection to the verified on-disk ledger."""
        events = self.events(record.id, verify=True)
        self._verify_projection_checkpoint(record, events)

    def _verify_projection_checkpoint(
        self,
        record: RunRecord,
        events: list[dict[str, Any]],
    ) -> None:
        if not events:
            raise StateError("Event ledger has no semantic projection checkpoint")
        expected = events[-1].get("projection_sha256")
        if not isinstance(expected, str) or expected != self.projection_sha256(record):
            raise StateError("Run projection does not match the hash-chained semantic checkpoint")

    def write_artifact(
        self,
        record: RunRecord,
        relative_path: str,
        content: str,
        *,
        author: str,
        kind: str,
        redact: bool = False,
    ) -> ArtifactRecord:
        normalized = relative_path.replace("\\", "/").strip("/")
        if not normalized or ".." in Path(normalized).parts or "\x00" in normalized:
            raise StateError(f"Unsafe artifact path: {relative_path}")
        run_root = self.directory(record.id)
        unresolved_artifact_root = run_root / "artifacts"
        unresolved_destination = unresolved_artifact_root / normalized
        _reject_symlink_components(self.project_root, unresolved_destination)
        artifact_root = unresolved_artifact_root.resolve()
        destination = unresolved_destination.resolve(strict=False)
        try:
            destination.relative_to(artifact_root)
        except ValueError as exc:
            raise StateError(f"Artifact escapes run directory: {relative_path}") from exc
        destination.parent.mkdir(parents=True, exist_ok=True)
        value = redact_text(content) if redact else content
        destination.write_text(value, encoding="utf-8", newline="\n")
        digest = sha256_bytes(destination.read_bytes())
        artifact = ArtifactRecord(
            path=str(destination.relative_to(self.directory(record.id))).replace("\\", "/"),
            sha256=digest,
            author=author,
            kind=kind,
        )
        record.artifacts = [item for item in record.artifacts if item.path != artifact.path]
        record.artifacts.append(artifact)
        self.append_event(
            record,
            "artifact.written",
            actor=author,
            data={"path": artifact.path, "sha256": artifact.sha256, "kind": kind},
        )
        return artifact

    def read_artifact(self, record: RunRecord, path: str) -> str:
        unresolved = self.directory(record.id) / path
        _reject_symlink_components(self.project_root, unresolved)
        destination = unresolved.resolve()
        try:
            destination.relative_to(self.directory(record.id).resolve())
        except ValueError as exc:
            raise StateError(f"Artifact escapes run directory: {path}") from exc
        return destination.read_text(encoding="utf-8")

    def verify_artifacts(self, record: RunRecord) -> None:
        run_root = self.directory(record.id).resolve()
        for artifact in record.artifacts:
            relative = Path(artifact.path)
            if relative.is_absolute() or ".." in relative.parts:
                raise StateError(f"Artifact path escapes run directory: {artifact.path}")
            unresolved = run_root / relative
            _reject_symlink_components(self.project_root, unresolved)
            destination = unresolved.resolve()
            try:
                destination.relative_to(run_root)
            except ValueError as exc:
                raise StateError(f"Artifact path escapes run directory: {artifact.path}") from exc
            try:
                digest = sha256_bytes(destination.read_bytes())
            except OSError as exc:
                raise StateError(f"Artifact is missing: {artifact.path}") from exc
            if digest != artifact.sha256:
                raise StateError(f"Artifact integrity failed: {artifact.path}")

    def export_redacted(self, record: RunRecord) -> Path:
        self.verify_projection(record)
        self.verify_artifacts(record)
        output = self.exports / f"{record.id}-evidence.zip"
        run_dir = self.directory(record.id)
        _reject_symlink_components(self.project_root, output)
        if output.is_symlink():
            raise StateError(f"Refusing to replace symlinked evidence export: {output}")
        candidates = {
            run_dir / "run.json",
            run_dir / "events.jsonl",
            *(run_dir / artifact.path for artifact in record.artifacts),
        }
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(candidates):
                _reject_symlink_components(self.project_root, path)
                if not path.is_file():
                    raise StateError(f"Evidence file is missing: {path.relative_to(run_dir)}")
                relative = path.relative_to(run_dir)
                try:
                    value = path.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    continue
                archive.writestr(str(relative).replace("\\", "/"), redact_text(value))
        return output

    def set_state(self, record: RunRecord, state: RunState, *, actor: str = "orchestrator") -> None:
        previous = record.state
        record.state = state
        self.append_event(
            record,
            "run.state_changed",
            actor=actor,
            data={"from": previous.value, "to": state.value},
        )


def _reject_symlink_components(base: Path, candidate: Path) -> None:
    try:
        candidate.absolute().relative_to(base.absolute())
    except ValueError as exc:
        raise StateError(f"State path escapes the project: {candidate}") from exc
    linked = linked_path_component(base, candidate)
    if linked is not None:
        raise StateError(f"Linked/reparse state path is not allowed: {linked}")
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(base.resolve())
    except ValueError as exc:
        raise StateError(f"State path resolves outside the project: {candidate}") from exc
