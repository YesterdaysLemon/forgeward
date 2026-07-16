"""Deterministic SSDLC orchestration. Models propose; code and humans decide."""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

from forgeward.checks import run_check
from forgeward.context import collect_repository_context, manifest_json
from forgeward.models import (
    Deliverable,
    ForgeWardConfig,
    GateDecision,
    GateRecord,
    HumanFeedbackRecord,
    RecordedFinding,
    RoleSpec,
    RunRecord,
    RunState,
    Severity,
    utc_now,
)
from forgeward.prompts import build_request, parse_deliverable
from forgeward.providers import ProviderError, create_provider
from forgeward.security import (
    SafeWorkspace,
    SecurityViolation,
    linked_path_component,
    redact_text_with_count,
    resolve_external_executable,
    sanitize_terminal_text,
    sha256_bytes,
    sha256_text,
)
from forgeward.state import RunStore, StateError

_PLAN_ARTIFACTS = {
    "product": "planning/requirements.md",
    "designer": "design/experience.md",
    "security": "security/threat-model.md",
    "architect": "design/architecture.md",
    "scrum-master": "planning/backlog.md",
}
_VERIFY_ARTIFACTS = {
    "reviewer": "verification/code-review.md",
    "tester": "verification/test-review.md",
    "security": "verification/security-review.md",
}
_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
_MAX_GIT_STATUS_BYTES = 1_000_000
_MAX_DIRTY_PATHS = 10_000


class OrchestrationError(RuntimeError):
    pass


class ForgeWardEngine:
    def __init__(self, root: Path, config: ForgeWardConfig) -> None:
        self.root = root.resolve()
        self.config = config
        self.store = RunStore(self.root)

    def create_run(
        self,
        objective: str,
        *,
        provider: str | None = None,
        apply_changes: bool = False,
    ) -> RunRecord:
        objective = objective.strip()
        if not objective:
            raise OrchestrationError("Objective must not be empty")
        if len(objective.encode("utf-8")) > 20_000:
            raise OrchestrationError("Objective must be at most 20000 UTF-8 bytes")
        selected = provider or self.config.project.default_provider
        if selected not in self.config.providers:
            raise OrchestrationError(f"Unknown provider: {selected}")
        if not self.config.providers[selected].enabled:
            raise OrchestrationError(f"Provider is disabled: {selected}")
        base_commit = git_commit(self.root)
        if apply_changes:
            if base_commit is None:
                raise OrchestrationError(
                    "--apply requires a Git repository with at least one commit"
                )
            dirty = git_dirty_paths(self.root)
            if dirty:
                raise OrchestrationError(
                    "--apply requires a clean worktree; commit or stash changes first: "
                    + ", ".join(dirty[:8])
                )
        return self.store.create(
            objective,
            provider=selected,
            apply_changes=apply_changes,
            base_commit=base_commit,
        )

    def advance(self, record: RunRecord, *, plan_only: bool = False) -> RunRecord:
        self._assert_run_integrity(record, prefix="Run integrity check failed")
        if record.failure is not None:
            record.failure = None
            self.store.append_event(
                record,
                "run.resumed",
                actor="orchestrator",
                data={"state": record.state.value},
            )
        try:
            while True:
                if record.state == RunState.CREATED:
                    self.store.write_artifact(
                        record,
                        "request.md",
                        f"# Engagement request\n\n{record.objective}\n",
                        author="human",
                        kind="request",
                    )
                    self.store.set_state(record, RunState.INTAKE)
                    continue

                if record.state == RunState.INTAKE:
                    role_id = self.config.workflow.plan_roles[0]
                    deliverable = self._call_role(
                        record,
                        role_id,
                        _PLAN_ARTIFACTS.get(role_id, f"planning/{role_id}.md"),
                    )
                    self._write_acceptance_criteria(record, deliverable, author=role_id)
                    self.store.set_state(record, RunState.DISCOVERY)
                    continue

                if record.state == RunState.DISCOVERY:
                    split = max(1, len(self.config.workflow.plan_roles) - 2)
                    for role_id in self.config.workflow.plan_roles[1:split]:
                        self._call_role(
                            record,
                            role_id,
                            _PLAN_ARTIFACTS.get(role_id, f"planning/{role_id}.md"),
                        )
                    self.store.set_state(record, RunState.DESIGN)
                    continue

                if record.state == RunState.DESIGN:
                    split = max(1, len(self.config.workflow.plan_roles) - 2)
                    for role_id in self.config.workflow.plan_roles[split:]:
                        self._call_role(
                            record,
                            role_id,
                            _PLAN_ARTIFACTS.get(role_id, f"planning/{role_id}.md"),
                        )
                    self._enter_gate(record, "plan", RunState.PLAN_GATE)
                    if plan_only:
                        return record
                    continue

                if record.state == RunState.PLAN_GATE:
                    decision = record.gates["plan"].decision
                    if decision == GateDecision.PENDING:
                        return record
                    if decision == GateDecision.REJECTED:
                        self.store.set_state(record, RunState.INTAKE)
                        continue
                    if plan_only:
                        return record
                    self.store.set_state(record, RunState.EXECUTION)
                    continue

                if record.state == RunState.EXECUTION:
                    if record.apply_changes:
                        self._assert_workspace_integrity(record)
                    deliverable = self._call_role(
                        record, self.config.workflow.build_role, "build/implementation.md"
                    )
                    self._record_proposed_changes(record, deliverable)
                    if record.apply_changes:
                        self._apply_changes(record, deliverable)
                    self.store.set_state(record, RunState.VERIFICATION)
                    continue

                if record.state == RunState.VERIFICATION:
                    record.blockers = []
                    self._run_checks(record)
                    findings = []
                    for role_id in self.config.workflow.verification_roles:
                        deliverable = self._call_role(
                            record,
                            role_id,
                            _VERIFY_ARTIFACTS.get(role_id, f"verification/{role_id}.md"),
                        )
                        findings.extend(deliverable.findings)
                    release_draft = self._call_role(
                        record, self.config.workflow.release_role, "release/release-notes.md"
                    )
                    findings.extend(release_draft.findings)
                    self._calculate_blockers(record, findings)
                    self._enter_gate(record, "release", RunState.RELEASE_GATE)
                    continue

                if record.state == RunState.RELEASE_GATE:
                    decision = record.gates["release"].decision
                    if decision == GateDecision.PENDING:
                        return record
                    if decision == GateDecision.REJECTED:
                        self.store.set_state(record, RunState.EXECUTION)
                        continue
                    if record.apply_changes:
                        self._assert_workspace_integrity(record)
                    self.store.set_state(record, RunState.COMPLETE)
                    return record

                if record.state in {
                    RunState.COMPLETE,
                    RunState.FAILED,
                    RunState.CANCELLED,
                    RunState.PAUSED,
                }:
                    return record
                raise OrchestrationError(f"Unhandled run state: {record.state}")
        except (ProviderError, SecurityViolation, OrchestrationError, StateError) as exc:
            safe_message = sanitize_terminal_text(str(exc))
            record.failure = safe_message
            self.store.append_event(
                record,
                "run.interrupted",
                actor="orchestrator",
                data={"error_type": type(exc).__name__, "message": safe_message},
            )
            raise OrchestrationError(safe_message) from exc

    def approve_gate(self, record: RunRecord, gate_id: str, *, actor: str) -> RunRecord:
        self._assert_run_integrity(record, prefix="Evidence integrity check failed")
        gate = self._gate(record, gate_id)
        if gate.decision != GateDecision.PENDING:
            raise OrchestrationError(f"Gate {gate_id} is already {gate.decision.value}")
        if gate_id == "release" and record.apply_changes:
            self._assert_workspace_integrity(record)
        current_evidence = self._evidence_digest(record)
        if gate.evidence_sha256 != current_evidence:
            raise OrchestrationError(
                f"Evidence changed after gate {gate_id} opened; reject and regenerate the gate"
            )
        if gate_id == "release" and record.blockers:
            raise OrchestrationError("Release gate is blocked: " + "; ".join(record.blockers))
        clean_actor = _clean_actor(actor)
        gate.decision = GateDecision.APPROVED
        gate.actor = clean_actor
        gate.decided_at = utc_now()
        self.store.append_event(
            record,
            "gate.approved",
            actor=clean_actor,
            data={
                "gate": gate_id,
                "evidence_sha256": gate.evidence_sha256,
                "decided_at": gate.decided_at.isoformat(),
            },
        )
        return record

    def reject_gate(self, record: RunRecord, gate_id: str, *, actor: str, reason: str) -> RunRecord:
        self._assert_run_integrity(record, prefix="Evidence integrity check failed")
        gate = self._gate(record, gate_id)
        if gate.decision != GateDecision.PENDING:
            raise OrchestrationError(f"Gate {gate_id} is already {gate.decision.value}")
        clean_reason = sanitize_terminal_text(reason.strip())
        if not clean_reason:
            raise OrchestrationError("A rejection reason is required")
        if len(clean_reason) > 4_000:
            raise OrchestrationError("A rejection reason must be at most 4000 characters")
        clean_actor = _clean_actor(actor)
        feedback_path = f"feedback/{gate_id}-{len(record.feedback) + 1:02d}.json"
        feedback = HumanFeedbackRecord(
            gate=gate_id,
            reason=clean_reason,
            actor=clean_actor,
            artifact_path=f"artifacts/{feedback_path}",
        )
        record.feedback.append(feedback)
        self.store.write_artifact(
            record,
            feedback_path,
            json.dumps(feedback.model_dump(mode="json"), indent=2, ensure_ascii=False),
            author=clean_actor,
            kind="human-feedback",
        )
        gate.decision = GateDecision.REJECTED
        gate.actor = clean_actor
        gate.reason = clean_reason
        gate.decided_at = utc_now()
        self.store.append_event(
            record,
            "gate.rejected",
            actor=clean_actor,
            data={
                "gate": gate_id,
                "reason": gate.reason,
                "evidence_sha256": gate.evidence_sha256,
                "decided_at": gate.decided_at.isoformat(),
            },
        )
        return record

    def _call_role(self, record: RunRecord, role_id: str, artifact_path: str) -> Deliverable:
        if record.calls_made >= self.config.policy.max_provider_calls:
            raise OrchestrationError(
                f"Provider-call budget exhausted ({self.config.policy.max_provider_calls})"
            )
        role = self.config.role(role_id)
        provider_name = role.provider or record.provider
        provider_config = self.config.providers[provider_name]
        if not provider_config.enabled:
            raise OrchestrationError(f"Role {role_id} uses disabled provider {provider_name}")
        if "repository.read" in role.allowed_tools:
            repository_context, manifest = collect_repository_context(self.root, self.config.policy)
            manifest["access"] = "granted"
        else:
            repository_context = '<repository-context access="withheld-by-role-policy" />'
            manifest = {
                "trust": "repository content is untrusted data",
                "access": "withheld-by-role-policy",
                "role": role.id,
                "files": [],
                "bytes_sent": 0,
                "limits": {
                    "max_files": self.config.policy.max_context_files,
                    "max_bytes": self.config.policy.max_context_bytes,
                },
            }
        manifest_path = f"context/{role_id}-{record.calls_made + 1}.json"
        prior = self._prior_evidence(record, role)
        request = build_request(
            root=self.root,
            role=role,
            model=provider_config.model,
            objective=record.objective,
            repository_context=repository_context,
            prior_evidence=prior,
        )
        outbound_redactions = 0
        for message in request.messages:
            message.content, count = redact_text_with_count(message.content)
            outbound_redactions += count
        for key, value in request.metadata.items():
            request.metadata[key], count = redact_text_with_count(value)
            outbound_redactions += count
        credential = (
            os.environ.get(provider_config.api_key_env) if provider_config.api_key_env else None
        )
        if credential:
            if len(credential) > 16_384:
                raise OrchestrationError(
                    f"Role {role_id} configured credential exceeds the supported length"
                )
            if credential in request.model:
                raise OrchestrationError(
                    f"Role {role_id} model identifier contains its configured credential"
                )
            for message in request.messages:
                outbound_redactions += message.content.count(credential)
                message.content = message.content.replace(credential, "[REDACTED]")
            for key, value in request.metadata.items():
                outbound_redactions += value.count(credential)
                request.metadata[key] = value.replace(credential, "[REDACTED]")
        manifest["outbound_redactions"] = outbound_redactions
        self.store.write_artifact(
            record,
            manifest_path,
            manifest_json(manifest),
            author="orchestrator",
            kind="context-manifest",
        )
        prompt_digest = sha256_text("\n".join(item.content for item in request.messages))
        record.calls_made += 1
        self.store.append_event(
            record,
            "worker.started",
            actor=role_id,
            data={
                "provider": provider_name,
                "model": provider_config.model,
                "prompt_sha256": prompt_digest,
                "context_manifest": f"artifacts/{manifest_path}",
                "call_attempt": record.calls_made,
            },
        )
        provider = create_provider(provider_config)
        result = provider.complete(request)
        deliverable = parse_deliverable(result.content)
        self._validate_deliverable(deliverable, role_id)
        self.store.write_artifact(
            record,
            artifact_path,
            deliverable.artifact,
            author=role_id,
            kind="role-deliverable",
        )
        findings_path = f"findings/{record.calls_made:02d}-{role_id}.json"
        recorded_at = utc_now()
        recorded_findings = [
            RecordedFinding(
                **finding.model_dump(),
                role=role_id,
                provider=provider_name,
                model=result.model,
                artifact_path=f"artifacts/{findings_path}",
                recorded_at=recorded_at,
            )
            for finding in deliverable.findings
        ]
        record.findings.extend(recorded_findings)
        self.store.write_artifact(
            record,
            findings_path,
            json.dumps(
                [finding.model_dump(mode="json") for finding in recorded_findings],
                indent=2,
                ensure_ascii=False,
                sort_keys=True,
            ),
            author=role_id,
            kind="finding-set",
        )
        self.store.append_event(
            record,
            "worker.completed",
            actor=role_id,
            data={
                "provider": provider_name,
                "model": result.model,
                "finish_reason": result.finish_reason,
                "input_tokens": result.usage.input_tokens,
                "output_tokens": result.usage.output_tokens,
                "output_sha256": sha256_text(result.content),
                "finding_count": len(deliverable.findings),
                "findings_artifact": f"artifacts/{findings_path}",
                "proposed_change_count": len(deliverable.proposed_changes),
            },
        )
        return deliverable

    def _validate_deliverable(self, deliverable: Deliverable, role_id: str) -> None:
        role = self.config.role(role_id)
        if deliverable.proposed_changes and (
            role_id != self.config.workflow.build_role
            or "workspace.propose" not in role.allowed_tools
        ):
            raise OrchestrationError(f"Role {role_id} is not allowed to propose repository changes")
        for change in deliverable.proposed_changes:
            if len(change.content.encode("utf-8")) > self.config.policy.max_file_bytes:
                raise OrchestrationError(f"Proposed change exceeds size policy: {change.path}")

    def _prior_evidence(self, record: RunRecord, role: RoleSpec) -> str:
        allowed_kinds: set[str] = set()
        if "artifact.read" in role.allowed_tools:
            allowed_kinds.update(
                {
                    "request",
                    "role-deliverable",
                    "acceptance-criteria",
                    "finding-set",
                    "human-feedback",
                }
            )
        if "diff.read" in role.allowed_tools:
            allowed_kinds.add("change-proposal")
        if "check.read" in role.allowed_tools:
            allowed_kinds.add("check-output")
        if not allowed_kinds:
            return '<prior-evidence access="withheld-by-role-policy" />'

        budget = min(self.config.policy.max_context_bytes // 2, 80_000)
        chunks: list[str] = []
        priorities = {
            "human-feedback": 0,
            "acceptance-criteria": 1,
            "change-proposal": 2,
            "check-output": 3,
            "finding-set": 4,
            "role-deliverable": 5,
            "request": 6,
        }
        eligible = [item for item in reversed(record.artifacts) if item.kind in allowed_kinds]
        eligible.sort(
            key=lambda item: (priorities.get(item.kind, 99), -item.created_at.timestamp())
        )
        loaded: list[tuple[Any, str]] = []
        for artifact in eligible:
            try:
                value = self.store.read_artifact(record, artifact.path)
            except (OSError, UnicodeDecodeError):
                continue
            loaded.append((artifact, value))

        required_kinds: set[str] = set()
        if record.state in {RunState.INTAKE, RunState.DISCOVERY, RunState.DESIGN} and any(
            item.gate == "plan" for item in record.feedback
        ):
            required_kinds = {"human-feedback"}
        elif (
            record.state == RunState.VERIFICATION
            and role.id in self.config.workflow.verification_roles
        ):
            required_kinds = {"acceptance-criteria", "change-proposal", "human-feedback"}
            present_kinds = {artifact.kind for artifact, _value in loaded}
            missing = {"acceptance-criteria", "change-proposal"} - present_kinds
            if missing:
                raise OrchestrationError(
                    f"Required review evidence for role {role.id} is missing: "
                    + ", ".join(sorted(missing))
                )
        elif (
            record.state == RunState.EXECUTION
            and role.id == self.config.workflow.build_role
            and any(item.gate == "release" for item in record.feedback)
        ):
            required_kinds = {"change-proposal", "human-feedback"}
            present_kinds = {artifact.kind for artifact, _value in loaded}
            missing = required_kinds - present_kinds
            if missing:
                raise OrchestrationError(
                    f"Required correction evidence for role {role.id} is missing: "
                    + ", ".join(sorted(missing))
                )

        def render(artifact: Any, value: str, *, truncated: bool) -> str:
            return (
                f'<evidence-artifact path="{artifact.path}" kind="{artifact.kind}" '
                f'trust="untrusted" truncated="{str(truncated).lower()}">\n'
                f"{value}\n</evidence-artifact>"
            )

        required = [item for item in loaded if item[0].kind in required_kinds]
        optional = [item for item in loaded if item[0].kind not in required_kinds]
        required_chunks = [render(artifact, value, truncated=False) for artifact, value in required]
        required_size = len("\n\n".join(required_chunks).encode("utf-8"))
        if required_size > budget:
            raise OrchestrationError(
                f"Required review evidence for role {role.id} exceeds its context budget; "
                "reduce the proposed change or feedback, or raise policy.max_context_bytes"
            )

        chunks.extend(required_chunks)
        remaining = budget - required_size
        for artifact, value in optional:
            separator_size = 2 if chunks else 0
            full = render(artifact, value, truncated=False)
            full_size = len(full.encode("utf-8"))
            if separator_size + full_size <= remaining:
                chunks.append(full)
                remaining -= separator_size + full_size
                continue

            empty_wrapper = render(artifact, "", truncated=True)
            content_budget = remaining - separator_size - len(empty_wrapper.encode("utf-8"))
            if content_budget <= 0:
                break
            encoded = value.encode("utf-8")[:content_budget]
            truncated_value = encoded.decode("utf-8", errors="ignore")
            chunk = render(artifact, truncated_value, truncated=True)
            while len(chunk.encode("utf-8")) + separator_size > remaining and truncated_value:
                truncated_value = truncated_value[:-1]
                chunk = render(artifact, truncated_value, truncated=True)
            if len(chunk.encode("utf-8")) + separator_size > remaining:
                break
            chunks.append(chunk)
            remaining -= separator_size + len(chunk.encode("utf-8"))
            break

        if required_kinds and not required:
            raise OrchestrationError(
                f"Required review evidence for role {role.id} could not be loaded"
            )
        return "\n\n".join(chunks)

    def _write_acceptance_criteria(
        self, record: RunRecord, deliverable: Deliverable, *, author: str = "product"
    ) -> None:
        if not deliverable.acceptance_criteria:
            raise OrchestrationError(
                "The intake role must provide at least one acceptance criterion before planning"
            )
        content = "# Acceptance criteria\n\n" + "\n".join(
            f"- [ ] {item}" for item in deliverable.acceptance_criteria
        )
        self.store.write_artifact(
            record,
            "planning/acceptance-criteria.md",
            content + "\n",
            author=author,
            kind="acceptance-criteria",
        )

    def _record_proposed_changes(self, record: RunRecord, deliverable: Deliverable) -> None:
        content = json.dumps(
            [change.model_dump(mode="json") for change in deliverable.proposed_changes],
            indent=2,
            ensure_ascii=False,
        )
        self.store.write_artifact(
            record,
            "build/proposed-changes.json",
            content,
            author=self.config.workflow.build_role,
            kind="change-proposal",
        )

    def _apply_changes(self, record: RunRecord, deliverable: Deliverable) -> None:
        workspace = SafeWorkspace(
            self.root,
            self.config.policy.denied_paths,
            self.config.policy.max_file_bytes,
        )
        for change in deliverable.proposed_changes:
            destination, digest = workspace.apply(change)
            relative = str(destination.relative_to(self.root)).replace("\\", "/")
            record.workspace_changes[relative] = digest
            self.store.append_event(
                record,
                "workspace.change_applied",
                actor=self.config.workflow.build_role,
                data={"path": relative, "operation": change.operation, "sha256": digest},
            )

    def _run_checks(self, record: RunRecord) -> None:
        record.checks = []
        for index, spec in enumerate(self.config.checks, start=1):
            result, output = run_check(self.root, spec, self.config.policy)
            safe_name = "".join(
                char if char.isalnum() else "-" for char in spec.name.lower()
            ).strip("-")
            path = f"evidence/check-{index:02d}-{safe_name or 'check'}.log"
            artifact = self.store.write_artifact(
                record,
                path,
                output,
                author="orchestrator",
                kind="check-output",
                redact=True,
            )
            result.report_path = artifact.path
            record.checks.append(result)
            self.store.append_event(
                record,
                "check.completed",
                actor="orchestrator",
                data={
                    "name": result.name,
                    "status": result.status,
                    "exit_code": result.exit_code,
                    "output_sha256": result.output_sha256,
                    "required": result.required,
                    "report_path": result.report_path,
                },
            )

    def _calculate_blockers(self, record: RunRecord, findings: list[Any]) -> None:
        for check in record.checks:
            if check.required and check.status != "passed":
                name = sanitize_terminal_text(check.name)
                record.blockers.append(f"required check {name!r} is {check.status}")
        threshold = _SEVERITY_ORDER[self.config.policy.fail_on_severity]
        for finding in findings:
            if _SEVERITY_ORDER[finding.severity] >= threshold:
                title = sanitize_terminal_text(finding.title)
                record.blockers.append(f"{finding.severity.value} finding: {title}")
        blockers_json = json.dumps(
            record.blockers,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        self.store.append_event(
            record,
            "release.blockers_calculated",
            actor="orchestrator",
            data={
                "count": len(record.blockers),
                "blockers_sha256": sha256_text(blockers_json),
            },
        )

    def _enter_gate(self, record: RunRecord, gate_id: str, state: RunState) -> None:
        existing = record.gates.get(gate_id)
        if existing is None or existing.decision == GateDecision.REJECTED:
            record.gates[gate_id] = GateRecord(
                id=gate_id, evidence_sha256=self._evidence_digest(record)
            )
            self.store.append_event(
                record,
                "gate.opened",
                actor="orchestrator",
                data={
                    "gate": gate_id,
                    "blocker_count": len(record.blockers),
                    "evidence_sha256": record.gates[gate_id].evidence_sha256,
                },
            )
        if gate_id not in self.config.policy.human_gates and not record.blockers:
            gate = record.gates[gate_id]
            gate.decision = GateDecision.APPROVED
            gate.actor = "policy:auto"
            gate.decided_at = utc_now()
            self.store.append_event(
                record,
                "gate.approved",
                actor="policy:auto",
                data={
                    "gate": gate_id,
                    "evidence_sha256": gate.evidence_sha256,
                    "decided_at": gate.decided_at.isoformat(),
                },
            )
        self.store.set_state(record, state)

    def _evidence_digest(self, record: RunRecord) -> str:
        evidence = {
            "artifacts": [
                {"path": item.path, "sha256": item.sha256, "kind": item.kind}
                for item in sorted(record.artifacts, key=lambda value: value.path)
                if item.kind != "report"
            ],
            "checks": [
                {
                    "name": item.name,
                    "status": item.status,
                    "output_sha256": item.output_sha256,
                    "required": item.required,
                }
                for item in record.checks
            ],
            "workspace_changes": dict(sorted(record.workspace_changes.items())),
        }
        return sha256_text(json.dumps(evidence, sort_keys=True, separators=(",", ":")))

    def _gate(self, record: RunRecord, gate_id: str) -> GateRecord:
        gate = record.gates.get(gate_id)
        if gate is None:
            raise OrchestrationError(f"Gate does not exist on this engagement: {gate_id}")
        expected_state = RunState.PLAN_GATE if gate_id == "plan" else RunState.RELEASE_GATE
        if record.state != expected_state:
            raise OrchestrationError(
                f"Gate {gate_id} cannot be decided while run state is {record.state.value}"
            )
        return gate

    def _assert_run_integrity(self, record: RunRecord, *, prefix: str) -> None:
        try:
            self.store.verify_projection(record)
            self.store.verify_artifacts(record)
        except StateError as exc:
            raise OrchestrationError(f"{prefix}: {exc}") from exc

    def _assert_workspace_integrity(self, record: RunRecord) -> None:
        if git_commit(self.root) != record.base_commit:
            raise OrchestrationError("Git HEAD changed since the engagement started")
        dirty = git_dirty_paths(self.root)
        expected = set(record.workspace_changes)
        unexpected = sorted(set(dirty) - expected)
        if unexpected:
            raise OrchestrationError(
                "Worktree contains changes outside this engagement: " + ", ".join(unexpected[:8])
            )
        for relative, expected_digest in record.workspace_changes.items():
            path = self.root / relative
            linked = linked_path_component(self.root, path)
            if linked is not None:
                raise OrchestrationError(
                    f"Workspace path became linked/reparse content: {relative}"
                )
            if not path.is_file() or sha256_bytes(path.read_bytes()) != expected_digest:
                raise OrchestrationError(
                    f"Workspace file changed outside ForgeWard since application: {relative}"
                )


def git_commit(root: Path) -> str | None:
    git = resolve_external_executable(root, "git")
    if git is None:
        return None
    try:
        completed = subprocess.run(  # noqa: S603 - resolved Git binary, constant arguments
            [git, "rev-parse", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        return completed.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def git_dirty_paths(root: Path) -> list[str]:
    git = resolve_external_executable(root, "git")
    if git is None:
        raise OrchestrationError("Git is unavailable; cannot verify worktree integrity")
    output, _status = _bounded_git_status(git, root)
    if output is None:
        raise OrchestrationError(
            "Git worktree inspection failed; refusing to treat the worktree as clean"
        )
    try:
        entries = [item.decode("utf-8") for item in output.split(b"\x00") if item]
    except UnicodeDecodeError as exc:
        raise OrchestrationError(
            "Git worktree inspection failed; refusing to treat the worktree as clean"
        ) from exc
    paths: list[str] = []
    index = 0
    try:
        while index < len(entries):
            entry = entries[index]
            index += 1
            if len(entry) < 4 or entry[2] != " ":
                raise ValueError("malformed porcelain entry")
            change_status = entry[:2]
            value = entry[3:]
            if not value:
                raise ValueError("empty porcelain path")
            paths.append(value.replace("\\", "/"))
            if "R" in change_status or "C" in change_status:
                if index >= len(entries) or not entries[index]:
                    raise ValueError("missing rename source")
                paths.append(entries[index].replace("\\", "/"))
                index += 1
            if len(paths) > _MAX_DIRTY_PATHS:
                raise ValueError("too many dirty paths")
    except ValueError as exc:
        raise OrchestrationError(
            "Git worktree inspection failed; refusing to treat the worktree as clean"
        ) from exc
    return paths


def _bounded_git_status(git: Path, root: Path) -> tuple[bytes | None, str]:
    """Read an unambiguous Git status stream with a hard memory and time ceiling."""
    try:
        process = subprocess.Popen(  # noqa: S603 - trusted Git binary, constant arguments
            [
                str(git),
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
            ],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return None, "failed"
    stream = process.stdout
    if stream is None:
        process.kill()
        return None, "failed"
    output = bytearray()
    overflow = threading.Event()
    read_failed = threading.Event()

    def read_output() -> None:
        try:
            while chunk := stream.read(64 * 1_024):
                available = _MAX_GIT_STATUS_BYTES - len(output)
                if len(chunk) > available:
                    output.extend(chunk[: max(available, 0)])
                    overflow.set()
                    return
                output.extend(chunk)
        except OSError:
            read_failed.set()

    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    deadline = time.monotonic() + 10
    while process.poll() is None:
        if overflow.is_set():
            process.kill()
            with suppress(subprocess.SubprocessError):
                process.wait(timeout=2)
            reader.join(timeout=1)
            return None, "overflow"
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            process.kill()
            with suppress(subprocess.SubprocessError):
                process.wait(timeout=2)
            reader.join(timeout=1)
            return None, "timeout"
        try:
            process.wait(timeout=min(0.1, remaining))
        except subprocess.TimeoutExpired:
            continue
    reader.join(timeout=1)
    if reader.is_alive() or overflow.is_set() or read_failed.is_set() or process.returncode != 0:
        return None, "failed"
    return bytes(output), "ok"


def human_actor() -> str:
    user = os.environ.get("GITHUB_USER") or os.environ.get("USERNAME") or os.environ.get("USER")
    normalized = " ".join(sanitize_terminal_text(user or "local").split())[:180]
    return f"human:{normalized or 'local'}"


def _clean_actor(actor: str) -> str:
    clean = " ".join(sanitize_terminal_text(actor).split())
    if not clean:
        raise OrchestrationError("Gate actor must not be empty")
    if len(clean) > 200:
        raise OrchestrationError("Gate actor must be at most 200 characters")
    return clean
