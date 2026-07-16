"""Human-readable engagement reports."""

from __future__ import annotations

from forgeward.models import RunRecord
from forgeward.security import redact_text
from forgeward.state import RunStore


def markdown_report(record: RunRecord, store: RunStore) -> str:
    events = store.events(record.id, verify=True)
    lines = [
        f"# ForgeWard engagement {record.id}",
        "",
        f"**Objective:** {_single_line(record.objective)}",
        f"**State:** `{record.state.value}`",
        f"**Provider route:** `{_single_line(record.provider)}`",
        f"**Repository writes enabled:** `{'yes' if record.apply_changes else 'no'}`",
        f"**Base commit:** `{_single_line(record.base_commit or 'not available')}`",
        f"**Provider calls:** `{record.calls_made}`",
        f"**Ledger head:** `{record.last_event_hash or 'none'}`",
        "",
    ]
    if record.provider == "demo":
        lines.extend(
            [
                "> [!WARNING]",
                "> This engagement used the deterministic demo provider. It demonstrates the",
                "> workflow but is not substantive product, engineering, testing, or security",
                "> review.",
                "",
            ]
        )
    lines.extend(["## Gates", ""])
    if not record.gates:
        lines.append("No gates have opened.")
    for gate_id, gate in record.gates.items():
        actor = _single_line(gate.actor or "—")
        lines.append(f"- **{_single_line(gate_id)}:** `{gate.decision.value}` · actor: `{actor}`")
        if gate.evidence_sha256:
            lines.append(f"  - Evidence digest: `{gate.evidence_sha256}`")
        if gate.reason:
            lines.append(f"  - Reason: {_single_line(gate.reason)}")
    lines.extend(["", "## Release blockers", ""])
    lines.extend([f"- {_single_line(item)}" for item in record.blockers] or ["- None recorded."])
    lines.extend(["", "## Human feedback history", ""])
    if record.feedback:
        for feedback in record.feedback:
            lines.append(
                f"- **{_single_line(feedback.gate)} gate:** {_single_line(feedback.reason)}"
            )
            lines.append(
                f"  - Actor: `{_single_line(feedback.actor)}` · record: "
                f"`{_single_line(feedback.artifact_path)}`"
            )
    else:
        lines.append("- None recorded.")
    lines.extend(["", "## Recorded findings", ""])
    if record.findings:
        for finding in record.findings:
            lines.append(
                f"- **{finding.severity.value.upper()} — {_single_line(finding.title)}** "
                f"· role `{_single_line(finding.role)}` · model `{_single_line(finding.model)}`"
            )
            lines.append(f"  - {_single_line(finding.detail)}")
            if finding.evidence:
                lines.append(f"  - Evidence: {_single_line(finding.evidence)}")
            lines.append(f"  - Structured record: `{_single_line(finding.artifact_path)}`")
    else:
        lines.append("- None recorded.")
    lines.extend(["", "## Deterministic checks", ""])
    if record.checks:
        lines.extend(
            f"- **{_single_line(check.name)}:** `{check.status}` · exit: `{check.exit_code}` · "
            f"evidence: `{_single_line(check.report_path or 'none')}`"
            for check in record.checks
        )
    else:
        lines.append("- No project checks were configured.")
    lines.extend(["", "## Workspace changes", ""])
    if record.workspace_changes:
        lines.extend(
            f"- `{_single_line(path)}` · `{digest}`"
            for path, digest in record.workspace_changes.items()
        )
    else:
        lines.append("- No repository files were applied.")
    lines.extend(["", "## Evidence artifacts", ""])
    lines.extend(
        f"- `{_single_line(artifact.path)}` · {_single_line(artifact.kind)} · "
        f"author `{_single_line(artifact.author)}` · `{artifact.sha256}`"
        for artifact in record.artifacts
        if artifact.kind != "report"
    )
    lines.extend(
        [
            "",
            "## Audit ledger",
            "",
            f"The event ledger contains {len(events)} hash-chained events. Ledger verification",
            "succeeded when this report was generated.",
            "",
            "---",
            "Generated locally by ForgeWard. Provider output and repository content remain",
            "untrusted data.",
            "",
        ]
    )
    return "\n".join(lines)


def _single_line(value: str) -> str:
    rendered = " ".join(redact_text(value).split())
    rendered = rendered.replace("\\", "\\\\")
    for character in "`[]()<>*_#|!":
        rendered = rendered.replace(character, f"\\{character}")
    return rendered
