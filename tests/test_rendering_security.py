from __future__ import annotations

from io import StringIO

import pytest
import typer
from rich.console import Console

import forgeward.cli as cli_module
from forgeward.models import RecordedFinding, RunRecord
from forgeward.orchestrator import OrchestrationError
from forgeward.reporting import markdown_report
from forgeward.state import RunStore

MALICIOUS_TEXT = "[link=https://evil.example]review[/link]\x1b[31mINJECTED\x1b[0m\x1b]0;OWNED\x07"


def _terminal_console(buffer: StringIO, *, stderr: bool = False) -> Console:
    return Console(
        file=buffer,
        stderr=stderr,
        force_terminal=True,
        color_system="standard",
        width=120,
    )


def test_run_panel_treats_provider_blockers_and_failures_as_plain_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    buffer = StringIO()
    monkeypatch.setattr(cli_module, "console", _terminal_console(buffer))
    record = RunRecord(
        id="fw-20260716-000000-abcdef",
        objective="render safely",
        provider=MALICIOUS_TEXT,
        blockers=[MALICIOUS_TEXT],
        failure=MALICIOUS_TEXT,
    )

    cli_module._print_run(record)

    rendered = buffer.getvalue()
    assert "INJECTED" in rendered
    assert "\x1b]8;" not in rendered
    assert "\x1b[31mINJECTED" not in rendered
    assert "\x1b]0;OWNED" not in rendered
    assert "\x07" not in rendered


def test_error_sink_treats_exception_text_as_plain_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    buffer = StringIO()
    monkeypatch.setattr(cli_module, "err_console", _terminal_console(buffer, stderr=True))

    with pytest.raises(typer.Exit):
        cli_module._fail(OrchestrationError(MALICIOUS_TEXT))

    rendered = buffer.getvalue()
    assert "INJECTED" in rendered
    assert "\x1b]8;" not in rendered
    assert "\x1b[31mINJECTED" not in rendered
    assert "\x1b]0;OWNED" not in rendered
    assert "\x07" not in rendered


def test_markdown_report_escapes_untrusted_finding_markup(project) -> None:
    store = RunStore(project)
    record = store.create(
        "[unsafe](https://evil.example)",
        provider="demo",
        apply_changes=False,
        base_commit=None,
    )
    record.findings.append(
        RecordedFinding(
            severity="low",
            title=MALICIOUS_TEXT,
            detail="[click](https://evil.example)",
            evidence="<script>alert(1)</script>",
            role="security",
            provider="demo",
            model="synthetic",
            artifact_path="artifacts/findings/test.json",
        )
    )
    store.append_event(record, "test.finding_recorded", actor="test")

    report = markdown_report(record, store)

    assert "\\[unsafe\\]\\(https://evil.example\\)" in report
    assert "\\[click\\]\\(https://evil.example\\)" in report
    assert "\\<script\\>" in report
    assert "\x1b" not in report
    assert "\x07" not in report
