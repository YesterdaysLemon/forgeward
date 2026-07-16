from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from forgeward.cli import app
from forgeward.config import config_path
from forgeward.models import RunState, __version__
from forgeward.state import RunStore


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def test_cli_version_smoke(runner: CliRunner) -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert f"ForgeWard {__version__}" in result.stdout


def test_cli_help_smoke(runner: CliRunner) -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Run a gated, evidence-led AI software team" in result.stdout
    assert "doctor" in result.stdout
    assert "context" in result.stdout
    assert "provider" in result.stdout


def test_cli_init_and_read_only_inspection_commands(tmp_path: Path, runner: CliRunner) -> None:
    project = tmp_path / "cli-project"
    project.mkdir()

    result = runner.invoke(app, ["init", str(project)])
    assert result.exit_code == 0, result.output
    assert "ForgeWard initialized" in result.stdout
    assert (project / ".forgeward" / "firm.yaml").is_file()

    commands = [
        (["doctor", "--root", str(project)], "Configuration"),
        (["context", "preview", "--root", str(project)], "Provider context preview"),
        (["provider", "list", "--root", str(project)], "Model provider routes"),
        (["provider", "test", "demo", "--root", str(project)], "offline deterministic"),
        (["team", "list", "--root", str(project)], "ForgeWard firm"),
        (["team", "validate", "--root", str(project)], "no self-approval authority"),
        (["policy", "check", "--root", str(project)], "Deterministic policy checks"),
    ]
    for arguments, expected in commands:
        result = runner.invoke(app, arguments)
        assert result.exit_code == 0, result.output
        assert expected in result.stdout


def test_cli_reports_config_error_with_nonzero_exit(tmp_path: Path, runner: CliRunner) -> None:
    result = runner.invoke(app, ["doctor", "--root", str(tmp_path)])

    assert result.exit_code == 1
    assert "Error:" in result.stderr
    assert "Could not read" in result.stderr


def test_doctor_fails_when_default_provider_is_disabled(project: Path, runner: CliRunner) -> None:
    path = config_path(project)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["providers"]["demo"]["enabled"] = False
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")

    result = runner.invoke(app, ["doctor", "--root", str(project)])

    assert result.exit_code == 1
    assert "Default provider" in result.stdout
    assert "disabled" in result.stdout


def test_config_load_rejects_invalid_provider_route_before_doctor(
    project: Path, runner: CliRunner
) -> None:
    path = config_path(project)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["project"]["default_provider"] = "local"
    raw["providers"]["local"]["enabled"] = True
    raw["providers"]["local"]["base_url"] = "not-an-http-url"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")

    result = runner.invoke(app, ["doctor", "--live", "--root", str(project)])

    assert result.exit_code == 1
    assert "invalid_base_url" in result.stderr
    assert result.exception is not None


def test_provider_list_never_echoes_credentialed_endpoint(project: Path, runner: CliRunner) -> None:
    path = config_path(project)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    sentinel = "OPAQUE_PROVIDER_LIST_PASSWORD_SENTINEL"
    raw["providers"]["local"]["base_url"] = f"https://user:{sentinel}@models.example.test/v1"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")

    result = runner.invoke(app, ["provider", "list", "--root", str(project)])

    assert result.exit_code == 1
    assert "invalid_base_url" in result.stderr
    assert sentinel not in result.output


def test_doctor_warns_when_litellm_owns_native_transport(project: Path, runner: CliRunner) -> None:
    path = config_path(project)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["providers"]["native"]["enabled"] = True
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")

    result = runner.invoke(app, ["doctor", "--root", str(project)])

    assert result.exit_code == 0, result.output
    assert "Provider transport" in result.stdout
    assert "LiteLLM-native transport delegated: native" in result.stdout


def test_doctor_warns_on_enabled_cleartext_transport_opt_in(
    project: Path, runner: CliRunner
) -> None:
    path = config_path(project)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["providers"]["local"]["enabled"] = True
    raw["providers"]["local"]["base_url"] = "http://gateway.internal.test/v1"
    raw["providers"]["local"]["allow_insecure_http"] = True
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")

    result = runner.invoke(app, ["doctor", "--root", str(project)])

    assert result.exit_code == 0, result.output
    assert "Provider transport" in result.stdout
    assert "cleartext opt-in: local" in result.stdout


def test_cli_demo_engagement_full_lifecycle_and_evidence_commands(
    project: Path, runner: CliRunner
) -> None:
    result = runner.invoke(
        app,
        ["run", "Exercise the complete CLI lifecycle", "--root", str(project)],
    )
    assert result.exit_code == 0, result.output
    store = RunStore(project)
    record = store.latest()
    assert record.state == RunState.PLAN_GATE

    result = runner.invoke(app, ["approve", record.id, "plan", "--root", str(project)])
    assert result.exit_code == 0, result.output
    assert "Approved" in result.stdout

    result = runner.invoke(app, ["resume", record.id, "--root", str(project)])
    assert result.exit_code == 0, result.output
    record = store.load(record.id)
    assert record.state == RunState.RELEASE_GATE

    result = runner.invoke(app, ["approve", record.id, "release", "--root", str(project)])
    assert result.exit_code == 0, result.output
    result = runner.invoke(app, ["resume", record.id, "--root", str(project)])
    assert result.exit_code == 0, result.output
    assert store.load(record.id).state == RunState.COMPLETE

    result = runner.invoke(app, ["status", record.id, "--json", "--root", str(project)])
    assert result.exit_code == 0, result.output
    assert '"state": "complete"' in result.stdout

    result = runner.invoke(app, ["inspect", record.id, "--root", str(project)])
    assert result.exit_code == 0, result.output
    assert "Verified audit ledger" in result.stdout

    result = runner.invoke(app, ["report", record.id, "--root", str(project)])
    assert result.exit_code == 0, result.output
    assert (store.directory(record.id) / "artifacts" / "reports" / "engagement-report.md").is_file()

    result = runner.invoke(app, ["export", record.id, "--root", str(project)])
    assert result.exit_code == 0, result.output
    assert (project / ".forgeward" / "exports" / f"{record.id}-evidence.zip").is_file()


def test_cli_plan_command_stops_at_plan_gate(project: Path, runner: CliRunner) -> None:
    result = runner.invoke(
        app,
        ["plan", "Create planning evidence only", "--root", str(project)],
    )

    assert result.exit_code == 0, result.output
    record = RunStore(project).latest()
    assert record.state == RunState.PLAN_GATE
    assert record.calls_made == 5
    assert "Review it" in result.stdout


@pytest.mark.parametrize("command", ["status", "inspect", "report", "export"])
def test_evidence_commands_fail_closed_on_modified_artifact(
    project: Path, runner: CliRunner, command: str
) -> None:
    result = runner.invoke(
        app,
        ["plan", "Create evidence to tamper with", "--root", str(project)],
    )
    assert result.exit_code == 0, result.output
    store = RunStore(project)
    record = store.latest()
    artifact = next(item for item in record.artifacts if item.kind == "role-deliverable")
    (store.directory(record.id) / artifact.path).write_text("tampered", encoding="utf-8")

    arguments = [command, record.id, "--root", str(project)]
    result = runner.invoke(app, arguments)

    assert result.exit_code == 1
    assert "Artifact integrity failed" in result.stderr
    assert not (
        store.directory(record.id) / "artifacts" / "reports" / "engagement-report.md"
    ).exists()
    assert not (store.exports / f"{record.id}-evidence.zip").exists()
