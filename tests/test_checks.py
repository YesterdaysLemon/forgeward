from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

import forgeward.checks as checks_module
from forgeward.checks import run_check
from forgeward.models import CheckSpec, PolicyConfig
from forgeward.security import sha256_text


def _policy(**overrides: object) -> PolicyConfig:
    values: dict[str, object] = {
        "allowed_executables": [sys.executable],
        "max_output_chars": 4_000,
    }
    values.update(overrides)
    return PolicyConfig.model_validate(values)


def _spec(*command: str, required: bool = True) -> CheckSpec:
    return CheckSpec(
        name="deterministic test",
        command=list(command),
        timeout_seconds=10,
        required=required,
    )


def test_run_check_executes_argv_without_shell_and_redacts_output(tmp_path: Path) -> None:
    script = (
        "import os, sys; "
        "print('check=' + os.environ['FORGEWARD_CHECK']); "
        "print('token=super-secret-token'); "
        "print('warning', file=sys.stderr)"
    )
    result, output = run_check(
        tmp_path,
        _spec(sys.executable, "-c", script),
        _policy(),
    )

    assert result.status == "passed"
    assert result.exit_code == 0
    assert result.required is True
    assert result.duration_seconds >= 0
    assert "check=1" in output
    assert "warning" in output
    assert "super-secret-token" not in output
    assert "[REDACTED]" in output
    assert result.output_sha256 == sha256_text(output)


def test_run_check_preserves_nonzero_exit_as_failed_evidence(tmp_path: Path) -> None:
    result, output = run_check(
        tmp_path,
        _spec(sys.executable, "-c", "import sys; print('failed'); sys.exit(7)", required=False),
        _policy(),
    )

    assert result.status == "failed"
    assert result.exit_code == 7
    assert result.required is False
    assert "failed" in output


def test_run_check_rejects_non_allowlisted_executable_without_spawning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("check process must not be called")

    monkeypatch.setattr(checks_module, "_run_process", forbidden)
    result, output = run_check(
        tmp_path,
        _spec("powershell", "-Command", "Write-Output should-not-run"),
        _policy(),
    )

    assert result.status == "skipped"
    assert result.exit_code is None
    assert result.output_sha256 is None
    assert output == "Command rejected by policy: powershell is not allowlisted.\n"


def test_run_check_rejects_path_by_basename_allowlist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "TOOLS" / "PYTEST.EXE"

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("subprocess.run must not be called")

    monkeypatch.setattr(checks_module, "_run_process", forbidden)
    result, output = run_check(
        tmp_path,
        _spec(str(executable), "--version"),
        _policy(allowed_executables=["pytest"]),
    )

    assert result.status == "skipped"
    assert "exact absolute-path allowlist" in output


@pytest.mark.parametrize("requested", ["./python", r".\\python", "/tmp/python"])
def test_run_check_rejects_spoofed_executable_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, requested: str
) -> None:
    monkeypatch.setattr(
        checks_module,
        "_run_process",
        lambda *args, **kwargs: pytest.fail("check process must not be called"),
    )

    result, _ = run_check(tmp_path, _spec(requested), _policy(allowed_executables=["python"]))

    assert result.status == "skipped"


def test_run_check_accepts_exact_absolute_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: dict[str, Any] = {}

    def fake_run(command: list[str], **kwargs: Any) -> tuple[int, bytes, bool, bool, bool]:
        observed["command"] = command
        observed.update(kwargs)
        return 0, b"ok", False, False, False

    monkeypatch.setattr(checks_module, "_run_process", fake_run)
    result, output = run_check(
        tmp_path,
        _spec(sys.executable, "--version"),
        _policy(allowed_executables=[sys.executable]),
    )

    assert result.status == "passed"
    assert observed["command"] == [str(Path(sys.executable).resolve()), "--version"]
    assert observed["root"] == tmp_path
    assert observed["environment"]["FORGEWARD_CHECK"] == "1"
    assert "ok" in output


def test_run_check_truncates_output_before_digest(tmp_path: Path) -> None:
    result, output = run_check(
        tmp_path,
        _spec(sys.executable, "-c", "print('x' * 5000000)"),
        _policy(max_output_chars=1_000),
    )

    assert result.status == "passed"
    assert len(output) == 1_000
    assert "output truncated" in output
    assert result.output_sha256 == sha256_text(output)


def test_run_check_normalizes_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def time_out(*args: object, **kwargs: object) -> tuple[None, bytes, bool, bool, bool]:
        return None, b"partial", False, True, False

    monkeypatch.setattr(checks_module, "_run_process", time_out)
    spec = CheckSpec(name="slow", command=[sys.executable], timeout_seconds=2)
    result, output = run_check(tmp_path, spec, _policy())

    assert result.status == "error"
    assert result.exit_code is None
    assert output == "Command timed out after 2 seconds.\n"
    assert result.output_sha256 == sha256_text(output)


def test_run_check_marks_inherited_output_pipe_as_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        checks_module,
        "_run_process",
        lambda *_args, **_kwargs: (0, b"parent output\n", True, False, True),
    )

    result, output = run_check(tmp_path, _spec(sys.executable), _policy())

    assert result.status == "error"
    assert "output capture incomplete" in output
    assert result.output_sha256 == sha256_text(output)


def test_run_check_normalizes_start_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_start(*args: object, **kwargs: object) -> None:
        raise OSError("executable disappeared")

    monkeypatch.setattr(checks_module, "_run_process", fail_start)
    result, output = run_check(tmp_path, _spec(sys.executable), _policy())

    assert result.status == "error"
    assert "Command could not start: executable disappeared" in output
    assert result.output_sha256 == sha256_text(output)
