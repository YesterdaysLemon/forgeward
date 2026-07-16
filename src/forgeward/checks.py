"""Deterministic, allowlisted project verification commands."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import threading
import time
from contextlib import suppress
from pathlib import Path
from typing import Literal

from forgeward.models import CheckResult, CheckSpec, PolicyConfig
from forgeward.security import redact_text, sha256_text

_OUTPUT_DRAIN_GRACE_SECONDS = 1.0


def run_check(root: Path, spec: CheckSpec, policy: PolicyConfig) -> tuple[CheckResult, str]:
    allowed_env = {item.upper() for item in policy.check_env_allowlist}
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed_env}
    environment["FORGEWARD_CHECK"] = "1"
    environment["NO_COLOR"] = "1"
    resolved, rejection = _resolve_executable(
        root, spec.command[0], policy.allowed_executables, environment.get("PATH", "")
    )
    if resolved is None:
        result = CheckResult(
            name=spec.name,
            command=spec.command,
            status="skipped",
            required=spec.required,
        )
        return result, f"Command rejected by policy: {rejection}.\n"

    started = time.monotonic()
    try:
        command = [str(resolved), *spec.command[1:]]
        exit_code, captured_bytes, truncated, timed_out, capture_incomplete = _run_process(
            command,
            root=root,
            timeout_seconds=spec.timeout_seconds,
            environment=environment,
            capture_limit=policy.max_output_chars * 4,
        )
        if timed_out:
            output = redact_text(f"Command timed out after {spec.timeout_seconds} seconds.\n")
            result = CheckResult(
                name=spec.name,
                command=spec.command,
                status="error",
                duration_seconds=round(time.monotonic() - started, 3),
                output_sha256=sha256_text(output),
                required=spec.required,
            )
            return result, output
        captured = captured_bytes.decode("utf-8", errors="replace")
        prefix = redact_text(f"$ {' '.join(spec.command)}\n")
        captured = redact_text(captured)
        truncated = truncated or len(prefix) + len(captured) > policy.max_output_chars
        marker = ""
        if capture_incomplete:
            marker = "\n[output capture incomplete: a descendant kept the pipe open]\n"
        elif truncated:
            marker = "\n[output truncated by ForgeWard evidence limit]\n"
        if marker:
            available = max(policy.max_output_chars - len(prefix) - len(marker), 0)
            captured = captured[:available] + marker
        output = prefix + captured
        output = output[: policy.max_output_chars]
        status: Literal["passed", "failed", "error"] = (
            "error" if capture_incomplete else "passed" if exit_code == 0 else "failed"
        )
        result = CheckResult(
            name=spec.name,
            command=spec.command,
            status=status,
            exit_code=exit_code,
            duration_seconds=round(time.monotonic() - started, 3),
            output_sha256=sha256_text(output),
            required=spec.required,
        )
        return result, output
    except OSError as exc:
        output = redact_text(f"Command could not start: {exc}\n")
        result = CheckResult(
            name=spec.name,
            command=spec.command,
            status="error",
            duration_seconds=round(time.monotonic() - started, 3),
            output_sha256=sha256_text(output),
            required=spec.required,
        )
        return result, output


def _run_process(
    command: list[str],
    *,
    root: Path,
    timeout_seconds: int,
    environment: dict[str, str],
    capture_limit: int,
) -> tuple[int | None, bytes, bool, bool, bool]:
    """Drain process output while retaining at most ``capture_limit`` bytes in memory."""
    process = subprocess.Popen(  # noqa: S603
        command,
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=False,
        env=environment,
        start_new_session=os.name != "nt",
        creationflags=(
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
        ),
    )
    stream = process.stdout
    if stream is None:
        process.kill()
        raise OSError("check process output pipe was unavailable")
    captured = bytearray()
    truncated = threading.Event()

    def drain() -> None:
        try:
            while chunk := stream.read(64 * 1_024):
                available = capture_limit - len(captured)
                if available > 0:
                    captured.extend(chunk[:available])
                if len(chunk) > max(available, 0):
                    truncated.set()
        except (OSError, ValueError):
            return

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    timed_out = False
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process(process)
        process.wait(timeout=2)
    reader.join(timeout=_OUTPUT_DRAIN_GRACE_SECONDS)
    capture_incomplete = reader.is_alive()
    if capture_incomplete:
        truncated.set()
        with suppress(OSError):
            os.close(stream.fileno())
        reader.join(timeout=0.1)
    return process.returncode, bytes(captured), truncated.is_set(), timed_out, capture_incomplete


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    """Terminate the check group where portable primitives allow it."""
    if os.name != "nt":
        killpg = getattr(os, "killpg", None)
        sigkill = getattr(signal, "SIGKILL", None)
        try:
            if killpg is not None and sigkill is not None:
                killpg(process.pid, sigkill)
                return
        except OSError:
            pass
    process.kill()


def _resolve_executable(
    root: Path, requested: str, allowed: list[str], path_value: str
) -> tuple[Path | None, str]:
    requested_has_path = Path(requested).is_absolute() or "/" in requested or "\\" in requested
    exact_allowed = {
        _path_key(Path(item))
        for item in allowed
        if Path(item).is_absolute() and ("/" in item or "\\" in item)
    }
    if requested_has_path:
        candidate = Path(requested)
        if not candidate.is_absolute() or _path_key(candidate) not in exact_allowed:
            return None, "executable paths require an exact absolute-path allowlist entry"
        return candidate.resolve(strict=False), ""

    executable = requested.lower().removesuffix(".exe")
    allowed_names = {
        item.lower().removesuffix(".exe")
        for item in allowed
        if not Path(item).is_absolute() and "/" not in item and "\\" not in item
    }
    if executable not in allowed_names:
        return None, f"{requested} is not allowlisted"
    discovered = shutil.which(requested, path=path_value)
    if discovered is None:
        return None, f"{requested} could not be resolved from PATH"
    candidate = Path(discovered).resolve(strict=False)
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return candidate, ""
    if _path_key(candidate) in exact_allowed:
        return candidate, ""
    return None, f"{requested} resolves inside the project; allow its absolute path explicitly"


def _path_key(path: Path) -> str:
    return os.path.normcase(str(path.resolve(strict=False)))
