from __future__ import annotations

import io
import subprocess
from pathlib import Path
from typing import BinaryIO

import pytest

import forgeward.context as context_module
import forgeward.security as security_module
from forgeward.context import collect_repository_context
from forgeward.models import PolicyConfig


def _write(root: Path, relative: str, content: str) -> None:
    destination = root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding="utf-8")


def test_repository_context_never_leaks_denied_case_or_env_variants(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    safe_files = {
        "README.md": "public project overview",
        ".github/workflows/test.yml": "public workflow",
        ".environment": "not an env-file variant",
    }
    denied_files = {
        ".ENV": "root-secret-credential",
        ".Env.Local": "local-secret-credential",
        ".Env.Staging/token.txt": "env-descendant-secret",
        "services/api/.ENV.PRODUCTION": "nested-service-secret",
        ".GIT/config": "git-internal-secret",
        ".FORGEWARD/firm.yaml": "forgeward-policy-secret",
        "PRIVATE/keys.txt": "private-tree-secret",
    }
    for relative, content in safe_files.items():
        _write(tmp_path, relative, content)
    for relative, content in denied_files.items():
        _write(tmp_path, relative, content)
    candidates = sorted([*safe_files, *denied_files])
    monkeypatch.setattr(
        context_module,
        "_candidate_paths",
        lambda _root: (candidates, {"source": "test", "status": "ok"}),
    )

    rendered, manifest = collect_repository_context(
        tmp_path,
        PolicyConfig(
            denied_paths=[".git", ".forgeward", ".env", "private"],
            max_context_files=50,
            max_context_bytes=50_000,
        ),
    )

    assert {item["path"] for item in manifest["files"]} == set(safe_files)
    for secret in denied_files.values():
        assert secret not in rendered


def test_repository_context_fails_closed_without_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(tmp_path, "untracked-secret.txt", "MUST_NOT_LEAK_WITHOUT_GIT")
    monkeypatch.setattr(context_module, "resolve_external_executable", lambda _root, _name: None)

    rendered, manifest = collect_repository_context(tmp_path, PolicyConfig())

    assert "MUST_NOT_LEAK_WITHOUT_GIT" not in rendered
    assert manifest["files"] == []
    assert manifest["enumeration"]["status"] == "unavailable"


def test_repository_context_never_executes_project_local_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_git = tmp_path / "git.exe"
    fake_git.write_text("FAKE_GIT_EXECUTION_SENTINEL", encoding="utf-8")
    monkeypatch.setattr(security_module.shutil, "which", lambda _name: str(fake_git))
    monkeypatch.setattr(
        context_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("project-local Git must not execute"),
    )

    rendered, manifest = collect_repository_context(tmp_path, PolicyConfig())

    assert "FAKE_GIT_EXECUTION_SENTINEL" not in rendered
    assert manifest["enumeration"]["status"] == "unavailable"


def test_repository_context_omits_sensitive_paths_and_redacts_secret_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    files = {
        "src/app.py": 'PUBLIC_SENTINEL\npassword = "CONTENT_SECRET_SENTINEL"\n',
        ".npmrc": "NPM_PATH_SECRET_SENTINEL",
        "infra/terraform.tfstate": "TFSTATE_PATH_SECRET_SENTINEL",
        "nested/.ssh/id_ed25519": "SSH_PATH_SECRET_SENTINEL",
        "config/secrets.yaml": "YAML_PATH_SECRET_SENTINEL",
        "secrets/prod.yaml": "SECRET_DIRECTORY_SENTINEL",
        "credentials/service.json": "CREDENTIAL_DIRECTORY_SENTINEL",
        "certs/service.key": "KEY_PATH_SECRET_SENTINEL",
    }
    for relative, content in files.items():
        _write(tmp_path, relative, content)
    monkeypatch.setattr(
        context_module,
        "_candidate_paths",
        lambda _root: (sorted(files), {"source": "test", "status": "ok"}),
    )

    rendered, manifest = collect_repository_context(
        tmp_path,
        PolicyConfig(max_context_files=50, max_context_bytes=50_000),
    )

    assert "PUBLIC_SENTINEL" in rendered
    assert "CONTENT_SECRET_SENTINEL" not in rendered
    assert "[REDACTED]" in rendered
    assert manifest["redactions"] == 1
    assert {item["path"] for item in manifest["files"]} == {"src/app.py"}
    omitted = {item["path"]: item["reason"] for item in manifest["omitted"]}
    assert set(omitted) == set(files) - {"src/app.py"}
    for sentinel in (
        "NPM_PATH_SECRET_SENTINEL",
        "TFSTATE_PATH_SECRET_SENTINEL",
        "SSH_PATH_SECRET_SENTINEL",
        "YAML_PATH_SECRET_SENTINEL",
        "SECRET_DIRECTORY_SENTINEL",
        "CREDENTIAL_DIRECTORY_SENTINEL",
        "KEY_PATH_SECRET_SENTINEL",
    ):
        assert sentinel not in rendered


def test_repository_context_rejects_symlinked_parent_escape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (outside / "payload.txt").write_text("PARENT_LINK_SECRET_SENTINEL", encoding="utf-8")
    link = tmp_path / "linked"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")
    monkeypatch.setattr(
        context_module,
        "_candidate_paths",
        lambda _root: (
            ["linked/payload.txt"],
            {"source": "test", "status": "ok", "scope": "tracked"},
        ),
    )

    rendered, manifest = collect_repository_context(tmp_path, PolicyConfig())

    assert "PARENT_LINK_SECRET_SENTINEL" not in rendered
    assert manifest["files"] == []
    assert manifest["omitted"] == [{"path": "linked/payload.txt", "reason": "unsafe-path"}]


def test_repository_context_rejects_canonical_alias_of_denied_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    protected = tmp_path / ".forgeward"
    protected.mkdir()
    destination = protected / "firm.yaml"
    destination.write_text("CANONICAL_ALIAS_SECRET_SENTINEL", encoding="utf-8")
    monkeypatch.setattr(
        context_module,
        "_candidate_paths",
        lambda _root: (["FORGEW~1/firm.yaml"], {"source": "test", "status": "ok"}),
    )
    monkeypatch.setattr(
        context_module, "_resolve_context_candidate", lambda _candidate: destination.resolve()
    )

    rendered, manifest = collect_repository_context(tmp_path, PolicyConfig())

    assert "CANONICAL_ALIAS_SECRET_SENTINEL" not in rendered
    assert manifest["files"] == []
    assert manifest["omitted"] == [{"path": "FORGEW~1/firm.yaml", "reason": "unsafe-path"}]


@pytest.mark.parametrize("relative", ["NUL", "src/aux.txt", "COM1.log", "tools/LPT9"])
def test_repository_context_rejects_windows_device_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relative: str
) -> None:
    monkeypatch.setattr(
        context_module,
        "_candidate_paths",
        lambda _root: ([relative], {"source": "test", "status": "ok"}),
    )

    _rendered, manifest = collect_repository_context(tmp_path, PolicyConfig())

    assert manifest["files"] == []
    assert manifest["omitted"] == [{"path": relative, "reason": "unsafe-path"}]


def test_candidate_enumeration_fails_closed_when_git_returns_too_many_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        context_module,
        "resolve_external_executable",
        lambda _root, _name: Path("C:/trusted/git.exe"),
    )
    output = b"file.txt\x00" * (context_module._MAX_CANDIDATES + 1)
    monkeypatch.setattr(context_module, "_bounded_git_output", lambda _git, _root: (output, "ok"))

    paths, enumeration = context_module._candidate_paths(tmp_path)

    assert paths == []
    assert enumeration == {"source": "git", "status": "overflow"}


def test_context_manifest_caps_omission_details_but_preserves_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidates = [f".env.secret-{index}" for index in range(5)]
    monkeypatch.setattr(context_module, "_MAX_OMISSION_DETAILS", 2)
    monkeypatch.setattr(
        context_module,
        "_candidate_paths",
        lambda _root: (candidates, {"source": "test", "status": "ok"}),
    )

    _rendered, manifest = collect_repository_context(tmp_path, PolicyConfig())

    assert len(manifest["omitted"]) == 2
    assert manifest["omitted_truncated"] is True
    assert manifest["omission_counts"] == {"policy-denied": 5}


class _FakeGitProcess:
    def __init__(self, stdout: BinaryIO | None, *, returncode: int | None = 0) -> None:
        self.stdout = stdout
        self.returncode = returncode
        self.killed = False

    def poll(self) -> int | None:
        return -9 if self.killed else self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is None and not self.killed:
            raise subprocess.TimeoutExpired(["git"], timeout or 0)
        return self.returncode or 0


@pytest.mark.parametrize(
    ("process", "expected_status"),
    [
        (_FakeGitProcess(None), "failed"),
        (_FakeGitProcess(io.BytesIO(b"file.txt\x00"), returncode=1), "failed"),
    ],
)
def test_bounded_git_output_fails_closed_on_pipe_or_exit_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    process: _FakeGitProcess,
    expected_status: str,
) -> None:
    monkeypatch.setattr(context_module.subprocess, "Popen", lambda *_args, **_kwargs: process)

    output, status = context_module._bounded_git_output(Path("git"), tmp_path)

    assert output is None
    assert status == expected_status


def test_bounded_git_output_fails_closed_on_overflow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = _FakeGitProcess(io.BytesIO(b"x" * 65))
    monkeypatch.setattr(context_module, "_MAX_GIT_OUTPUT_BYTES", 64)
    monkeypatch.setattr(context_module.subprocess, "Popen", lambda *_args, **_kwargs: process)

    output, status = context_module._bounded_git_output(Path("git"), tmp_path)

    assert output is None
    assert status == "overflow"


def test_bounded_git_output_fails_closed_on_read_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class BrokenStream(io.BytesIO):
        def read(self, size: int = -1) -> bytes:
            raise OSError("synthetic read error")

    process = _FakeGitProcess(BrokenStream())
    monkeypatch.setattr(context_module.subprocess, "Popen", lambda *_args, **_kwargs: process)

    output, status = context_module._bounded_git_output(Path("git"), tmp_path)

    assert output is None
    assert status == "failed"


def test_bounded_git_output_fails_closed_on_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = _FakeGitProcess(io.BytesIO(), returncode=None)
    timestamps = iter([0.0, 11.0])
    monkeypatch.setattr(context_module.time, "monotonic", lambda: next(timestamps))
    monkeypatch.setattr(context_module.subprocess, "Popen", lambda *_args, **_kwargs: process)

    output, status = context_module._bounded_git_output(Path("git"), tmp_path)

    assert output is None
    assert status == "timeout"
    assert process.killed is True
