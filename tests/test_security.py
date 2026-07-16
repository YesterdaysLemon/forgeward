from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

import forgeward.security as security_module
from forgeward.models import ProposedChange
from forgeward.security import (
    DeniedPathMatcher,
    SafeWorkspace,
    SecurityViolation,
    redact_text,
    resolve_external_executable,
    sha256_bytes,
    sha256_text,
)


def test_host_executable_resolution_rejects_project_local_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    local = tmp_path / "git.exe"
    local.write_text("must never execute", encoding="utf-8")
    monkeypatch.setattr(security_module.shutil, "which", lambda _name: str(local))

    assert resolve_external_executable(tmp_path, "git") is None


def _workspace(root: Path, *, max_file_bytes: int = 100) -> SafeWorkspace:
    return SafeWorkspace(
        root,
        denied_paths=[".git", ".forgeward", ".env", "private"],
        max_file_bytes=max_file_bytes,
    )


def _change(operation: str, path: str, content: str = "content") -> ProposedChange:
    return ProposedChange(
        operation=operation,
        path=path,
        content=content,
        rationale="test the workspace boundary",
    )


def test_workspace_resolves_normalized_project_relative_path(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)

    assert (
        workspace.resolve(r"src\package\module.py")
        == (tmp_path / "src" / "package" / "module.py").resolve()
    )


@pytest.mark.parametrize(
    ("path", "message"),
    [
        ("", "empty or ambiguous"),
        (".", "empty or ambiguous"),
        ("..", "empty or ambiguous"),
        ("../escape.txt", "path traversal"),
        (r"src\..\escape.txt", "path traversal"),
        ("file.txt:stream", "non-portable path characters"),
        ("src/file\nname.txt", "non-portable path characters"),
        ("src/file\tname.txt", "non-portable path characters"),
        (".git./config", "ambiguous Windows path component"),
        (".GIT /config", "ambiguous Windows path component"),
        ("NUL", "reserved Windows device"),
        ("src/nul.txt", "reserved Windows device"),
        ("AUX/config", "reserved Windows device"),
        ("COM1.log", "reserved Windows device"),
        ("tools/LPT9", "reserved Windows device"),
        (".git", "protected path"),
        (".git/config", "protected path"),
        ("./.GIT/config", "protected path"),
        (r".GiT\hooks\pre-commit", "protected path"),
        (r".forgeward\firm.yaml", "protected path"),
        ("./.forgeward/firm.yaml", "protected path"),
        (r".FORGEWARD\runs\record.json", "protected path"),
        (".ENV", "protected path"),
        (".Env.Local", "protected path"),
        (".ENV.PRODUCTION/cache/token", "protected path"),
        ("services/api/.Env.Staging", "protected path"),
        ("services/api/.ENV.TEST/secrets/key", "protected path"),
        ("private/keys/value", "protected path"),
        ("PRIVATE/KEYS/value", "protected path"),
    ],
)
def test_workspace_rejects_ambiguous_traversal_and_protected_paths(
    tmp_path: Path, path: str, message: str
) -> None:
    with pytest.raises(SecurityViolation, match=message):
        _workspace(tmp_path).resolve(path)


def test_workspace_does_not_treat_protected_name_prefix_as_subtree(tmp_path: Path) -> None:
    assert (
        _workspace(tmp_path).resolve(".github/workflows/test.yml")
        == (tmp_path / ".github" / "workflows" / "test.yml").resolve()
    )


@pytest.mark.parametrize(
    "path",
    [
        ".github/workflows/test.yml",
        ".environment",
        ".environment.md",
        ".envrc",
        "private-notes/readme.md",
    ],
)
def test_denied_matcher_does_not_block_unrelated_prefixes(path: str) -> None:
    matcher = DeniedPathMatcher([".git", ".forgeward", ".env", "private"])

    assert not matcher.matches(path)


def test_workspace_rejects_absolute_paths(tmp_path: Path) -> None:
    absolute = (tmp_path.parent / "outside.txt").resolve()

    with pytest.raises(SecurityViolation, match="absolute path"):
        _workspace(tmp_path).resolve(str(absolute))


def test_workspace_rejects_canonical_windows_alias_of_protected_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    protected = tmp_path / ".forgeward"
    protected.mkdir()
    destination = protected / "firm.yaml"
    destination.write_text("protected", encoding="utf-8")
    workspace = _workspace(tmp_path)
    monkeypatch.setattr(workspace, "_canonical_candidate", lambda _path: destination)

    with pytest.raises(SecurityViolation, match="canonical path alias"):
        workspace.resolve("FORGEW~1/firm.yaml")


def _make_symlink(link: Path, target: Path, *, directory: bool) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")


def test_workspace_rejects_symlink_that_points_outside_root(tmp_path: Path) -> None:
    root = tmp_path / "project"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    _make_symlink(root / "linked", outside, directory=True)

    with pytest.raises(SecurityViolation, match=r"(?:escapes project root|linked/reparse path)"):
        _workspace(root).resolve("linked/file.txt")


def test_workspace_rejects_symlink_chain_even_when_target_stays_inside_root(tmp_path: Path) -> None:
    root = tmp_path / "project"
    real = root / "real"
    real.mkdir(parents=True)
    _make_symlink(root / "linked", real, directory=True)

    with pytest.raises(SecurityViolation, match="linked/reparse path"):
        _workspace(root).resolve("linked/file.txt")


def test_workspace_rejects_simulated_windows_reparse_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "junction"
    parent.mkdir()
    original_lstat = security_module.os.lstat

    def fake_lstat(path: object) -> object:
        metadata = original_lstat(path)
        if Path(path) == parent:

            class ReparseMetadata:
                st_mode = metadata.st_mode
                st_file_attributes = 0x400

            return ReparseMetadata()
        return metadata

    monkeypatch.setattr(security_module.os, "lstat", fake_lstat)

    with pytest.raises(SecurityViolation, match="linked/reparse path"):
        _workspace(tmp_path).resolve("junction/file.txt")


def test_workspace_create_and_update_are_explicit_and_digest_content(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    destination, digest = workspace.apply(_change("create", "src/new.txt", "hello"))

    assert destination.read_text(encoding="utf-8") == "hello"
    assert digest == sha256_bytes(b"hello")
    with pytest.raises(SecurityViolation, match="create would overwrite"):
        workspace.apply(_change("create", "src/new.txt", "replacement"))

    destination, digest = workspace.apply(_change("update", "src/new.txt", "updated"))
    assert destination.read_text(encoding="utf-8") == "updated"
    assert digest == sha256_text("updated")


def test_workspace_update_requires_existing_regular_file(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    with pytest.raises(SecurityViolation, match="does not exist"):
        workspace.apply(_change("update", "missing.txt"))

    (tmp_path / "directory").mkdir()
    with pytest.raises(SecurityViolation, match="not a regular file"):
        workspace.apply(_change("update", "directory"))


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode semantics are unavailable on Windows")
@pytest.mark.parametrize("mode", [0o600, 0o755])
def test_workspace_update_preserves_existing_file_mode(tmp_path: Path, mode: int) -> None:
    destination = tmp_path / "script.sh"
    destination.write_text("old", encoding="utf-8")
    destination.chmod(mode)

    _workspace(tmp_path).apply(_change("update", "script.sh", "new"))

    assert stat.S_IMODE(destination.stat().st_mode) == mode


def test_workspace_size_limit_is_measured_in_utf8_bytes(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, max_file_bytes=4)
    workspace.apply(_change("create", "four.txt", "éé"))

    with pytest.raises(SecurityViolation, match="exceeds 4 byte policy"):
        workspace.apply(_change("create", "six.txt", "ééé"))


@pytest.mark.parametrize(
    "secret",
    [
        "api_key=super-sensitive-value",
        'password: "hunter2"',
        "token=abcdef123456",
        "sk-proj-abcdefghijklmnopqrstuvwxyz012345",
        "ghp_abcdefghijklmnopqrstuvwxyz012345",
        "-----BEGIN PRIVATE KEY-----",
    ],
)
def test_redact_text_removes_supported_secret_shapes(secret: str) -> None:
    redacted = redact_text(f"before {secret} after")

    assert "[REDACTED]" in redacted
    assert secret not in redacted
    assert redacted.startswith("before ")
    assert redacted.endswith(" after")


def test_redact_text_preserves_non_secret_content() -> None:
    value = "authentication failed for user; status=401"
    assert redact_text(value) == value


def test_terminal_sanitization_removes_unicode_direction_controls() -> None:
    value = "safe\u202eexe.txt\u2066tail"

    assert security_module.sanitize_terminal_text(value) == "safeexe.txttail"


def test_hash_helpers_use_utf8_and_are_deterministic() -> None:
    assert sha256_text("café") == sha256_bytes("café".encode())
    assert sha256_text("café") != sha256_text("cafe")
