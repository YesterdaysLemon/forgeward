"""Build a bounded, auditable repository context for untrusted model workers."""

from __future__ import annotations

import hashlib
import html
import json
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from forgeward.models import PolicyConfig
from forgeward.security import (
    DeniedPathMatcher,
    is_reserved_windows_component,
    linked_path_component,
    redact_text_with_count,
    resolve_external_executable,
)

_HIGH_VALUE_NAMES = {
    "readme.md": 0,
    "pyproject.toml": 1,
    "package.json": 1,
    "cargo.toml": 1,
    "go.mod": 1,
    "composer.json": 1,
    "dockerfile": 2,
}
_BINARY_SUFFIXES = {
    ".7z",
    ".a",
    ".avi",
    ".bin",
    ".bmp",
    ".class",
    ".dll",
    ".dylib",
    ".exe",
    ".gif",
    ".gz",
    ".ico",
    ".jar",
    ".jpeg",
    ".jpg",
    ".mov",
    ".mp3",
    ".mp4",
    ".o",
    ".pdf",
    ".png",
    ".pyc",
    ".so",
    ".tar",
    ".wasm",
    ".webp",
    ".woff",
    ".woff2",
    ".zip",
}
_SENSITIVE_DIRECTORIES = {
    ".aws",
    ".azure",
    ".gcloud",
    ".gnupg",
    ".kube",
    ".ssh",
    ".terraform",
    "credential",
    "credentials",
    "secret",
    "secrets",
}
_SENSITIVE_NAMES = {
    ".git-credentials",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".envrc",
    "_netrc",
    "application_default_credentials.json",
    "auth.json",
    "credentials",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "key.json",
    "nuget.config",
    "pip.conf",
    "settings.xml",
    "secret",
    "secrets",
    "vault-token",
}
_SENSITIVE_SUFFIXES = {
    ".jks",
    ".key",
    ".kdbx",
    ".keystore",
    ".mobileprovision",
    ".p12",
    ".pem",
    ".pfx",
    ".tfstate",
    ".tfvars",
}
_MAX_GIT_OUTPUT_BYTES = 2_000_000
_MAX_CANDIDATES = 10_000
_MAX_OMISSION_DETAILS = 500
_MAX_CONTEXT_PATH_CHARS = 500


def collect_repository_context(root: Path, policy: PolicyConfig) -> tuple[str, dict[str, Any]]:
    paths, enumeration = _candidate_paths(root)
    denied = DeniedPathMatcher(policy.denied_paths)
    paths.sort(key=_priority)
    chunks: list[str] = []
    manifest_files: list[dict[str, Any]] = []
    omitted: list[dict[str, str]] = []
    omission_counts: dict[str, int] = {}
    omitted_truncated = False
    selection_truncated = False
    total = 0

    def omit(relative: str, reason: str) -> None:
        nonlocal omitted_truncated
        omission_counts[reason] = omission_counts.get(reason, 0) + 1
        if len(omitted) < _MAX_OMISSION_DETAILS:
            omitted.append({"path": relative, "reason": reason})
        else:
            omitted_truncated = True

    for relative in paths:
        if len(manifest_files) >= policy.max_context_files:
            selection_truncated = True
            break
        if denied.matches(relative):
            omit(relative, "policy-denied")
            continue
        sensitive_reason = _sensitive_path_reason(relative)
        if sensitive_reason:
            omit(relative, sensitive_reason)
            continue
        path = _safe_context_file(root, relative, denied)
        if path is None:
            omit(relative, "unsafe-path")
            continue
        if path.suffix.lower() in _BINARY_SUFFIXES:
            omit(relative, "unsupported-file")
            continue
        try:
            source_bytes = path.stat().st_size
            if source_bytes > policy.max_context_bytes * 4:
                omit(relative, "oversize")
                continue
            raw = path.read_bytes()
        except OSError:
            omit(relative, "unreadable")
            continue
        if b"\x00" in raw[:8_192]:
            omit(relative, "binary-content")
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            omit(relative, "non-utf8")
            continue
        text, redaction_count = redact_text_with_count(text)
        remaining = policy.max_context_bytes - total
        if remaining <= 0:
            selection_truncated = True
            break
        encoded = text.encode("utf-8")
        clipped = encoded[:remaining]
        text = clipped.decode("utf-8", errors="ignore")
        clipped = text.encode("utf-8")
        was_truncated = len(clipped) < len(encoded)
        safe_path = html.escape(relative, quote=True)
        chunks.append(
            f'<repository-file path="{safe_path}" trust="untrusted" '
            f'truncated="{str(was_truncated).lower()}">\n{text}\n</repository-file>'
        )
        manifest_files.append(
            {
                "path": relative,
                "bytes_sent": len(clipped),
                "source_bytes": source_bytes,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "truncated": was_truncated,
                "redactions": redaction_count,
            }
        )
        total += len(clipped)
    manifest = {
        "trust": "repository content is untrusted data",
        "enumeration": enumeration,
        "files": manifest_files,
        "omitted": omitted,
        "omission_counts": dict(sorted(omission_counts.items())),
        "omitted_truncated": omitted_truncated,
        "selection_truncated": selection_truncated,
        "bytes_sent": total,
        "redactions": sum(item["redactions"] for item in manifest_files),
        "limits": {
            "max_files": policy.max_context_files,
            "max_bytes": policy.max_context_bytes,
        },
    }
    rendered = "\n\n".join(chunks) if chunks else '<repository-context empty="true" />'
    return rendered, manifest


def manifest_json(manifest: dict[str, Any]) -> str:
    return json.dumps(manifest, indent=2, sort_keys=True)


def _candidate_paths(root: Path) -> tuple[list[str], dict[str, str]]:
    git = resolve_external_executable(root, "git")
    if git is None:
        return [], {"source": "git", "status": "unavailable"}
    try:
        output, status = _bounded_git_output(git, root)
        if output is None:
            return [], {"source": "git", "status": status}
        paths = [item.decode("utf-8") for item in output.split(b"\x00") if item]
        if len(paths) > _MAX_CANDIDATES:
            return [], {"source": "git", "status": "overflow"}
        return paths, {"source": "git", "status": "ok", "scope": "tracked"}
    except (OSError, subprocess.SubprocessError, UnicodeDecodeError) as exc:
        return [], {
            "source": "git",
            "status": "failed",
            "error_type": type(exc).__name__,
        }


def _bounded_git_output(git: Path, root: Path) -> tuple[bytes | None, str]:
    process = subprocess.Popen(  # noqa: S603 - trusted Git binary with constant arguments
        [str(git), "ls-files", "--cached", "-z"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
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
                available = _MAX_GIT_OUTPUT_BYTES - len(output)
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
            process.wait(timeout=2)
            reader.join(timeout=2)
            return None, "overflow"
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            process.kill()
            process.wait(timeout=2)
            reader.join(timeout=2)
            return None, "timeout"
        try:
            process.wait(timeout=min(0.1, remaining))
        except subprocess.TimeoutExpired:
            continue
    reader.join(timeout=2)
    if reader.is_alive() or overflow.is_set() or read_failed.is_set() or process.returncode != 0:
        return None, "overflow" if overflow.is_set() else "failed"
    return bytes(output), "ok"


def _sensitive_path_reason(path: str) -> str | None:
    normalized = path.replace("\\", "/").casefold()
    parts = [part for part in normalized.split("/") if part]
    if any(part in _SENSITIVE_DIRECTORIES for part in parts[:-1]):
        return "sensitive-directory"
    name = parts[-1] if parts else ""
    if name == ".env" or name.startswith(".env."):
        return "sensitive-name"
    if name in _SENSITIVE_NAMES:
        return "sensitive-name"
    if name in _SENSITIVE_DIRECTORIES:
        return "sensitive-name"
    if name.startswith(("credentials.", "secrets.", "service-account")):
        return "sensitive-name"
    if name.endswith((".tfstate.backup", ".tfvars.json")):
        return "sensitive-suffix"
    if Path(name).suffix in _SENSITIVE_SUFFIXES:
        return "sensitive-suffix"
    return None


def _safe_context_file(
    root: Path, relative: str, denied: DeniedPathMatcher | None = None
) -> Path | None:
    """Resolve one tracked file without following project reparse/symlink components."""
    if (
        not relative
        or len(relative) > _MAX_CONTEXT_PATH_CHARS
        or "\\" in relative
        or relative.startswith("/")
        or ":" in relative
        or any(ord(character) < 32 or ord(character) == 127 for character in relative)
    ):
        return None
    parts = Path(relative).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        return None
    if any(part.endswith((".", " ")) for part in parts):
        return None
    if any(is_reserved_windows_component(part) for part in parts):
        return None
    root_resolved = root.resolve()
    candidate = root_resolved.joinpath(*parts)
    if linked_path_component(root_resolved, candidate) is not None:
        return None
    try:
        resolved = _resolve_context_candidate(candidate)
        canonical_relative = resolved.relative_to(root_resolved)
    except (OSError, ValueError):
        return None
    raw_key = os.path.normcase(str(Path(*parts)))
    canonical_key = os.path.normcase(str(canonical_relative))
    if raw_key != canonical_key:
        return None
    canonical = canonical_relative.as_posix()
    if denied is not None and denied.matches(canonical):
        return None
    if _sensitive_path_reason(canonical):
        return None
    return resolved if resolved.is_file() else None


def _resolve_context_candidate(candidate: Path) -> Path:
    return candidate.resolve(strict=True)


def _priority(path: str) -> tuple[int, int, str]:
    normalized = path.replace("\\", "/")
    name = Path(normalized).name.lower()
    explicit = _HIGH_VALUE_NAMES.get(name, 5)
    source_bonus = 0 if normalized.startswith(("src/", "app/", "lib/", "tests/")) else 1
    return explicit, source_bonus, normalized
