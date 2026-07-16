"""Security primitives for untrusted model output, paths, and logs."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
from collections.abc import Iterable
from pathlib import Path

from forgeward.models import ProposedChange

_SECRET_PATTERNS = [
    re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.*?"
        r"-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        re.DOTALL,
    ),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bgh[opusr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\bxox(?:a|b|p|r|s)-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{12,}=*"),
    re.compile(
        r"(?im)[\"']?(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
        r"aws[_-]?secret[_-]?access[_-]?key|aws[_-]?session[_-]?token|private[_-]?key|"
        r"password|passwd|token|secret)[\"']?\s*[:=]\s*"
        r'(?:"[^"\r\n]*"|\'[^\'\r\n]*\'|[^\s,;}\]#]+)'
    ),
]
_TERMINAL_CONTROL_PATTERN = re.compile(
    r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\ufeff]"
)
_WINDOWS_RESERVED_BASENAMES = {
    "aux",
    "clock$",
    "con",
    "conin$",
    "conout$",
    "nul",
    "prn",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}


class SecurityViolation(RuntimeError):
    pass


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def redact_text(value: str) -> str:
    redacted, _count = redact_text_with_count(value)
    return redacted


def redact_text_with_count(value: str) -> tuple[str, int]:
    """Redact common credential shapes and return the number of substitutions."""
    redacted = value
    count = 0
    for pattern in _SECRET_PATTERNS:
        redacted, substitutions = pattern.subn("[REDACTED]", redacted)
        count += substitutions
    return sanitize_terminal_text(redacted), count


def sanitize_terminal_text(value: str) -> str:
    """Remove terminal and bidi controls while preserving ordinary tabs and newlines."""
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    return _TERMINAL_CONTROL_PATTERN.sub("", normalized)


def is_reserved_windows_component(value: str) -> bool:
    """Return whether a path component aliases a Windows DOS device name."""
    basename = value.split(".", 1)[0].casefold()
    return basename in _WINDOWS_RESERVED_BASENAMES


def resolve_external_executable(root: Path, name: str) -> Path | None:
    """Resolve a host tool while refusing binaries supplied by the project itself."""
    discovered = shutil.which(name)
    if discovered is None:
        return None
    try:
        candidate = Path(discovered).resolve(strict=True)
    except OSError:
        return None
    if not candidate.is_file():
        return None
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return candidate
    return None


def linked_path_component(root: Path, candidate: Path) -> Path | None:
    """Return the first symlink/junction/reparse component below ``root``, if any."""
    try:
        relative = candidate.absolute().relative_to(root.absolute())
    except ValueError:
        return candidate
    current = root
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    for part in relative.parts:
        current = current / part
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            continue
        except OSError:
            return current
        if stat.S_ISLNK(metadata.st_mode) or (
            getattr(metadata, "st_file_attributes", 0) & reparse_flag
        ):
            return current
    return None


class DeniedPathMatcher:
    """Match repository paths against policy roots without platform case ambiguity.

    Policy matching is intentionally case-insensitive on every platform. A root-level
    ``.env`` policy entry is also treated as a repository-wide sensitive-file rule so
    nested service directories cannot leak or overwrite ``.env`` and ``.env.*`` files.
    """

    def __init__(self, denied_paths: Iterable[str]) -> None:
        self._denied = tuple(
            normalized for item in denied_paths if (normalized := self._normalize(item))
        )
        self._deny_env_anywhere = ".env" in self._denied

    def matches(self, path: str) -> bool:
        normalized = self._normalize(path)
        if not normalized:
            return False
        path_parts = normalized.split("/")
        if self._deny_env_anywhere and any(self._is_env_name(part) for part in path_parts):
            return True
        for denied in self._denied:
            if normalized == denied or normalized.startswith(f"{denied}/"):
                return True
            denied_parts = denied.split("/")
            if (
                denied_parts[-1] == ".env"
                and len(path_parts) >= len(denied_parts)
                and path_parts[: len(denied_parts) - 1] == denied_parts[:-1]
                and self._is_env_name(path_parts[len(denied_parts) - 1])
            ):
                return True
        return False

    @staticmethod
    def _normalize(path: str) -> str:
        parts = [part for part in path.replace("\\", "/").split("/") if part not in {"", "."}]
        return "/".join(parts).casefold()

    @staticmethod
    def _is_env_name(name: str) -> bool:
        return name == ".env" or name.startswith(".env.")


class SafeWorkspace:
    """Apply validated text changes without following paths outside the project root."""

    def __init__(self, root: Path, denied_paths: list[str], max_file_bytes: int) -> None:
        self.root = root.resolve()
        self._denied_paths = DeniedPathMatcher(denied_paths)
        self.max_file_bytes = max_file_bytes

    def resolve(self, relative: str) -> Path:
        normalized = relative.replace("\\", "/")
        if not normalized or normalized in {".", ".."}:
            raise SecurityViolation("empty or ambiguous change path")
        if normalized.startswith("/") or Path(normalized).is_absolute():
            raise SecurityViolation(f"absolute path rejected: {relative}")
        if ":" in normalized or any(ord(char) < 32 or ord(char) == 127 for char in normalized):
            raise SecurityViolation(f"non-portable path characters rejected: {relative!r}")
        parts = Path(normalized).parts
        if ".." in parts:
            raise SecurityViolation(f"path traversal rejected: {relative}")
        if any(part != part.strip() or part.endswith(".") for part in parts):
            raise SecurityViolation(f"ambiguous Windows path component rejected: {relative!r}")
        if any(is_reserved_windows_component(part) for part in parts):
            raise SecurityViolation(f"reserved Windows device path rejected: {relative!r}")
        if self._denied_paths.matches(normalized):
            raise SecurityViolation(f"protected path rejected: {relative}")
        unresolved = self.root / Path(*parts)
        self._reject_symlink_chain(unresolved)
        candidate = self._canonical_candidate(unresolved)
        try:
            canonical_relative = candidate.relative_to(self.root)
        except ValueError as exc:
            raise SecurityViolation(f"path escapes project root: {relative}") from exc
        raw_key = os.path.normcase(str(Path(*parts)))
        canonical_key = os.path.normcase(str(canonical_relative))
        if raw_key != canonical_key:
            raise SecurityViolation(f"canonical path alias rejected: {relative!r}")
        if self._denied_paths.matches(canonical_relative.as_posix()):
            raise SecurityViolation(f"protected canonical path rejected: {relative}")
        return candidate

    @staticmethod
    def _canonical_candidate(path: Path) -> Path:
        return path.resolve(strict=False)

    def apply(self, change: ProposedChange) -> tuple[Path, str]:
        destination = self.resolve(change.path)
        encoded = change.content.encode("utf-8")
        if len(encoded) > self.max_file_bytes:
            raise SecurityViolation(
                f"proposed file exceeds {self.max_file_bytes} byte policy: {change.path}"
            )
        exists = destination.exists()
        if change.operation == "create" and exists:
            raise SecurityViolation(f"create would overwrite existing file: {change.path}")
        if change.operation == "update" and not exists:
            raise SecurityViolation(f"update target does not exist: {change.path}")
        if exists and not destination.is_file():
            raise SecurityViolation(f"change target is not a regular file: {change.path}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.forgeward-tmp")
        if temporary.exists() or temporary.is_symlink():
            raise SecurityViolation(f"temporary path already exists: {temporary.name}")
        existing_mode = stat.S_IMODE(destination.stat().st_mode) if exists else None
        try:
            with temporary.open("xb") as handle:
                handle.write(encoded)
            if existing_mode is not None:
                temporary.chmod(existing_mode)
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)
        return destination, sha256_bytes(encoded)

    def _reject_symlink_chain(self, candidate: Path) -> None:
        linked = linked_path_component(self.root, candidate)
        if linked is not None:
            try:
                display = linked.relative_to(self.root)
            except ValueError:
                display = linked
            raise SecurityViolation(f"linked/reparse path rejected: {display}")
