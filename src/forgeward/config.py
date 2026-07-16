"""Configuration discovery, loading, and project scaffolding."""

from __future__ import annotations

import os
import shutil
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from forgeward.models import ForgeWardConfig
from forgeward.providers.base import ProviderError
from forgeward.providers.url_policy import validate_provider_base_url

CONFIG_DIR = ".forgeward"
CONFIG_FILE = "firm.yaml"
_MAX_CONFIG_BYTES = 2_000_000


class ConfigError(RuntimeError):
    pass


def find_project_root(start: Path | None = None) -> Path:
    current = (start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        if (candidate / CONFIG_DIR / CONFIG_FILE).is_file():
            _require_safe_directory(candidate, candidate / CONFIG_DIR)
            _require_safe_file(candidate, candidate / CONFIG_DIR / CONFIG_FILE)
            return candidate
    raise ConfigError("No .forgeward/firm.yaml found. Run `forgeward init` from the project root.")


def config_path(root: Path) -> Path:
    return root / CONFIG_DIR / CONFIG_FILE


def load_config(root: Path) -> ForgeWardConfig:
    project_root = root.resolve()
    if not (project_root / CONFIG_DIR).exists() and not (project_root / CONFIG_DIR).is_symlink():
        raise ConfigError(f"Could not read {config_path(project_root)}: configuration not found")
    _require_safe_directory(project_root, project_root / CONFIG_DIR)
    path = config_path(project_root)
    _require_safe_file(project_root, path)
    try:
        if path.stat().st_size > _MAX_CONFIG_BYTES:
            raise ConfigError(
                f"Could not read {path}: configuration exceeds the {_MAX_CONFIG_BYTES}-byte limit"
            )
        raw: Any = yaml.safe_load(path.read_bytes().decode("utf-8"))
    except ConfigError:
        raise
    except OSError as exc:
        raise ConfigError(f"Could not read {path}: operating-system error") from exc
    except UnicodeDecodeError as exc:
        raise ConfigError(f"Invalid UTF-8 in {path}") from exc
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        location = f" at line {mark.line + 1}, column {mark.column + 1}" if mark is not None else ""
        raise ConfigError(f"Invalid YAML in {path}{location}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path} must contain a YAML mapping")
    try:
        config = ForgeWardConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(_validation_error_message(exc)) from exc
    _validate_provider_routes(config)
    return config


def _validation_error_message(exc: ValidationError) -> str:
    lines = ["Invalid ForgeWard configuration:"]
    for error in exc.errors(include_url=False, include_context=False, include_input=False):
        location = ".".join(str(part) for part in error.get("loc", ())) or "configuration"
        lines.append(f"- {location}: {error.get('msg', 'invalid value')}")
    return "\n".join(lines)


def _validate_provider_routes(config: ForgeWardConfig) -> None:
    for name, provider in config.providers.items():
        if provider.adapter == "demo" or provider.base_url is None:
            continue
        try:
            validate_provider_base_url(
                provider.base_url,
                allow_insecure_http=provider.allow_insecure_http,
                allow_loopback_http=provider.adapter == "openai-compatible",
            )
        except ProviderError as exc:
            raise ConfigError(
                f"Invalid provider configuration for {name!r}: {exc.code}: {exc}"
            ) from exc


def template_root() -> Path:
    installed = Path(__file__).parent / "templates" / "default"
    if installed.is_dir():
        return installed
    source = Path(__file__).parents[2] / "templates" / "default"
    if source.is_dir():
        return source
    raise ConfigError("ForgeWard's bundled project template is missing")


def initialize_project(destination: Path, *, force: bool = False) -> Path:
    destination = destination.resolve()
    target = destination / CONFIG_DIR
    if target.exists() or target.is_symlink():
        _require_safe_directory(destination, target)
    if target.exists() and not force:
        raise ConfigError(f"{target} already exists; pass --force to refresh template files")
    target.mkdir(parents=True, exist_ok=True)
    source = template_root()
    for item in source.rglob("*"):
        relative = item.relative_to(source)
        output = target / relative
        if item.is_dir():
            _ensure_safe_directory(target, output)
            continue
        if output.exists() and not force:
            continue
        _ensure_safe_directory(target, output.parent)
        if output.is_symlink():
            raise ConfigError(f"Refusing to replace symlinked template file: {output}")
        _atomic_copy(item, output)
    _ensure_safe_directory(target, target / "runs")
    _ensure_safe_directory(target, target / "exports")
    return target


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(left)) == os.path.normcase(str(right))


def _require_safe_directory(root: Path, path: Path) -> None:
    if path.is_symlink():
        raise ConfigError(f"Refusing to use symlinked configuration directory: {path}")
    if not path.is_dir():
        raise ConfigError(f"Configuration path is not a directory: {path}")
    resolved = path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise ConfigError(f"Configuration directory escapes the project: {path}") from exc
    if not _same_path(resolved, path.absolute()):
        raise ConfigError(f"Refusing to use linked configuration directory: {path}")


def _require_safe_file(root: Path, path: Path) -> None:
    if path.is_symlink():
        raise ConfigError(f"Refusing to read symlinked configuration file: {path}")
    if not path.is_file():
        raise ConfigError(f"Could not read {path}: file not found")
    resolved = path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise ConfigError(f"Configuration file escapes the project: {path}") from exc
    if not _same_path(resolved, path.absolute()):
        raise ConfigError(f"Refusing to read linked configuration file: {path}")


def _ensure_safe_directory(root: Path, path: Path) -> None:
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ConfigError(f"Template path escapes the configuration directory: {path}") from exc
    current = root
    _require_safe_directory(root, root)
    for part in relative.parts:
        current = current / part
        if current.exists() or current.is_symlink():
            _require_safe_directory(root, current)
        else:
            current.mkdir()


def _atomic_copy(source: Path, destination: Path) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with source.open("rb") as source_handle, os.fdopen(descriptor, "wb") as target_handle:
            shutil.copyfileobj(source_handle, target_handle)
            target_handle.flush()
            os.fsync(target_handle.fileno())
        temporary.replace(destination)
    except Exception:
        with suppress(OSError):
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
