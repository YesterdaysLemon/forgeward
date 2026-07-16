from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from forgeward.config import (
    ConfigError,
    config_path,
    find_project_root,
    initialize_project,
    load_config,
)


def test_initialize_project_copies_a_loadable_default_firm(tmp_path: Path) -> None:
    target = initialize_project(tmp_path)

    assert target == tmp_path.resolve() / ".forgeward"
    assert (target / "firm.yaml").is_file()
    assert (target / "prompts" / "security.md").is_file()
    assert (target / "runs").is_dir()
    assert (target / "exports").is_dir()

    config = load_config(tmp_path)
    assert config.project.default_provider == "demo"
    assert config.providers["demo"].adapter == "demo"
    assert {role.id for role in config.team} >= {
        "product",
        "designer",
        "security",
        "architect",
        "scrum-master",
        "builder",
        "reviewer",
        "tester",
        "release",
    }


def test_initialize_refuses_existing_configuration_without_force(project: Path) -> None:
    with pytest.raises(ConfigError, match="already exists"):
        initialize_project(project)


def test_initialize_force_refreshes_templates_but_preserves_run_data(project: Path) -> None:
    prompt = project / ".forgeward" / "prompts" / "product.md"
    prompt.write_text("locally changed", encoding="utf-8")
    run_marker = project / ".forgeward" / "runs" / "keep.txt"
    run_marker.write_text("evidence", encoding="utf-8")

    initialize_project(project, force=True)

    assert prompt.read_text(encoding="utf-8") != "locally changed"
    assert run_marker.read_text(encoding="utf-8") == "evidence"


def test_initialize_force_rejects_symlinked_configuration_directory(tmp_path: Path) -> None:
    external = tmp_path / "external"
    external.mkdir()
    sentinel = external / "firm.yaml"
    sentinel.write_text("external sentinel", encoding="utf-8")
    link = tmp_path / ".forgeward"
    try:
        link.symlink_to(external, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    with pytest.raises(ConfigError, match=r"symlinked|linked"):
        load_config(tmp_path)
    with pytest.raises(ConfigError, match=r"symlinked|linked"):
        initialize_project(tmp_path, force=True)

    assert sentinel.read_text(encoding="utf-8") == "external sentinel"


def test_initialize_force_rejects_symlinked_template_file(tmp_path: Path) -> None:
    target = initialize_project(tmp_path)
    external = tmp_path / "external-firm.yaml"
    external.write_text("external sentinel", encoding="utf-8")
    firm = target / "firm.yaml"
    firm.unlink()
    try:
        firm.symlink_to(external)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    with pytest.raises(ConfigError, match="symlinked configuration file"):
        load_config(tmp_path)
    with pytest.raises(ConfigError, match="symlinked template file"):
        initialize_project(tmp_path, force=True)

    assert external.read_text(encoding="utf-8") == "external sentinel"


def test_find_project_root_walks_up_from_nested_directory(project: Path) -> None:
    nested = project / "src" / "package"
    nested.mkdir(parents=True)

    assert find_project_root(nested) == project.resolve()
    assert config_path(project) == project / ".forgeward" / "firm.yaml"


def test_find_project_root_has_actionable_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=r"forgeward init"):
        find_project_root(tmp_path)


@pytest.mark.parametrize("contents", ["- not\n- a\n- mapping\n", "null\n", "plain text\n"])
def test_load_config_requires_yaml_mapping(project: Path, contents: str) -> None:
    config_path(project).write_text(contents, encoding="utf-8")

    with pytest.raises(ConfigError, match="must contain a YAML mapping"):
        load_config(project)


def test_load_config_wraps_yaml_errors(project: Path) -> None:
    config_path(project).write_text("project: [unterminated", encoding="utf-8")

    with pytest.raises(ConfigError, match="Invalid YAML"):
        load_config(project)


def test_load_config_never_echoes_yaml_source_snippets(project: Path) -> None:
    sentinel = "OPAQUE_YAML_SECRET_SENTINEL"
    config_path(project).write_text(
        f"project:\n  name: ok\nproviders: [\n  {sentinel}\n", encoding="utf-8"
    )

    with pytest.raises(ConfigError) as raised:
        load_config(project)

    assert "Invalid YAML" in str(raised.value)
    assert "line" in str(raised.value)
    assert sentinel not in str(raised.value)


def test_load_config_wraps_schema_and_reference_errors(project: Path) -> None:
    path = config_path(project)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["project"]["default_provider"] = "missing"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")

    with pytest.raises(ConfigError, match="default_provider does not exist"):
        load_config(project)


def test_load_config_schema_error_omits_credential_input(project: Path) -> None:
    path = config_path(project)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    sentinel = "OPAQUE_CONFIG_CREDENTIAL_SENTINEL"
    raw["providers"]["local"]["api_key"] = sentinel
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")

    with pytest.raises(ConfigError) as raised:
        load_config(project)

    assert "extra inputs are not permitted" in str(raised.value).lower()
    assert sentinel not in str(raised.value)


@pytest.mark.parametrize("api_key_env", ["BAD=NAME", "9INVALID", "HAS-DASH"])
def test_load_config_rejects_nonportable_credential_environment_names(
    project: Path, api_key_env: str
) -> None:
    path = config_path(project)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["providers"]["local"]["api_key_env"] = api_key_env
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")

    with pytest.raises(ConfigError, match="api_key_env"):
        load_config(project)


def test_load_config_rejects_credentialed_provider_url_without_echoing_it(project: Path) -> None:
    path = config_path(project)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    sentinel = "OPAQUE_URL_PASSWORD_SENTINEL"
    raw["providers"]["local"]["base_url"] = f"https://user:{sentinel}@models.example.test/v1"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")

    with pytest.raises(ConfigError) as raised:
        load_config(project)

    assert "invalid_base_url" in str(raised.value)
    assert sentinel not in str(raised.value)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("allowed_tools", ["repository.read", "shell.exec"], "unsupported role capabilities"),
        ("allowed_tools", ["repository.read", "repository.read"], "must be unique"),
        (
            "allowed_tools",
            ["repository.read", "workspace.propose"],
            "workspace.propose is reserved",
        ),
        ("may_approve", ["release"], "model roles cannot approve gates"),
    ],
)
def test_load_config_rejects_unsafe_role_authority(
    project: Path, field: str, value: list[str], message: str
) -> None:
    path = config_path(project)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["team"][0][field] = value
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")

    with pytest.raises(ConfigError, match=message):
        load_config(project)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("human_gates", ["plan", "relase"], "unknown human gates"),
        ("human_gates", ["plan", "plan"], "human gates must be unique"),
        ("denied_paths", [".gti", ".forgeward", ".env"], "must protect: .git"),
        ("denied_paths", [".git", ".env"], "must protect: .forgeward"),
        ("denied_paths", [".git", ".forgeward"], "must protect: .env"),
    ],
)
def test_load_config_rejects_unsafe_policy_roots(
    project: Path, field: str, value: list[str], message: str
) -> None:
    path = config_path(project)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["policy"][field] = value
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")

    with pytest.raises(ConfigError, match=message):
        load_config(project)


def test_load_config_reports_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="Could not read"):
        load_config(tmp_path)
