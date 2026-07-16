"""ForgeWard command-line interface."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from forgeward.config import ConfigError, find_project_root, initialize_project, load_config
from forgeward.context import collect_repository_context
from forgeward.models import ForgeWardConfig, RunRecord, RunState, __version__
from forgeward.orchestrator import ForgeWardEngine, OrchestrationError, human_actor
from forgeward.providers import ProviderError, create_provider
from forgeward.reporting import markdown_report
from forgeward.security import sanitize_terminal_text
from forgeward.state import RunStore, StateError

app = typer.Typer(
    name="forgeward",
    help="Run a gated, evidence-led AI software team from your terminal.",
    no_args_is_help=True,
    invoke_without_command=True,
    pretty_exceptions_show_locals=False,
    rich_markup_mode="markdown",
)
provider_app = typer.Typer(help="Inspect and test model-provider routes.", no_args_is_help=True)
team_app = typer.Typer(
    help="Inspect and validate the configured software team.", no_args_is_help=True
)
policy_app = typer.Typer(help="Inspect deterministic security policy.", no_args_is_help=True)
context_app = typer.Typer(help="Preview bounded provider context.", no_args_is_help=True)
app.add_typer(provider_app, name="provider")
app.add_typer(team_app, name="team")
app.add_typer(policy_app, name="policy")
app.add_typer(context_app, name="context")

console = Console()
err_console = Console(stderr=True)


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", help="Show ForgeWard's version and exit.", is_eager=True),
    ] = False,
) -> None:
    if version:
        console.print(f"ForgeWard {__version__}")
        raise typer.Exit()


@app.command()
def init(
    path: Annotated[Path, typer.Argument(help="Project directory to initialize.")] = Path("."),
    force: Annotated[
        bool, typer.Option("--force", help="Refresh existing template files in .forgeward.")
    ] = False,
) -> None:
    """Create a reviewable firm, provider, role, prompt, and policy configuration."""
    try:
        target = initialize_project(path, force=force)
    except ConfigError as exc:
        _fail(exc)
    message = Text("ForgeWard initialized", style="bold")
    message.append(f"\n{sanitize_terminal_text(str(target))}\n\nNext: review ")
    message.append(".forgeward/firm.yaml", style="cyan")
    message.append(", then run ")
    message.append("forgeward doctor", style="cyan")
    message.append(".")
    console.print(Panel.fit(message, border_style="green"))


@app.command()
def doctor(
    root: Annotated[Path | None, typer.Option("--root", help="Project root override.")] = None,
    live: Annotated[
        bool, typer.Option("--live", help="Also make a small request to the default provider.")
    ] = False,
) -> None:
    """Validate configuration and safety invariants without exposing credentials."""
    try:
        project, config, _engine = _project(root)
    except (ConfigError, StateError, OrchestrationError) as exc:
        _fail(exc)
    rows: list[tuple[str, str, str]] = []
    rows.append(("Configuration", "PASS", str(project / ".forgeward" / "firm.yaml")))
    git_ok = (project / ".git").exists()
    rows.append(
        ("Git repository", "PASS" if git_ok else "WARN", "found" if git_ok else "not found")
    )
    _context, context_manifest = collect_repository_context(project, config.policy)
    enumeration = context_manifest["enumeration"]
    context_status = enumeration.get("status", "failed")
    context_detail = (
        f"{len(context_manifest['files'])} tracked files; "
        f"{context_manifest['bytes_sent']} bytes; "
        f"{context_manifest['redactions']} redactions"
        if context_status == "ok"
        else "withheld because tracked-file enumeration is unavailable"
    )
    rows.append(
        (
            "Provider context",
            "PASS" if context_status == "ok" else "WARN",
            context_detail,
        )
    )
    protected = {item.strip("./") for item in config.policy.denied_paths}
    required = {"git", "forgeward", "env"}
    missing = sorted(required - protected)
    rows.append(
        (
            "Protected paths",
            "PASS" if not missing else "FAIL",
            "configured" if not missing else f"missing {', '.join(missing)}",
        )
    )
    gates = set(config.policy.human_gates)
    rows.append(
        (
            "Human gates",
            "PASS" if {"plan", "release"}.issubset(gates) else "WARN",
            ", ".join(config.policy.human_gates) or "none",
        )
    )
    rows.append(
        (
            "Telemetry",
            "PASS" if not config.policy.telemetry else "WARN",
            "off" if not config.policy.telemetry else "enabled by configuration",
        )
    )
    provider_name = config.project.default_provider
    provider_config = config.providers[provider_name]
    credential_state = "not required"
    credential_missing = False
    if provider_config.api_key_env:
        import os

        credential_missing = not bool(os.environ.get(provider_config.api_key_env))
        credential_state = f"{provider_config.api_key_env} " + (
            "missing" if credential_missing else "present"
        )
    provider_result = (
        "FAIL" if not provider_config.enabled else "WARN" if credential_missing else "PASS"
    )
    provider_detail = (
        f"{provider_name} · disabled"
        if not provider_config.enabled
        else f"{provider_name} · {credential_state}"
    )
    rows.append(("Default provider", provider_result, provider_detail))
    transport_failures: list[str] = []
    insecure_opt_ins: list[str] = []
    delegated_transports: list[str] = []
    for name, candidate in config.providers.items():
        if not candidate.enabled or candidate.adapter == "demo":
            continue
        try:
            create_provider(candidate)
        except ProviderError as exc:
            transport_failures.append(f"{name}: {exc.code}")
        if candidate.allow_insecure_http:
            insecure_opt_ins.append(name)
        if candidate.adapter == "litellm" and candidate.base_url is None:
            delegated_transports.append(name)
    if transport_failures:
        rows.append(("Provider transport", "FAIL", "; ".join(transport_failures)))
    elif insecure_opt_ins or delegated_transports:
        warnings: list[str] = []
        if insecure_opt_ins:
            warnings.append("cleartext opt-in: " + ", ".join(insecure_opt_ins))
        if delegated_transports:
            warnings.append(
                "LiteLLM-native transport delegated: " + ", ".join(delegated_transports)
            )
        rows.append(
            (
                "Provider transport",
                "WARN",
                "; ".join(warnings),
            )
        )
    else:
        rows.append(("Provider transport", "PASS", "remote cleartext denied"))
    if live:
        if not provider_config.enabled:
            ok, detail = False, "default provider is disabled"
        else:
            try:
                ok, detail = create_provider(provider_config).probe()
            except ProviderError as exc:
                ok, detail = False, f"{exc.code}: {exc}"
        rows.append(("Live provider probe", "PASS" if ok else "FAIL", detail))
    table = Table(title="ForgeWard doctor", show_lines=False)
    table.add_column("Check", style="bold")
    table.add_column("Result")
    table.add_column("Detail")
    for name, result, detail in rows:
        color = "green" if result == "PASS" else "yellow" if result == "WARN" else "red"
        table.add_row(_safe_text(name), Text(result, style=color), _safe_text(detail))
    console.print(table)
    if any(result == "FAIL" for _, result, _ in rows):
        raise typer.Exit(1)


@context_app.command("preview")
def context_preview(
    root: Annotated[Path | None, typer.Option("--root", help="Project root override.")] = None,
) -> None:
    """List exactly which tracked files would be sent, omitted, or redacted."""
    try:
        project, config, _engine = _project(root)
        _rendered, manifest = collect_repository_context(project, config.policy)
    except (ConfigError, StateError, OrchestrationError) as exc:
        _fail(exc)

    enumeration = manifest["enumeration"]
    table = Table(title="Provider context preview", show_lines=False)
    table.add_column("Path", style="bold")
    table.add_column("Decision")
    table.add_column("Detail")
    for item in manifest["files"]:
        detail = f"{item['bytes_sent']} bytes"
        if item["redactions"]:
            detail += f"; {item['redactions']} redactions"
        if item["truncated"]:
            detail += "; truncated"
        table.add_row(_safe_text(item["path"]), Text("SEND", style="green"), _safe_text(detail))
    for item in manifest["omitted"]:
        table.add_row(
            _safe_text(item["path"]),
            Text("OMIT", style="yellow"),
            _safe_text(item["reason"]),
        )
    if not manifest["files"] and not manifest["omitted"]:
        table.add_row(Text("(none)"), Text("WITHHOLD", style="yellow"), Text("no tracked files"))
    console.print(table)
    summary = Text.assemble(
        "Enumeration: ",
        (sanitize_terminal_text(str(enumeration.get("status", "failed"))), "bold"),
        " · scope: tracked files only · bytes sent: ",
        str(manifest["bytes_sent"]),
        " · redactions: ",
        str(manifest["redactions"]),
    )
    console.print(summary)


@app.command()
def plan(
    objective: Annotated[str, typer.Argument(help="Outcome the team should plan.")],
    provider: Annotated[
        str | None, typer.Option("--provider", help="Provider route for this engagement.")
    ] = None,
    root: Annotated[Path | None, typer.Option("--root", help="Project root override.")] = None,
) -> None:
    """Produce requirements, design, threat model, architecture, and backlog; then pause."""
    project, _config, engine = _project_or_fail(root)
    try:
        record = engine.create_run(objective, provider=provider, apply_changes=False)
        with console.status("[bold green]The ForgeWard planning bench is working…"):
            record = engine.advance(record, plan_only=True)
    except OrchestrationError as exc:
        _fail(exc)
    _show_outcome(project, record)


@app.command()
def run(
    objective: Annotated[str, typer.Argument(help="Outcome the team should deliver.")],
    apply: Annotated[
        bool,
        typer.Option(
            "--apply",
            help=(
                "Allow validated builder proposals to create or update project files after plan "
                "approval."
            ),
        ),
    ] = False,
    provider: Annotated[
        str | None, typer.Option("--provider", help="Provider route for this engagement.")
    ] = None,
    root: Annotated[Path | None, typer.Option("--root", help="Project root override.")] = None,
) -> None:
    """Start a complete gated engagement and stop whenever human approval is required."""
    project, _config, engine = _project_or_fail(root)
    try:
        record = engine.create_run(objective, provider=provider, apply_changes=apply)
        with console.status("[bold green]The ForgeWard team is working…"):
            record = engine.advance(record)
    except OrchestrationError as exc:
        _fail(exc)
    _show_outcome(project, record)


@app.command()
def resume(
    run_id: Annotated[str, typer.Argument(help="Engagement id to continue.")],
    root: Annotated[Path | None, typer.Option("--root", help="Project root override.")] = None,
) -> None:
    """Continue an engagement from its persisted phase."""
    project, _config, engine = _project_or_fail(root)
    try:
        record = engine.store.load(run_id)
        with console.status("[bold green]Resuming the ForgeWard engagement…"):
            record = engine.advance(record)
    except (StateError, OrchestrationError) as exc:
        _fail(exc)
    _show_outcome(project, record)


@app.command()
def approve(
    run_id: Annotated[str, typer.Argument(help="Engagement id.")],
    gate: Annotated[str, typer.Argument(help="Gate id: plan or release.")],
    root: Annotated[Path | None, typer.Option("--root", help="Project root override.")] = None,
) -> None:
    """Record an explicit human gate approval; continuation remains a separate command."""
    _project_path, _config, engine = _project_or_fail(root)
    try:
        record = engine.store.load(run_id)
        engine.approve_gate(record, gate, actor=human_actor())
    except (StateError, OrchestrationError) as exc:
        _fail(exc)
    console.print(
        Text.assemble(
            ("Approved", "green"), " ", _safe_text(gate), " for ", _safe_text(run_id), "."
        )
    )
    console.print(Text.assemble("Continue with: ", (f"forgeward resume {run_id}", "cyan")))


@app.command()
def reject(
    run_id: Annotated[str, typer.Argument(help="Engagement id.")],
    gate: Annotated[str, typer.Argument(help="Gate id: plan or release.")],
    reason: Annotated[str, typer.Option("--reason", help="Actionable rejection reason.")],
    root: Annotated[Path | None, typer.Option("--root", help="Project root override.")] = None,
) -> None:
    """Reject a gate and record why corrective work is required."""
    _project_path, _config, engine = _project_or_fail(root)
    try:
        record = engine.store.load(run_id)
        engine.reject_gate(record, gate, actor=human_actor(), reason=reason)
    except (StateError, OrchestrationError) as exc:
        _fail(exc)
    console.print(
        Text.assemble(
            ("Rejected", "yellow"), " ", _safe_text(gate), " for ", _safe_text(run_id), "."
        )
    )
    console.print(
        Text.assemble(
            "Return it for corrective work with: ", (f"forgeward resume {run_id}", "cyan")
        )
    )


@app.command()
def status(
    run_id: Annotated[str | None, typer.Argument(help="Engagement id; defaults to latest.")] = None,
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit the run projection as JSON.")
    ] = False,
    root: Annotated[Path | None, typer.Option("--root", help="Project root override.")] = None,
) -> None:
    """Show the latest persisted engagement state."""
    project, _config, _engine = _project_or_fail(root)
    store = RunStore(project)
    try:
        record = store.load(run_id) if run_id else store.latest()
        store.verify_projection(record)
        store.verify_artifacts(record)
    except StateError as exc:
        _fail(exc)
    if as_json:
        console.print_json(record.model_dump_json())
        return
    _print_run(record)


@app.command()
def inspect(
    run_id: Annotated[str, typer.Argument(help="Engagement id.")],
    root: Annotated[Path | None, typer.Option("--root", help="Project root override.")] = None,
) -> None:
    """Inspect gates, artifacts, checks, blockers, and verified ledger events."""
    project, _config, _engine = _project_or_fail(root)
    store = RunStore(project)
    try:
        record = store.load(run_id)
        events = store.events(run_id, verify=True)
        store.verify_artifacts(record)
    except StateError as exc:
        _fail(exc)
    _print_run(record)
    artifacts = Table(title=f"Evidence artifacts · {len(record.artifacts)}")
    artifacts.add_column("Path")
    artifacts.add_column("Kind")
    artifacts.add_column("Author")
    artifacts.add_column("SHA-256", overflow="fold")
    for item in record.artifacts:
        artifacts.add_row(
            _safe_text(item.path),
            _safe_text(item.kind),
            _safe_text(item.author),
            _safe_text(item.sha256[:16] + "…"),
        )
    console.print(artifacts)
    ledger = Table(title=f"Verified audit ledger · {len(events)} events")
    ledger.add_column("#", justify="right")
    ledger.add_column("Type")
    ledger.add_column("Actor")
    ledger.add_column("Hash")
    for event in events:
        ledger.add_row(
            _safe_text(event["seq"]),
            _safe_text(event["type"]),
            _safe_text(event["actor"]),
            _safe_text(event["hash"][:16] + "…"),
        )
    console.print(ledger)


@app.command()
def report(
    run_id: Annotated[str, typer.Argument(help="Engagement id.")],
    root: Annotated[Path | None, typer.Option("--root", help="Project root override.")] = None,
) -> None:
    """Generate a local Markdown engagement report after verifying the event chain."""
    project, _config, _engine = _project_or_fail(root)
    store = RunStore(project)
    try:
        record = store.load(run_id)
        store.verify_projection(record)
        store.verify_artifacts(record)
        content = markdown_report(record, store)
        artifact = store.write_artifact(
            record,
            "reports/engagement-report.md",
            content,
            author="orchestrator",
            kind="report",
        )
    except StateError as exc:
        _fail(exc)
    console.print(
        Text.assemble(
            "Report written to ",
            (sanitize_terminal_text(str(store.directory(run_id) / artifact.path)), "cyan"),
        )
    )


@app.command(name="export")
def export_evidence(
    run_id: Annotated[str, typer.Argument(help="Engagement id.")],
    root: Annotated[Path | None, typer.Option("--root", help="Project root override.")] = None,
) -> None:
    """Create a best-effort redacted ZIP of the local evidence pack."""
    project, _config, _engine = _project_or_fail(root)
    store = RunStore(project)
    try:
        record = store.load(run_id)
        store.verify_projection(record)
        store.verify_artifacts(record)
        output = store.export_redacted(record)
    except StateError as exc:
        _fail(exc)
    console.print(
        Text.assemble("Redacted evidence pack: ", (sanitize_terminal_text(str(output)), "cyan"))
    )


@provider_app.command("list")
def provider_list(
    root: Annotated[Path | None, typer.Option("--root", help="Project root override.")] = None,
) -> None:
    """List configured provider routes without reading or printing key values."""
    _project_path, config, _engine = _project_or_fail(root)
    table = Table(title="Model provider routes")
    table.add_column("Name")
    table.add_column("Adapter")
    table.add_column("Model")
    table.add_column("Endpoint")
    table.add_column("Credential")
    table.add_column("Enabled")
    for name, item in config.providers.items():
        table.add_row(
            _safe_text(name),
            _safe_text(item.adapter),
            _safe_text(item.model),
            _safe_text(_provider_endpoint_label(item)),
            _safe_text(item.api_key_env or "none"),
            _safe_text("yes" if item.enabled else "no"),
        )
    console.print(table)


def _provider_endpoint_label(item: object) -> str:
    adapter = getattr(item, "adapter", None)
    base_url = getattr(item, "base_url", None)
    if adapter == "demo":
        return "offline"
    if adapter == "litellm" and base_url is None:
        return "LiteLLM native (delegated)"
    return str(base_url or "unconfigured")


@provider_app.command("test")
def provider_test(
    name: Annotated[
        str | None, typer.Argument(help="Provider name; defaults to project route.")
    ] = None,
    root: Annotated[Path | None, typer.Option("--root", help="Project root override.")] = None,
) -> None:
    """Make one explicit readiness request to a provider."""
    _project_path, config, _engine = _project_or_fail(root)
    selected = name or config.project.default_provider
    if selected not in config.providers:
        _fail(OrchestrationError(f"Unknown provider: {selected}"))
    item = config.providers[selected]
    if not item.enabled:
        _fail(OrchestrationError(f"Provider is disabled: {selected}"))
    try:
        ok, detail = create_provider(item).probe()
    except ProviderError as exc:
        _fail(exc)
    result = Text("PASS" if ok else "FAIL", style="green" if ok else "red")
    result.append(" ")
    result.append_text(_safe_text(selected))
    result.append(": ")
    result.append_text(_safe_text(detail))
    console.print(result)
    if not ok:
        raise typer.Exit(1)


@team_app.command("list")
def team_list(
    root: Annotated[Path | None, typer.Option("--root", help="Project root override.")] = None,
) -> None:
    """List roles, missions, tool declarations, and approval authority."""
    _project_path, config, _engine = _project_or_fail(root)
    table = Table(title="ForgeWard firm")
    table.add_column("Role")
    table.add_column("Mission")
    table.add_column("Provider")
    table.add_column("Declared tools")
    table.add_column("May approve")
    for role in config.team:
        table.add_row(
            _safe_text(role.id),
            _safe_text(role.mission),
            _safe_text(role.provider or config.project.default_provider),
            _safe_text(", ".join(role.allowed_tools) or "none"),
            _safe_text(", ".join(role.may_approve) or "none"),
        )
    console.print(table)


@team_app.command("validate")
def team_validate(
    root: Annotated[Path | None, typer.Option("--root", help="Project root override.")] = None,
) -> None:
    """Validate role references and enforce no model self-approval."""
    _project_path, config, _engine = _project_or_fail(root)
    offenders = [role.id for role in config.team if role.may_approve]
    if offenders:
        err_console.print(
            "[red]FAIL[/red] model roles must not approve gates: " + ", ".join(offenders)
        )
        raise typer.Exit(1)
    console.print(
        f"[green]PASS[/green] {len(config.team)} roles validated; no self-approval authority."
    )


@policy_app.command("check")
def policy_check(
    root: Annotated[Path | None, typer.Option("--root", help="Project root override.")] = None,
) -> None:
    """Evaluate hard security invariants in the configured policy."""
    _project_path, config, _engine = _project_or_fail(root)
    findings: list[tuple[str, bool, str]] = []
    normalized = {item.replace("\\", "/").strip("./") for item in config.policy.denied_paths}
    findings.append(("Git internals protected", "git" in normalized, ".git"))
    findings.append(("ForgeWard policy/state protected", "forgeward" in normalized, ".forgeward"))
    findings.append(("Common env files protected", "env" in normalized, ".env"))
    findings.append(("Plan gate human-controlled", "plan" in config.policy.human_gates, "plan"))
    findings.append(
        ("Release gate human-controlled", "release" in config.policy.human_gates, "release")
    )
    findings.append(
        ("Telemetry disabled", not config.policy.telemetry, str(config.policy.telemetry))
    )
    findings.append(
        (
            "No role can self-approve",
            not any(role.may_approve for role in config.team),
            "role may_approve lists",
        )
    )
    table = Table(title="Deterministic policy checks")
    table.add_column("Invariant")
    table.add_column("Result")
    table.add_column("Evidence")
    for title, passed, evidence in findings:
        table.add_row(
            _safe_text(title),
            Text("PASS" if passed else "FAIL", style="green" if passed else "red"),
            _safe_text(evidence),
        )
    console.print(table)
    if not all(passed for _, passed, _ in findings):
        raise typer.Exit(1)


def _project(root: Path | None) -> tuple[Path, ForgeWardConfig, ForgeWardEngine]:
    project = root.resolve() if root else find_project_root()
    config = load_config(project)
    return project, config, ForgeWardEngine(project, config)


def _project_or_fail(root: Path | None) -> tuple[Path, ForgeWardConfig, ForgeWardEngine]:
    try:
        return _project(root)
    except (ConfigError, StateError, OrchestrationError) as exc:
        _fail(exc)
    raise AssertionError("unreachable")


def _show_outcome(project: Path, record: RunRecord) -> None:
    _print_run(record)
    run_dir = project / ".forgeward" / "runs" / record.id
    console.print(Text.assemble("Evidence: ", (sanitize_terminal_text(str(run_dir)), "cyan")))
    if record.state == RunState.PLAN_GATE:
        console.print(
            Text.assemble("Review it, then: ", (f"forgeward approve {record.id} plan", "cyan"))
        )
    elif record.state == RunState.RELEASE_GATE:
        if record.blockers:
            console.print(
                "[red]Release is blocked.[/red] Reject the gate after reviewing evidence."
            )
        else:
            console.print(
                Text.assemble(
                    "Review it, then: ", (f"forgeward approve {record.id} release", "cyan")
                )
            )
    elif record.state == RunState.COMPLETE:
        console.print(
            Text.assemble(("Engagement complete.", "green"), f" Run: forgeward report {record.id}")
        )


def _print_run(record: RunRecord) -> None:
    gate_text = (
        ", ".join(f"{name}={gate.decision.value}" for name, gate in record.gates.items()) or "none"
    )
    body = Text(sanitize_terminal_text(record.id), style="bold")
    body.append("\nState: ")
    body.append(record.state.value, style="cyan")
    body.append("\nProvider: ")
    body.append(sanitize_terminal_text(record.provider))
    body.append(f" · Calls: {record.calls_made}\nGates: ")
    body.append(sanitize_terminal_text(gate_text))
    body.append(f"\nArtifacts: {len(record.artifacts)} · Events: {record.event_count}")
    if record.blockers:
        body.append("\nBlockers:")
        for item in record.blockers:
            body.append("\n  • ")
            body.append(sanitize_terminal_text(item))
    if record.failure:
        body.append("\nLast interruption: ")
        body.append(sanitize_terminal_text(record.failure), style="yellow")
    console.print(Panel(body, title="ForgeWard engagement", border_style="green"))


def _fail(exc: Exception) -> None:
    message = Text("Error:", style="red")
    message.append(" ")
    message.append(sanitize_terminal_text(str(exc)))
    err_console.print(message)
    raise typer.Exit(1)


def _safe_text(value: object) -> Text:
    return Text(sanitize_terminal_text(str(value)))


if __name__ == "__main__":
    app()
