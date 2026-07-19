"""Anzen command-line interface."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

from . import __version__
from .store import SEVERITY_ORDER, Store, anzen_home, default_db

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 4318

_DB_OPTION = typer.Option(None, "--db", help="SQLite database path (default: ~/.anzen/anzen.db).")


def _db(db: str | None) -> str:
    return db or default_db()

app = typer.Typer(
    help="Anzen — flight recorder and compliance auditor for AI agents.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()

_SEV_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def _ago(timestamp: float | None) -> str:
    """Humanize a unix timestamp as time elapsed ('42s ago', '3m ago')."""
    from datetime import datetime, timezone

    if not timestamp:
        return "never"
    delta = datetime.now(timezone.utc).timestamp() - timestamp
    if delta < 120:
        return f"{delta:.0f}s ago"
    if delta < 7200:
        return f"{delta / 60:.0f}m ago"
    return f"{delta / 3600:.1f}h ago"


def _findings_cells(counts: dict[str, int]) -> str:
    parts = [f"[{_SEV_STYLE[sev]}]{counts[sev]} {sev}[/]" for sev in SEVERITY_ORDER if counts.get(sev)]
    return "  ".join(parts) or "[green]clean[/green]"


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"anzen {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    pass


@app.command()
def serve(
    port: int = typer.Option(DEFAULT_PORT, help="OTLP/HTTP port to listen on."),
    host: str = typer.Option(DEFAULT_HOST, help="Host to bind."),
    db: str = _DB_OPTION,
) -> None:
    """Start the collector: receive and record agent telemetry (OpenInference over OTLP)."""
    from .collector import make_server
    from .rules import load_rules

    db = _db(db)
    store = Store(db)
    rules = load_rules()
    server = make_server(store, host=host, port=port, rules=rules)
    console.print(f"[bold]anzen[/bold] collector · db=[cyan]{db}[/cyan] · "
                  f"auto-scan: [green]{len(rules)} rules[/green]")
    console.print(f"listening on [green]http://{host}:{port}/v1/traces[/green]")
    console.print("[dim]inspect with: anzen list · anzen show <session>[/dim]")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        store.close()


@app.command(name="list")
def list_sessions(db: str = _DB_OPTION) -> None:
    """List recorded agent sessions."""
    db = _db(db)
    store = Store(db)
    sessions = store.list_sessions()
    if not sessions:
        console.print("[dim]No sessions recorded yet. Run `anzen serve` and point an agent at it.[/dim]")
        return

    table = Table(title="Agent sessions")
    table.add_column("Session", style="cyan", no_wrap=True)
    table.add_column("Agent")
    table.add_column("Actions", justify="right")
    table.add_column("Findings")
    for s in sessions:
        table.add_row(s.id, s.agent_name, str(s.action_count), _findings_cells(s.finding_counts))
    console.print(table)
    store.close()


@app.command()
def show(
    session_id: str = typer.Argument(..., help="Session id (or unique prefix)."),
    db: str = _DB_OPTION,
    full: bool = typer.Option(False, "--full", help="Show untruncated inputs/outputs."),
) -> None:
    """Show the captured action timeline for a session (pure observation, no verdicts)."""
    from datetime import datetime, timezone

    db = _db(db)
    store = Store(db)
    session = store.get_session(session_id)
    if session is None:
        console.print(f"[red]No session matching '{session_id}'.[/red]")
        raise typer.Exit(1)

    actions = store.get_actions(session.id)
    console.print(
        f"[bold]{session.id}[/bold] · agent=[cyan]{session.agent_name}[/cyan] · "
        f"{len(actions)} actions · {session.input_tokens} tok in / {session.output_tokens} tok out"
    )

    def clip(text: str, limit: int = 120) -> str:
        text = text.replace("\n", " ")
        return text if full or len(text) <= limit else text[:limit] + "…"

    for i, a in enumerate(actions, 1):
        ts = datetime.fromtimestamp(a.timestamp, tz=timezone.utc).strftime("%H:%M:%S")
        style = {"tool_call": "yellow", "llm_call": "magenta", "agent_invoke": "blue"}.get(
            a.action_type.value, "dim"
        )
        console.print(f"[dim]{i:>3}  {ts}[/dim]  [{style}]{a.action_type.value:<12}[/] [bold]{a.name}[/bold]"
                      + ("  [red](error)[/red]" if a.status == "error" else ""))
        if a.input:
            console.print(f"       [dim]in:[/dim]  {clip(a.input)}")
        if a.output:
            console.print(f"       [dim]out:[/dim] {clip(a.output)}")
    store.close()


@app.command()
def scan(
    session_id: str = typer.Argument(..., help="Session id (or unique prefix)."),
    db: str = _DB_OPTION,
    rules_dir: str = typer.Option(None, "--rules", help="Extra rules directory."),
    llm: bool = typer.Option(False, "--llm", help="Add a Claude contextual analysis pass."),
) -> None:
    """Re-run deterministic rules (and optionally the Claude analysis pass)."""
    from .rules import load_rules, scan_session

    db = _db(db)
    store = Store(db)
    session = store.get_session(session_id)
    if session is None:
        console.print(f"[red]No session matching '{session_id}'.[/red]")
        raise typer.Exit(1)

    rules = load_rules(rules_dir)
    findings = scan_session(store, session.id, rules)
    console.print(f"Deterministic scan: [bold]{len(findings)}[/bold] finding(s).")

    if llm:
        from .llm import LlmUnavailable, analyze_session

        try:
            llm_findings = analyze_session(store, session.id)
            console.print(f"Claude analysis: [bold]{len(llm_findings)}[/bold] contextual finding(s).")
        except LlmUnavailable as exc:
            console.print(f"[yellow]LLM pass skipped:[/yellow] {exc}")

    total = len(store.get_findings(session.id))
    console.print(f"Total findings for [cyan]{session.id}[/cyan]: [bold]{total}[/bold]. "
                  f"Run [green]anzen report {session.id}[/green] for the full audit.")
    store.close()


@app.command()
def report(
    session_id: str = typer.Argument(..., help="Session id (or unique prefix)."),
    db: str = _DB_OPTION,
    out: str = typer.Option(None, "-o", "--out", help="Write Markdown report to this path."),
) -> None:
    """Render the audit report for a session (terminal + optional file)."""
    from .report import build_report

    db = _db(db)
    store = Store(db)
    try:
        session, markdown = build_report(store, session_id)
    except KeyError:
        console.print(f"[red]No session matching '{session_id}'.[/red]")
        raise typer.Exit(1)

    console.print(Markdown(markdown))
    if out:
        Path(out).write_text(markdown)
        console.print(f"\n[green]Report written to {out}[/green]")
    store.close()


def _collector_healthy(host: str, port: int, timeout: float = 1.0) -> bool:
    import urllib.request

    try:
        with urllib.request.urlopen(f"http://{host}:{port}/healthz", timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


@app.command()
def agents(db: str = _DB_OPTION) -> None:
    """The managed-agents view: every agent Anzen has seen, with live posture."""
    db = _db(db)
    store = Store(db)
    rows = store.list_agents()
    store.close()
    if not rows:
        console.print("[dim]No agents observed yet. Connect one:[/dim]")
        console.print("  · Claude Code: [green]anzen install-hook[/green] (with the collector running)")
        console.print("  · OpenInference agents: set "
                      "[green]OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318[/green]")
        return

    table = Table(title="Managed agents")
    table.add_column("Agent", style="cyan")
    table.add_column("Sessions", justify="right")
    table.add_column("Actions", justify="right")
    table.add_column("Last seen")
    table.add_column("Findings")
    for a in rows:
        table.add_row(
            a["agent_name"], str(a["sessions"]), str(a["actions"]),
            _ago(a["last_seen"]), _findings_cells(a["finding_counts"]),
        )
    console.print(table)


@app.command()
def status(
    db: str = _DB_OPTION,
    port: int = typer.Option(DEFAULT_PORT, help="Collector port to health-check."),
    host: str = typer.Option(DEFAULT_HOST, help="Collector host to health-check."),
) -> None:
    """One-glance health: collector, database, captured activity, hook installation."""
    db = _db(db)
    if _collector_healthy(host, port):
        console.print(f"[green]●[/green] collector [green]running[/green] — "
                      f"http://{host}:{port}/v1/traces")
    else:
        console.print("[red]●[/red] collector [red]not running[/red] — "
                      "start with: [green]anzen serve[/green]")

    db_path = Path(db)
    size = f"{db_path.stat().st_size / 1024:.0f} KB" if db_path.exists() else "not created yet"
    console.print(f"  home: [cyan]{anzen_home()}[/cyan] · db: {db_path.name} ({size})")

    store = Store(db)
    stats = store.stats()
    store.close()
    console.print(f"  captured: {stats['sessions']} sessions · {stats['actions']} actions · "
                  f"last activity: {_ago(stats['last_action_at'])}")
    console.print(f"  findings: {_findings_cells(stats['findings'])}")

    hooks = []
    for scope, user_flag in (("project", False), ("user", True)):
        path = _settings_path(user_flag)
        if path.exists() and _HOOK_MARKER in path.read_text():
            hooks.append(scope)
    hook_str = ", ".join(hooks) if hooks else "not installed [dim](anzen install-hook)[/dim]"
    console.print(f"  claude-code hook: {hook_str}")


_HOOK_MARKER = "anzen.claude_code_hook"


def _settings_path(user: bool) -> "Path":
    from pathlib import Path

    base = Path.home() / ".claude" if user else Path.cwd() / ".claude"
    return base / "settings.json"


@app.command(name="install-hook")
def install_hook(
    user: bool = typer.Option(False, "--user", help="Install into ~/.claude/settings.json instead of ./.claude/settings.json."),
    endpoint: str = typer.Option(None, "--endpoint", help="Collector endpoint if not the default http://127.0.0.1:4318."),
) -> None:
    """Capture Claude Code sessions: add a PostToolUse hook that streams tool calls to Anzen."""
    import json as jsonlib

    path = _settings_path(user)
    settings = {}
    if path.exists():
        try:
            settings = jsonlib.loads(path.read_text() or "{}")
        except jsonlib.JSONDecodeError:
            console.print(f"[red]{path} exists but is not valid JSON — fix it first, not overwriting.[/red]")
            raise typer.Exit(1)

    # Use the interpreter anzen is installed in — a bare `python3` may not
    # have the anzen package importable (e.g. venv installs).
    import sys as syslib

    command = f'"{syslib.executable}" -m {_HOOK_MARKER}'
    if endpoint:
        command = f"ANZEN_ENDPOINT={endpoint} {command}"

    post = settings.setdefault("hooks", {}).setdefault("PostToolUse", [])
    for entry in post:
        for hook in entry.get("hooks", []):
            if _HOOK_MARKER in hook.get("command", ""):
                hook["command"] = command  # already installed — refresh endpoint if changed
                break
        else:
            continue
        break
    else:
        post.append({"matcher": "*", "hooks": [{"type": "command", "command": command}]})

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(jsonlib.dumps(settings, indent=2) + "\n")
    console.print(f"[green]Anzen hook installed[/green] in [cyan]{path}[/cyan]")
    console.print("[dim]Takes effect in new Claude Code sessions. Remove with: anzen uninstall-hook"
                  + (" --user" if user else "") + "[/dim]")


@app.command(name="uninstall-hook")
def uninstall_hook(
    user: bool = typer.Option(False, "--user", help="Remove from ~/.claude/settings.json instead of ./.claude/settings.json."),
) -> None:
    """Remove the Anzen PostToolUse hook from Claude Code settings."""
    import json as jsonlib

    path = _settings_path(user)
    if not path.exists():
        console.print(f"[dim]{path} does not exist — nothing to remove.[/dim]")
        return
    settings = jsonlib.loads(path.read_text() or "{}")
    post = settings.get("hooks", {}).get("PostToolUse", [])
    removed = False
    for entry in post[:]:
        hooks = [h for h in entry.get("hooks", []) if _HOOK_MARKER not in h.get("command", "")]
        if len(hooks) != len(entry.get("hooks", [])):
            removed = True
            if hooks:
                entry["hooks"] = hooks
            else:
                post.remove(entry)
    if settings.get("hooks", {}).get("PostToolUse") == []:
        del settings["hooks"]["PostToolUse"]
        if not settings["hooks"]:
            del settings["hooks"]
    path.write_text(jsonlib.dumps(settings, indent=2) + "\n")
    console.print(
        f"[green]Anzen hook removed[/green] from [cyan]{path}[/cyan]" if removed
        else f"[dim]No Anzen hook found in {path}.[/dim]"
    )


if __name__ == "__main__":
    app()
