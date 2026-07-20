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
def report(
    session_id: str = typer.Argument(..., help="Session id (or unique prefix)."),
    db: str = _DB_OPTION,
    out: str = typer.Option(None, "-o", "--out", help="Write Markdown report to this path."),
    rules_dir: str = typer.Option(None, "--rules", help="Re-scan with an extra rules directory."),
    llm: bool = typer.Option(False, "--llm", help="Add a Claude contextual analysis pass first."),
) -> None:
    """Render the audit report for a session (terminal + optional file).

    Rules already ran automatically as actions arrived; `--rules` re-scans with
    an extra pack and `--llm` adds the cross-action Claude pass before rendering.
    """
    from .report import build_report

    db = _db(db)
    store = Store(db)
    session = store.get_session(session_id)
    if session is None:
        console.print(f"[red]No session matching '{session_id}'.[/red]")
        raise typer.Exit(1)

    if rules_dir:
        from .rules import load_rules, scan_session

        findings = scan_session(store, session.id, load_rules(rules_dir))
        console.print(f"[dim]Re-scanned with {rules_dir}: {len(findings)} finding(s).[/dim]")

    if llm:
        from .llm import LlmUnavailable, analyze_session

        try:
            llm_findings = analyze_session(store, session.id)
            console.print(f"[dim]Claude analysis: {len(llm_findings)} contextual finding(s).[/dim]")
        except LlmUnavailable as exc:
            console.print(f"[yellow]LLM pass skipped:[/yellow] {exc}")

    try:
        session, markdown = build_report(store, session.id)
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
def status(
    db: str = _DB_OPTION,
    port: int = typer.Option(DEFAULT_PORT, help="Collector port to health-check."),
    host: str = typer.Option(DEFAULT_HOST, help="Collector host to health-check."),
) -> None:
    """One glance: collector health, agents seen, findings."""
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
    agent_rows = store.list_agents()
    store.close()
    console.print(f"  captured: {stats['sessions']} sessions · {stats['actions']} actions · "
                  f"last activity: {_ago(stats['last_action_at'])}")
    console.print(f"  findings: {_findings_cells(stats['findings'])}")

    if not agent_rows:
        console.print("\n[dim]No agents observed yet. Point an agent's OTel exporter at the collector:[/dim]")
        console.print("  [green]OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318[/green]")
        return

    table = Table(title="Agents")
    table.add_column("Agent", style="cyan")
    table.add_column("Sessions", justify="right")
    table.add_column("Actions", justify="right")
    table.add_column("Last seen")
    table.add_column("Findings")
    for a in agent_rows:
        table.add_row(
            a["agent_name"], str(a["sessions"]), str(a["actions"]),
            _ago(a["last_seen"]), _findings_cells(a["finding_counts"]),
        )
    console.print(table)


if __name__ == "__main__":
    app()
