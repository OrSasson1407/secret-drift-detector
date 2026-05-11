import asyncio
import json as _json
from datetime import datetime, timezone, timedelta

import click
from rich.console import Console
from rich.table import Table

from detector.agent import Agent
from detector.diff.models import DriftReport, Severity
from detector.storage.history import History

console = Console()

_SEV_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "warn":     "yellow",
    "info":     "dim",
}


def _render_table(report: DriftReport):
    if not report.has_drift:
        console.print("[bold green]✔ No drift detected — runtime matches expected secrets.[/bold green]")
        return

    console.print(
        f"\n[bold red]✖ DRIFT DETECTED — {len(report.items)} item(s)[/bold red]  "
        f"[dim]{report.checked_at.strftime('%Y-%m-%d %H:%M:%S UTC')}[/dim]"
    )
    console.print(f"  Sources : [cyan]{', '.join(report.sources) or '—'}[/cyan]")
    console.print(f"  Targets : [cyan]{', '.join(report.targets) or '—'}[/cyan]\n")

    tbl = Table(show_header=True, header_style="bold magenta", border_style="dim")
    tbl.add_column("KEY",      style="cyan",  no_wrap=True)
    tbl.add_column("KIND",     style="white")
    tbl.add_column("SEVERITY", no_wrap=True)
    tbl.add_column("DETAIL",   style="dim")

    for item in sorted(report.items, key=lambda i: -i.severity.rank):
        color = _SEV_COLOR.get(item.severity.value, "white")
        tbl.add_row(
            item.key,
            item.kind.value,
            f"[{color}]{item.severity.value.upper()}[/{color}]",
            item.detail,
        )
    console.print(tbl)
    console.print()


@click.group()
def cli():
    """Secret Drift Detector — catch config drift before it becomes an incident."""


@cli.command()
@click.option("--config",  default="config/detector.toml", show_default=True, help="Path to detector.toml")
@click.option("--output",  type=click.Choice(["table", "json"]), default="table", show_default=True)
@click.option("--min-severity", default="info", show_default=True,
              type=click.Choice(["info","warn","high","critical"]),
              help="Only show items at or above this severity")
def check(config, output, min_severity):
    """One-shot drift check. Exits 1 if drift is found (and fail_on_drift=true)."""
    async def _run():
        agent  = Agent.from_config(config)
        report = await agent.run_once()

        if output == "json":
            console.print_json(report.model_dump_json(indent=2))
        else:
            # Filter display by min_severity
            threshold = Severity(min_severity)
            report.items = report.items_at_or_above(threshold)
            _render_table(report)

        if agent.config.agent.fail_on_drift and report.has_drift:
            raise SystemExit(1)

    asyncio.run(_run())


@cli.command()
@click.option("--config",   default="config/detector.toml", show_default=True)
@click.option("--interval", type=int, default=None, help="Override interval_seconds from config")
def watch(config, interval):
    """Continuous daemon mode — polls on a configurable interval."""
    async def _run():
        agent = Agent.from_config(config)
        ivl   = interval or agent.config.agent.interval_seconds
        console.print(f"[bold]Watch mode[/bold] — polling every [cyan]{ivl}s[/cyan]. Ctrl+C to stop.\n")
        await agent.run_loop(override_interval=ivl)

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("\n[dim]Stopped.[/dim]")


@cli.command()
@click.option("--db",         default="drift_history.db", show_default=True)
@click.option("--limit",      default=20,  show_default=True, type=int)
@click.option("--only-drift", is_flag=True, default=False, help="Show only runs with drift")
@click.option("--since",      default=None, help="ISO date or relative e.g. '24h', '7d'")
@click.option("--output",     type=click.Choice(["table","json"]), default="table", show_default=True)
def report(db, limit, only_drift, since, output):
    """Show drift history from the local SQLite database."""
    hist = History(db_path=db)
    runs = hist.list_runs(limit=limit, only_drift=only_drift)

    if since:
        cutoff = _parse_since(since)
        runs   = [r for r in runs if datetime.fromisoformat(r.timestamp) >= cutoff]

    if output == "json":
        console.print_json(_json.dumps([r.__dict__ for r in runs], default=str))
        return

    if not runs:
        console.print("[dim]No runs found.[/dim]")
        return

    tbl = Table(show_header=True, header_style="bold magenta", border_style="dim")
    tbl.add_column("ID",       style="dim",   justify="right")
    tbl.add_column("TIMESTAMP")
    tbl.add_column("DRIFT",    justify="center")
    tbl.add_column("ITEMS",    justify="right")
    tbl.add_column("MAX SEV")
    tbl.add_column("SOURCES",  style="dim")

    for r in runs:
        drift_cell = "[red]YES[/red]" if r.has_drift else "[green]no[/green]"
        sev        = r.max_severity or "—"
        color      = _SEV_COLOR.get(sev, "white")
        tbl.add_row(
            str(r.id),
            r.timestamp[:19].replace("T", " "),
            drift_cell,
            str(r.drift_count),
            f"[{color}]{sev.upper()}[/{color}]" if r.has_drift else "—",
            ", ".join(r.sources)[:40] or "—",
        )
    console.print(tbl)


def _parse_since(value: str) -> datetime:
    """Accept ISO datetime string or shorthand like '24h' / '7d'."""
    now = datetime.now(timezone.utc)
    if value.endswith("h"):
        return now - timedelta(hours=int(value[:-1]))
    if value.endswith("d"):
        return now - timedelta(days=int(value[:-1]))
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)


if __name__ == "__main__":
    cli()
