import asyncio
import json as _json
from datetime import datetime, timezone, timedelta

import click
from rich.console import Console
from rich.table import Table

from detector.agent import Agent
from detector.diff.models import DriftReport, Severity
from detector.storage.history import History
from detector.storage.snapshot import Storage

console = Console()

_SEV_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "warn":     "yellow",
    "info":     "dim",
}

_SEV_ICON = {
    "critical": "[bold red]●[/bold red]",
    "high":     "[red]●[/red]",
    "warn":     "[yellow]●[/yellow]",
    "info":     "[dim]●[/dim]",
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


# ── check ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--config",       default="config/detector.toml", show_default=True)
@click.option("--output",       type=click.Choice(["table", "json"]), default="table", show_default=True)
@click.option("--min-severity", default="info", show_default=True,
              type=click.Choice(["info", "warn", "high", "critical"]))
def check(config, output, min_severity):
    """One-shot drift check. Exits 1 if drift is found (and fail_on_drift=true)."""
    async def _run():
        agent  = Agent.from_config(config)
        report = await agent.run_once()

        if output == "json":
            console.print_json(report.model_dump_json(indent=2))
        else:
            threshold    = Severity(min_severity)
            report.items = report.items_at_or_above(threshold)
            _render_table(report)

        if agent.config.agent.fail_on_drift and report.has_drift:
            raise SystemExit(1)

    asyncio.run(_run())


# ── watch ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--config",   default="config/detector.toml", show_default=True)
@click.option("--interval", type=int, default=None, help="Override interval_seconds from config")
def watch(config, interval):
    """Continuous daemon mode — polls on a configurable interval, prints each result."""
    async def _run():
        agent   = Agent.from_config(config)
        ivl     = interval or agent.config.agent.interval_seconds
        run_num = 0

        console.print(
            f"[bold]Watch mode[/bold] — config: [cyan]{config}[/cyan]  "
            f"interval: [cyan]{ivl}s[/cyan]  "
            f"db: [cyan]{agent.config.agent.db_path}[/cyan]\n"
            "Press Ctrl+C to stop.\n"
        )

        while True:
            run_num += 1
            ts     = datetime.now(timezone.utc).strftime("%H:%M:%S")
            report = await agent.run_once()

            if report.has_drift:
                icon  = _SEV_ICON.get(report.max_severity.value, "●") if report.max_severity else "●"
                console.print(
                    f"[dim]{ts}[/dim]  run #{run_num}  {icon}  "
                    f"[red]{len(report.items)} drift item(s)[/red]  "
                    f"max=[bold]{report.max_severity.value if report.max_severity else '?'}[/bold]"
                )
            else:
                console.print(
                    f"[dim]{ts}[/dim]  run #{run_num}  [green]✔ clean[/green]  "
                    f"{report.expected_count} keys checked"
                )

            await asyncio.sleep(ivl)

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("\n[dim]Stopped.[/dim]")


# ── report ────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--db",         default="drift_history.db", show_default=True)
@click.option("--limit",      default=20,  show_default=True, type=int)
@click.option("--only-drift", is_flag=True, default=False)
@click.option("--since",      default=None, help="ISO date or relative: '24h', '7d'")
@click.option("--output",     type=click.Choice(["table", "json"]), default="table", show_default=True)
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
    tbl.add_column("ID",      style="dim", justify="right")
    tbl.add_column("TIMESTAMP")
    tbl.add_column("DRIFT",   justify="center")
    tbl.add_column("ITEMS",   justify="right")
    tbl.add_column("MAX SEV")
    tbl.add_column("SOURCES", style="dim")

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


# ── stats ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--db",     default="drift_history.db", show_default=True)
@click.option("--output", type=click.Choice(["table", "json"]), default="table", show_default=True)
def stats(db, output):
    """Show aggregate drift statistics across all recorded runs."""
    hist = History(db_path=db)
    s    = hist.stats()

    if output == "json":
        console.print_json(_json.dumps(s))
        return

    console.print("\n[bold]Drift Statistics[/bold]\n")
    console.print(f"  Total runs    : [cyan]{s['total_runs']}[/cyan]")
    console.print(f"  Drifted runs  : [red]{s['drifted_runs']}[/red]")
    console.print(f"  Clean runs    : [green]{s['clean_runs']}[/green]")
    console.print(f"  Drift rate    : [yellow]{s['drift_rate_pct']}%[/yellow]")
    console.print(f"  Total items   : {s['total_drift_items']}\n")

    if s["by_max_severity"]:
        tbl = Table(show_header=True, header_style="bold magenta", border_style="dim")
        tbl.add_column("MAX SEVERITY")
        tbl.add_column("DRIFTED RUNS", justify="right")
        for sev in ("critical", "high", "warn", "info"):
            count = s["by_max_severity"].get(sev, 0)
            if count:
                color = _SEV_COLOR.get(sev, "white")
                tbl.add_row(f"[{color}]{sev.upper()}[/{color}]", str(count))
        console.print(tbl)
    console.print()


# ── prune ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--db",   default="drift_history.db", show_default=True)
@click.option("--keep", default=500, show_default=True, type=int,
              help="Number of most recent runs to keep")
@click.confirmation_option(prompt="This will permanently delete old runs. Continue?")
def prune(db, keep):
    """Delete old runs from the history database, keeping the N most recent."""
    storage = Storage(db_path=db)
    deleted = storage.delete_old_runs(keep=keep)
    console.print(f"[green]Pruned {deleted} run(s). Kept most recent {keep}.[/green]")


# ── helpers ───────────────────────────────────────────────────────────────────

def _parse_since(value: str) -> datetime:
    now = datetime.now(timezone.utc)
    if value.endswith("h"):
        return now - timedelta(hours=int(value[:-1]))
    if value.endswith("d"):
        return now - timedelta(days=int(value[:-1]))
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)


if __name__ == "__main__":
    cli()
