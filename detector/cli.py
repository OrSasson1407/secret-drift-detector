import asyncio
import json as _json
import os
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm

from detector.agent import Agent
from detector.diff.models import DriftReport, DriftKind, Severity
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
    \"\"\"Secret Drift Detector — catch config drift before it becomes an incident.\"\"\"


# ── check ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--config",       default="config/detector.toml", show_default=True)
@click.option("--output",       type=click.Choice(["table", "json"]), default="table", show_default=True)
@click.option("--min-severity", default="info", show_default=True,
              type=click.Choice(["info", "warn", "high", "critical"]))
def check(config, output, min_severity):
    \"\"\"One-shot drift check. Exits 1 if drift is found (and fail_on_drift=true).\"\"\"
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
    \"\"\"Continuous daemon mode — polls on a configurable interval.\"\"\"
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
                icon = _SEV_ICON.get(report.max_severity.value, "●") if report.max_severity else "●"
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
    \"\"\"Show drift history from the local SQLite database.\"\"\"
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
    \"\"\"Show aggregate drift statistics across all recorded runs.\"\"\"
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
    \"\"\"Delete old runs from the history database, keeping the N most recent.\"\"\"
    storage = Storage(db_path=db)
    deleted = storage.delete_old_runs(keep=keep)
    console.print(f"[green]Pruned {deleted} run(s). Kept most recent {keep}.[/green]")


# ── init (wizard) ─────────────────────────────────────────────────────────────

@cli.command("init")
@click.option("--output", default="config/detector.toml",
              show_default=True, help="Where to write the generated config")
@click.option("--force",  is_flag=True, default=False,
              help="Overwrite existing config without prompting")
def init_wizard(output, force):
    \"\"\"Interactive wizard — generates a detector.toml from prompted answers.\"\"\"
    console.print("\n[bold cyan]Secret Drift Detector — Setup Wizard[/bold cyan]\n")

    out_path = Path(output)
    if out_path.exists() and not force:
        if not Confirm.ask(f"[yellow]{output}[/yellow] already exists. Overwrite?"):
            console.print("[dim]Aborted.[/dim]")
            return

    console.print("[bold]Agent settings[/bold]")
    interval   = Prompt.ask("  Poll interval (seconds)", default="60")
    db_path    = Prompt.ask("  SQLite database path",    default="drift_history.db")
    fail_drift = Confirm.ask("  Exit with code 1 when drift is found?", default=True)
    alert_extra = Confirm.ask("  Alert on extra runtime keys?", default=False)
    enable_entropy = Confirm.ask("  Enable weak-value entropy scanning?", default=True)

    console.print("\n[bold]Secret source[/bold]")
    src_type = Prompt.ask(
        "  Source type",
        choices=["dotenv", "vault", "ssm", "doppler", "secrets_manager", "gcp", "kubernetes"],
        default="dotenv",
    )

    source_lines: list[str] = [f'[[sources]]', f'type = "{src_type}"']

    if src_type == "dotenv":
        path = Prompt.ask("  Path to .env file", default=".env")
        source_lines.append(f'path = "{path}"')

    elif src_type == "vault":
        addr  = Prompt.ask("  Vault address",   default="http://127.0.0.1:8200")
        path  = Prompt.ask("  Secret path",     default="secret/data/myapp")
        token = Prompt.ask("  Token env var",   default="VAULT_TOKEN")
        max_age = Prompt.ask("  Max secret age in days (blank to skip)", default="")
        source_lines += [
            f'addr  = "{addr}"',
            f'path  = "{path}"',
            f'token = "env:{token}"',
        ]
        if max_age.strip():
            source_lines.append(f'max_age_days = {int(max_age)}')

    elif src_type == "ssm":
        prefix = Prompt.ask("  SSM parameter prefix", default="/myapp/prod/")
        region = Prompt.ask("  AWS region",           default="us-east-1")
        source_lines += [f'prefix = "{prefix}"', f'region = "{region}"']

    elif src_type == "doppler":
        project    = Prompt.ask("  Doppler project")
        config_env = Prompt.ask("  Doppler config/environment", default="prd")
        token_var  = Prompt.ask("  Token env var", default="DOPPLER_TOKEN")
        source_lines += [
            f'project    = "{project}"',
            f'config_env = "{config_env}"',
            f'token      = "env:{token_var}"',
        ]

    elif src_type == "secrets_manager":
        path   = Prompt.ask("  Secret name/ARN")
        region = Prompt.ask("  AWS region", default="us-east-1")
        source_lines += [f'path = "{path}"', f'region = "{region}"']

    console.print("\n[bold]Runtime target[/bold]")
    tgt_type = Prompt.ask(
        "  Target type",
        choices=["local_env", "docker", "proc", "k8s_exec"],
        default="local_env",
    )

    target_lines: list[str] = ["[[targets]]", f'type = "{tgt_type}"']

    if tgt_type == "docker":
        container = Prompt.ask("  Container name")
        target_lines.append(f'container = "{container}"')
    elif tgt_type == "proc":
        pid_file = Prompt.ask("  PID file path")
        target_lines.append(f'pid_file = "{pid_file}"')
    elif tgt_type == "k8s_exec":
        pod = Prompt.ask("  Pod name")
        ns  = Prompt.ask("  Namespace", default="default")
        target_lines += [f'pod = "{pod}"', f'namespace = "{ns}"']

    alert_lines: list[str] = []
    if Confirm.ask("\n  Configure Slack alerts?", default=False):
        hook_var = Prompt.ask("  Slack webhook env var", default="SLACK_WEBHOOK_URL")
        mention  = Prompt.ask("  Mention (e.g. <!channel>, blank to skip)", default="")
        alert_lines = [
            "[alerts.slack]",
            "enabled     = true",
            f'webhook_url = "env:{hook_var}"',
            'min_severity = "warn"',
        ]
        if mention:
            alert_lines.append(f'mention = "{mention}"')

    lines = [
        "# detector.toml — generated by detector init",
        "",
        "[agent]",
        f"interval_seconds = {interval}",
        f'db_path          = "{db_path}"',
        f"fail_on_drift    = {'true' if fail_drift else 'false'}",
        f"alert_on_extra   = {'true' if alert_extra else 'false'}",
        f"enable_entropy   = {'true' if enable_entropy else 'false'}",
        "",
        "\n".join(source_lines),
        "",
        "\n".join(target_lines),
    ]
    if alert_lines:
        lines += ["", "\n".join(alert_lines)]

    toml_text = "\n".join(lines) + "\n"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(toml_text, encoding="utf-8")
    console.print(f"\n[bold green]✔ Config written to {output}[/bold green]")
    console.print(f"  Run [cyan]detector check --config {output}[/cyan] to verify connectivity.\n")


# ── simulate ──────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--config",       default="config/detector.toml", show_default=True)
@click.option("--delete",       multiple=True, metavar="KEY",  help="Remove KEY from expected snapshot")
@click.option("--change",       multiple=True, metavar="KEY",  help="Change value of KEY to a random hash")
@click.option("--add",          multiple=True, metavar="KEY=VALUE", help="Inject KEY=VALUE into expected snapshot")
@click.option("--weak",         multiple=True, metavar="KEY=VALUE", help="Inject weak KEY=VALUE into runtime (for entropy test)")
@click.option("--output",       type=click.Choice(["table", "json"]), default="table", show_default=True)
def simulate(config, delete, change, add, weak, output):
    \"\"\"Dry-run: inject synthetic drift into a snapshot and show how the tool responds.\"\"\"
    import secrets as _secrets
    from detector.diff.engine import compute_drift
    from detector.sources import _hash

    async def _run():
        agent = Agent.from_config(config)

        cfg = agent.config.agent
        snapshots = await asyncio.gather(
            *[src.fetch_with_retry(max_retries=1, delay=0.5) for src in agent.sources],
            return_exceptions=True,
        )

        expected: dict[str, str] = {}
        for snap in snapshots:
            if not isinstance(snap, Exception):
                expected.update(snap.secrets)

        actual_hashed:    dict[str, str] = dict(expected)
        actual_plaintext: dict[str, str] = {}

        for key in delete:
            actual_hashed.pop(key, None)
            console.print(f"  [dim]→ deleted '{key}' from runtime snapshot[/dim]")

        for key in change:
            actual_hashed[key] = _hash(_secrets.token_hex(16))
            console.print(f"  [dim]→ changed value of '{key}' in runtime snapshot[/dim]")

        for kv in add:
            if "=" in kv:
                k, v = kv.split("=", 1)
                expected[k] = _hash(v)
                console.print(f"  [dim]→ added '{k}' to expected snapshot[/dim]")

        for kv in weak:
            if "=" in kv:
                k, v = kv.split("=", 1)
                actual_hashed[k]    = _hash(v)
                actual_plaintext[k] = v
                console.print(f"  [dim]→ injected weak value for '{k}' into runtime[/dim]")

        console.print()

        report = compute_drift(
            expected,
            actual_hashed,
            sources=["[simulate]"],
            targets=["[simulate]"],
            actual_plaintext=actual_plaintext,
            enable_entropy=cfg.enable_entropy,
        )

        if output == "json":
            console.print_json(report.model_dump_json(indent=2))
        else:
            console.print("[bold yellow]⚡ SIMULATION — no data written to database[/bold yellow]\n")
            _render_table(report)

    asyncio.run(_run())


# ── verify (audit chain) ──────────────────────────────────────────────────────

@cli.command()
@click.option("--db", default="drift_history.db", show_default=True)
@click.option("--limit", default=100, show_default=True, type=int,
              help="Number of most recent runs to verify")
def verify(db, limit):
    \"\"\"Verify the tamper-evident audit hash chain for stored drift reports.\"\"\"
    hist = History(db_path=db)
    runs = hist.verify_chain(limit=limit)

    if not runs:
        console.print("[dim]No runs found.[/dim]")
        return

    tbl = Table(show_header=True, header_style="bold magenta", border_style="dim")
    tbl.add_column("ID",      style="dim", justify="right")
    tbl.add_column("TIMESTAMP")
    tbl.add_column("CHAIN",   justify="center")
    tbl.add_column("STORED HASH",   style="dim")
    tbl.add_column("EXPECTED HASH", style="dim")

    all_ok = True
    for entry in runs:
        ok = entry["chain_ok"]
        if not ok:
            all_ok = False
        status = "[green]✔ OK[/green]" if ok else "[bold red]✖ BROKEN[/bold red]"
        tbl.add_row(
            str(entry["id"]),
            entry["timestamp"][:19].replace("T", " "),
            status,
            (entry.get("stored_hash") or "—")[:16] + "…",
            (entry.get("expected_hash") or "—")[:16] + "…",
        )

    console.print(tbl)
    if all_ok:
        console.print(f"\n[bold green]✔ Chain intact across {len(runs)} run(s).[/bold green]\n")
    else:
        console.print(f"\n[bold red]✖ Chain violation detected — database may have been tampered with.[/bold red]\n")
        raise SystemExit(1)


# ── helpers ───────────────────────────────────────────────────────────────────

def _parse_since(value: str) -> datetime:
    now = datetime.now(timezone.utc)
    if value.endswith("h"):
        return now - timedelta(hours=int(value[:-1]))
    if value.endswith("d"):
        return now - timedelta(days=int(value[:-1]))
    try:
        return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError(f"Invalid ISO datetime format: {value}")


# ── scan (CI integration) ─────────────────────────────────────────────────────
@cli.command()
@click.option("--config", default="config/detector.toml")
@click.option("--ci", is_flag=True)
@click.option("--fail-on-drift", is_flag=True)
def scan(config, ci, fail_on_drift):
    \"\"\"Scan for drift (designed for CI/CD pipelines).\"\"\"
    import asyncio
    from detector.agent import Agent
    async def _run():
        agent = Agent.from_config(config)
        report = await agent.run_once()
        if (fail_on_drift or agent.config.agent.fail_on_drift) and report.has_drift:
            raise SystemExit(1)
    asyncio.run(_run())

if __name__ == "__main__":
    cli()