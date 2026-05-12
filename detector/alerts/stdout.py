from rich.console import Console
from rich.table import Table
from detector.alerts import BaseAlerter
from detector.diff.models import DriftReport, Severity

console = Console()

_SEV_ICON = {
    "critical": "🔴",
    "high":     "🟠",
    "warn":     "🟡",
    "info":     "⚪",
}

_SEV_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "warn":     "yellow",
    "info":     "dim",
}


class StdoutAlerter(BaseAlerter):
    async def send_alert(self, report: DriftReport) -> None:
        items = self._filter_items(report)
        if not items:
            return

        # ── Header ────────────────────────────────────────────────────
        ts = report.checked_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        console.rule(f"[bold red]Secret Drift Detected — {ts}[/bold red]")

        console.print(f"  Sources : [cyan]{', '.join(report.sources) or '—'}[/cyan]")
        console.print(f"  Targets : [cyan]{', '.join(report.targets) or '—'}[/cyan]")
        if report.run_id:
            console.print(f"  Run ID  : [dim]{report.run_id}[/dim]")
        console.print()

        # ── Per-severity counts ───────────────────────────────────────
        counts: dict[str, int] = {}
        for item in items:
            counts[item.severity.value] = counts.get(item.severity.value, 0) + 1

        summary_parts = []
        for sev in ("critical", "high", "warn", "info"):
            n = counts.get(sev, 0)
            if n:
                icon  = _SEV_ICON[sev]
                color = _SEV_COLOR[sev]
                summary_parts.append(f"{icon} [{color}]{n} {sev}[/{color}]")
        console.print("  " + "   ".join(summary_parts) + "\n")

        # ── Item table ────────────────────────────────────────────────
        tbl = Table(show_header=True, header_style="bold magenta", border_style="dim")
        tbl.add_column("KEY",      style="cyan", no_wrap=True)
        tbl.add_column("KIND",     style="white")
        tbl.add_column("SEVERITY", no_wrap=True)
        tbl.add_column("DETAIL",   style="dim")

        for item in sorted(items, key=lambda i: -i.severity.rank):
            icon  = _SEV_ICON.get(item.severity.value, "⚪")
            color = _SEV_COLOR.get(item.severity.value, "white")
            tbl.add_row(
                item.key,
                item.kind.value,
                f"{icon} [{color}]{item.severity.value.upper()}[/{color}]",
                item.detail,
            )
        console.print(tbl)

        # ── Remediation hints ─────────────────────────────────────────
        critical_items = [i for i in items if i.severity == Severity.CRITICAL]
        if critical_items:
            console.print("\n[bold red]Remediation (CRITICAL)[/bold red]")
            for item in critical_items:
                if item.remediation_hint:
                    console.print(f"  [dim]→[/dim] {item.remediation_hint}")

        console.rule(style="dim")
        console.print()
