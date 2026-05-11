import click
import asyncio
from rich.console import Console
from rich.table import Table
from detector.agent import Agent
from detector.diff.models import DriftReport

console = Console()

def render_table(report: DriftReport):
    if not report.has_drift:
        console.print("[green]No drift detected. Runtime matches expected secrets.[/green]")
        return

    console.print(f"\n[bold red]Status: DRIFT DETECTED ({len(report.items)} items)[/bold red]")
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("KEY", style="cyan")
    table.add_column("KIND")
    table.add_column("SEVERITY")
    table.add_column("DETAIL")

    for item in report.items:
        sev_color = "red" if item.severity.value in ['critical', 'high'] else "yellow"
        table.add_row(
            item.key,
            item.kind.value,
            f"[{sev_color}]{item.severity.value.upper()}[/{sev_color}]",
            item.detail
        )

    console.print(table)
    print("\n")

@click.group()
def cli():
    pass

@cli.command()
@click.option('--config', default='config/detector.toml', help='Path to config file')
@click.option('--output', type=click.Choice(['table', 'json']), default='table')
def check(config, output):
    '''One-shot drift check'''
    async def run():
        agent = Agent.from_config(config)
        report = await agent.run_once()
        
        if output == 'table':
            render_table(report)
        else:
            console.print(report.model_dump_json(indent=2))
            
        if agent.config.agent.fail_on_drift and report.has_drift:
            raise SystemExit(1)
            
    asyncio.run(run())

@cli.command()
@click.option('--config', default='config/detector.toml', help='Path to config file')
@click.option('--interval', type=int, help='Seconds between checks')
def watch(config, interval):
    '''Continuous daemon mode'''
    async def run():
        agent = Agent.from_config(config)
        active_interval = interval or agent.config.agent.interval_seconds
        console.print(f"Starting watch mode. Polling every {active_interval}s...")
        await agent.run_loop(override_interval=active_interval)
        
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        console.print("\nShutting down watch mode.")

if __name__ == '__main__':
    cli()
