from __future__ import annotations
from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich.padding import Padding

from netcreds_ng.analytics import AnalyticsTracker

def _build_analytics_summary(tracker: AnalyticsTracker, console: Console):
    """Builds and prints a multi-panel summary of the analysis."""
    
    console.print("\n" + "="*30 + " Analysis Summary " + "="*30, justify="center", style="bold cyan")

    # --- Risk Panel ---
    risk_grid = Table.grid(expand=True)
    risk_grid.add_column(style="yellow")
    risk_grid.add_column(style="white", justify="right")
    has_risks = False
    if tracker.cleartext_creds:
        has_risks = True
        risk_grid.add_row("[bold]Cleartext Credentials[/bold]", str(sum(tracker.cleartext_creds.values())))
    if tracker.weak_passwords_found:
        has_risks = True
        risk_grid.add_row("[bold]Weak Passwords Found[/bold]", str(tracker.weak_passwords_found))
    if tracker.password_reuse:
        has_risks = True
        top_reused = tracker.password_reuse.most_common(1)[0] # type: ignore
        risk_grid.add_row("[bold]Most Reused Pass[/bold]", f"'{top_reused[0]}' ({top_reused[1]}x)")
    
    if has_risks:
        console.print(Panel(Padding(risk_grid, 1), title="[bold red]Risks Identified[/bold red]", border_style="red"))

    # --- Combined Layout for Stats & Hosts ---
    layout = Table.grid(expand=True)
    layout.add_column(width=40)
    layout.add_column()
    
    # --- General Stats Panel ---
    stats_table = Table.grid(expand=True)
    stats_table.add_column(style="bold cyan")
    stats_table.add_column(style="white")
    stats_table.add_row("Elapsed Time:", f"{tracker.elapsed_time:.2f}s")
    stats_table.add_row("Total Packets:", f"{tracker.total_packets}")
    stats_table.add_row("Interesting:", f"{tracker.interesting_packets}")
    stats_table.add_row("Credentials:", f"{tracker.creds_found}")
    stats_table.add_row("Unique Hosts:", f"{len(tracker.unique_hosts)}")
    stats_panel = Panel(Padding(stats_table, 1), title="[bold cyan]General Stats[/bold cyan]", border_style="cyan")

    # --- Top Involved Hosts Panel (Unified) ---
    top_hosts_table = Table(header_style="bold yellow", show_header=True)
    top_hosts_table.add_column("IP Address")
    top_hosts_table.add_column("Total Creds", justify="right")
    
    # Calculate total involvement (source + dest) for each host
    sorted_hosts = sorted(
        tracker.host_profiles.values(),
        key=lambda h: h.creds_as_source + h.creds_as_dest,
        reverse=True
    )
    
    for host in sorted_hosts[:7]:
        total_creds = host.creds_as_source + host.creds_as_dest
        if total_creds > 0:
            top_hosts_table.add_row(host.ip_address, str(total_creds))
            
    top_hosts_panel = Panel(top_hosts_table, title="[bold yellow]Top Involved Hosts[/bold yellow]", border_style="yellow")

    layout.add_row(stats_panel, top_hosts_panel)
    console.print(layout)


def display_results_table(results: List[Dict[str, Any]], tracker: AnalyticsTracker):
    """
    Displays a final, static table of captured credentials and an analytics summary.
    """
    console = Console()
    
    if not results:
        console.print(f"\n[bold yellow]Analysis complete in {tracker.elapsed_time:.2f}s. No credentials found.[/bold yellow]")
    else:
        creds_table = Table(
            title=f"\nAnalysis Complete: Found {tracker.creds_found} Credentials in {tracker.elapsed_time:.2f}s",
            header_style="bold magenta",
            border_style="cyan",
            show_lines=True
        )
        creds_table.add_column("Protocol", style="cyan", no_wrap=True)
        creds_table.add_column("Source", style="white")
        creds_table.add_column("Destination", style="white")
        creds_table.add_column("Type", style="yellow")
        creds_table.add_column("Credential", style="green")

        for cred in results:
            credential_text = str(cred.get("credential", "-"))
            if len(credential_text) > 100:
                credential_text = credential_text[:97] + "..."
            
            creds_table.add_row(
                str(cred.get("protocol", "-")),
                str(cred.get("source", "-")),
                str(cred.get("destination", "-")),
                Text(str(cred.get("type", "-")), style="yellow"),
                Text(credential_text, style="green"),
            )
        
        console.print(creds_table)

    _build_analytics_summary(tracker, console)