from __future__ import annotations
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn
from rich.align import Align
from rich.padding import Padding

from netcreds_ng.analytics import AnalyticsTracker

class AnalyticsPanel:
    """A Rich Panel widget for displaying capture analytics."""

    def __init__(self, tracker: AnalyticsTracker, interface: str | None = None):
        self.tracker = tracker
        self.interface = interface

    def _build_risk_panel(self) -> Panel | None:
        grid = Table.grid(expand=True)
        grid.add_column(style="yellow")
        grid.add_column(style="white", justify="right")
        has_risks = False

        if self.tracker.cleartext_creds:
            has_risks = True
            total_cleartext = sum(self.tracker.cleartext_creds.values())
            grid.add_row("[bold]Cleartext Secrets[/bold]", f"{total_cleartext}")

        if self.tracker.weak_passwords_found:
            has_risks = True
            grid.add_row("[bold]Weak Passwords[/bold]", f"{self.tracker.weak_passwords_found}")

        if self.tracker.password_reuse:
            has_risks = True
            top_reused = self.tracker.password_reuse.most_common(1)[0] # type: ignore
            grid.add_row("[bold]Most Reused Pwd[/bold]", f"'{top_reused[0]}' ({top_reused[1]}x)")

        return Panel(grid, title="[bold red]Risks Identified[/bold red]", border_style="red") if has_risks else None

    def _build_host_tables(self) -> Table:
        container = Table.grid(expand=True, padding=(0, 1))
        
        clients = Table(header_style="bold yellow", border_style="yellow", expand=False)
        clients.add_column("Top Clients")
        clients.add_column("Items", justify="right")
        sorted_clients = sorted(self.tracker.host_profiles.values(), key=lambda h: h.creds_as_source, reverse=True)
        for host in sorted_clients[:4]:
            if host.creds_as_source > 0:
                clients.add_row(host.ip_address, str(host.creds_as_source))

        servers = Table(header_style="bold yellow", border_style="yellow", expand=False)
        servers.add_column("Top Servers")
        servers.add_column("Items", justify="right")
        sorted_servers = sorted(self.tracker.host_profiles.values(), key=lambda h: h.creds_as_dest, reverse=True)
        for host in sorted_servers[:4]:
            if host.creds_as_dest > 0:
                servers.add_row(host.ip_address, str(host.creds_as_dest))

        container.add_row(clients, servers)
        return container

    def get_renderable(self) -> Panel:
        master_grid = Table.grid(expand=True, padding=(0, 0))
        
        risk_panel = self._build_risk_panel()
        if risk_panel:
            master_grid.add_row(risk_panel)
            master_grid.add_row("")

        stats_table = Table.grid(expand=True)
        stats_table.add_column(style="bold cyan")
        stats_table.add_column(style="white")
        stats_table.add_row("Elapsed Time:", f"{self.tracker.elapsed_time:.2f}s")
        stats_table.add_row("Total Packets:", f"{self.tracker.total_packets}")
        stats_table.add_row("Interesting:", f"{self.tracker.interesting_packets}")
        stats_table.add_row("Secrets Found:", f"{self.tracker.creds_found}")
        stats_table.add_row("Unique Hosts:", f"{len(self.tracker.unique_hosts)}")
        master_grid.add_row(stats_table)
        master_grid.add_row("")

        if self.tracker.host_profiles:
            master_grid.add_row(self._build_host_tables())
            master_grid.add_row("")

        if self.tracker.is_pcap:
            progress = Progress(TextColumn("[cyan]{task.description}"), BarColumn(), TextColumn("[cyan]{task.percentage:>3.0f}%"), expand=True)
            progress.add_task("Progress", total=self.tracker.pcap_size, completed=self.tracker.bytes_processed)
            master_grid.add_row(Align.center(progress))
        else: # Live Capture
            self.tracker.update_pps()
            live_table = Table.grid(expand=True)
            live_table.add_column(style="bold cyan")
            live_table.add_column(style="white")
            live_table.add_row("Interface:", f"{self.interface}")
            live_table.add_row("Rate (PPS):", f"{self.tracker.packets_per_second:.2f}")
            master_grid.add_row(live_table)
            
        return Panel(Padding(master_grid, (0, 1)), title="[bold cyan]Analytics[/bold cyan]", border_style="cyan")