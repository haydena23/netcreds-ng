from __future__ import annotations
import time
from queue import Queue, Empty
from typing import Optional

from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel

from netcreds_ng.tui.widgets.credentials_table import CredentialsTable
from netcreds_ng.tui.widgets.analytics_panel import AnalyticsPanel
from netcreds_ng.analytics import AnalyticsTracker

def create_layout(is_verbose: bool) -> Layout:
    """Defines the TUI layout, conditionally including the analytics panel."""
    layout = Layout(name="root")
    layout.split(
        Layout(name="header", size=3),
        Layout(name="main", ratio=1),
    )
    
    if is_verbose:
        layout["main"].split_row(
            Layout(name="side", size=30),
            Layout(name="body")
        )
    else:
        layout["main"].split(Layout(name="body"))
        
    return layout

def run_dashboard(data_queue: Queue, is_verbose: bool, tracker: AnalyticsTracker, interface: Optional[str]): # type: ignore
    """Manages the live TUI dashboard, conditionally showing extra panels."""
    layout = create_layout(is_verbose)
    cred_table = CredentialsTable()
    
    header_text = "[bold green]netcreds-ng[/bold green] - Captured Credentials"
    if not is_verbose:
        header_text += " (run with -v to see analytics)"
        
    layout["header"].update(Panel(header_text, border_style="green"))
    layout["body"].update(cred_table.get_renderable())

    analytics_panel = None
    if is_verbose:
        analytics_panel = AnalyticsPanel(tracker, interface)
        layout["side"].update(analytics_panel.get_renderable())
    
    with Live(layout, screen=True, redirect_stderr=False, refresh_per_second=10) as live: # type: ignore
        try:
            while True:
                updated = False
                try:
                    credential_data = data_queue.get_nowait() # type: ignore
                    cred_table.add_credential(credential_data) # type: ignore
                    layout["body"].update(cred_table.get_renderable())
                    updated = True
                except Empty:
                    pass

                if is_verbose and analytics_panel:
                    layout["side"].update(analytics_panel.get_renderable())
                    updated = True
                
                if not updated:
                    time.sleep(0.05)

        except KeyboardInterrupt:
            pass