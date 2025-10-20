from __future__ import annotations
from collections import deque
from rich.table import Table
from rich.text import Text

class CredentialsTable:
    """
    A Rich Table widget for displaying a sliding window of captured credentials.
    """

    def __init__(self, max_rows: int = 100):
        self._display_rows = deque(maxlen=max_rows) # type: ignore
        self.total_credentials_found = 0

    def add_credential(self, data: dict) -> None: # type: ignore
        """Adds a new credential. It will be stored and added to the display buffer."""
        self.total_credentials_found += 1
        
        protocol = str(data.get("protocol", "-")) # type: ignore
        source = str(data.get("source", "-")) # type: ignore
        destination = str(data.get("destination", "-")) # type: ignore
        cred_type = str(data.get("type", "-")) # type: ignore
        credential = str(data.get("credential", "-")) # type: ignore

        if len(credential) > 100:
            credential = credential[:97] + "..."
            
        self._display_rows.append( # type: ignore
            (
                protocol,
                source,
                destination,
                Text(cred_type, style="yellow"),
                Text(credential, style="green")
            )
        )

    def get_renderable(self) -> Table:
        """Builds and returns the Rich Table object to be rendered."""
        
        table_title = f"Captured Credentials (Displaying last {len(self._display_rows)} of {self.total_credentials_found} total)" # type: ignore
        
        table = Table(
            title=table_title,
            expand=True,
            header_style="bold magenta",
            border_style="cyan"
        )
        table.add_column("Protocol", style="cyan", no_wrap=True)
        table.add_column("Source", style="white")
        table.add_column("Destination", style="white")
        table.add_column("Type", style="yellow")
        table.add_column("Credential", style="green")

        for row in self._display_rows: # type: ignore
            table.add_row(*row) # type: ignore
            
        return table