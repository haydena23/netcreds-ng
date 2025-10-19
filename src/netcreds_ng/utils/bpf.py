from __future__ import annotations
from typing import List, Optional

def build_filter(ips: List[str]) -> Optional[str]:
    """Build a BPF filter string to exclude specified IPs."""
    if not ips:
        return None
    return "not (" + " or ".join(f"host {ip}" for ip in ips) + ")"