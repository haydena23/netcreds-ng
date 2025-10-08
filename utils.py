from __future__ import annotations

import platform
from subprocess import Popen, PIPE, DEVNULL
from typing import Optional, List

def interface_finder() -> Optional[str]:
    """Search for a valid interface, depending on the OS."""
    os_type = platform.system()
    if os_type == "Linux":
        try:
            ip_route = Popen(['/sbin/ip', 'route'], stdout=PIPE, stderr=DEVNULL)
            for line in ip_route.communicate()[0].splitlines():
                if b"default" in line:
                    interface = line.split()[4]
                    return interface.decode("utf-8")
        except FileNotFoundError:
            return None
    return None

def bfp_filter(ips: List[str]) -> Optional[str]:
    """Build a BPF filter string to exclude specified IPs."""
    if not ips:
        return None
    # Corrected BPF filter syntax
    return "not (" + " or ".join(f"host {ip}" for ip in ips) + ")"