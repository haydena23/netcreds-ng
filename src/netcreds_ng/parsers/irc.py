from __future__ import annotations

import logging

from typing import Optional, Dict, Any

from scapy.packet import Packet, Raw
from scapy.layers.inet import IP, TCP

from netcreds_ng.parsers.base_parser import BaseParser

class IRCParser(BaseParser):
    """Parses IRC traffic for nicknames and passwords."""

    @property
    def name(self) -> str:
        return "IRC"

    def can_handle(self, packet: Packet) -> bool:
        """Return True if the packet is IRC traffic (TCP ports 6667, 6697)."""
        if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
            return False
        
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        return sport == 6667 or dport == 6667 or sport == 6697 or dport == 6697

    def process(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """
        Processes a potential IRC packet for credentials.
        """
        if not packet.haslayer(IP):
            return None

        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore').strip()
        except (UnicodeDecodeError, AttributeError):
            return None
        
        src_ip_port = f"{packet[IP].src}:{packet[TCP].sport}"
        dst_ip_port = f"{packet[IP].dst}:{packet[TCP].dport}"
        
        credential = None
        cred_type = None
        
        # Split by lines to handle multiple commands in one packet
        for line in payload.splitlines():
            upper_line = line.upper()
            if upper_line.startswith("NICK "):
                credential = line[5:]
                cred_type = "Nickname"
                break # Found a credential, stop searching
            elif upper_line.startswith("PASS "):
                credential = line[5:]
                cred_type = "Password"
                break # Found a credential, stop searching

        if credential and cred_type:
            return {
                "protocol": self.name,
                "source": src_ip_port,
                "destination": dst_ip_port,
                "type": cred_type,
                "credential": credential
            }

        logging.debug(f"'{self.name}' parser processed packet but found no credentials.")    
        return None