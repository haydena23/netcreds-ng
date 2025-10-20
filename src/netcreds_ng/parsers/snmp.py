from __future__ import annotations
import logging
from typing import Optional, Dict, Any

from scapy.packet import Packet
from scapy.layers.inet import IP, UDP
from scapy.layers.snmp import SNMP

from netcreds_ng.parsers.base_parser import BaseParser

SNMP_VERSION_MAP = {0: "v1", 1: "v2c", 2: "v2", 3: "v3"}

class SNMPParser(BaseParser):
    """Parses SNMP packets to extract the Community String."""

    @property
    def name(self) -> str:
        return "SNMP"

    def can_handle(self, packet: Packet) -> bool:
        """Return True if the packet is an SNMP packet."""
        return bool(packet.haslayer(SNMP))

    def process(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """
        Processes an SNMP packet and extracts the community string.
        
        Returns a dictionary with credential data if found, otherwise None.
        """
        if not (packet.haslayer(IP) and packet.haslayer(UDP)):
            return None

        snmp_layer = packet[SNMP]
        version = snmp_layer.version.val

        if version == 3:
            logging.debug("SNMPv3 packet received: no community string to capture.")
            return None

        community_bytes = snmp_layer.community.val
        try:
            community_string = community_bytes.decode("ascii")
        except (AttributeError, UnicodeDecodeError):
            community_string = str(community_bytes)
        
        version_string = SNMP_VERSION_MAP.get(version, f"Unknown({version})")
        src_ip_port = f"{packet[IP].src}:{packet[UDP].sport}"
        dst_ip_port = f"{packet[IP].dst}:{packet[UDP].dport}"

        return {
            "protocol": self.name,
            "source": src_ip_port,
            "destination": dst_ip_port,
            "type": "Community String",
            "version": version_string,
            "credential": f"'{community_string}'"
        }