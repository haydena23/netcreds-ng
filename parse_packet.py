from __future__ import annotations

import logging
from typing import Optional, ByteString

from scapy.all import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.snmp import SNMP

def parse_snmp(src_ip_port: str, dst_ip_port: str, snmp_packet: SNMP) -> None:
    """Parses SNMP packets."""
    # Placeholder for SNMP parsing logic
    logging.info(f"SNMP packet from {src_ip_port} to {dst_ip_port}")


def parse_packet(packet: Ether) -> None:
    """Parse a network packet."""
    load: Optional[ByteString] = None
    if packet.haslayer(Raw):
        load = packet[Raw].load

    if (packet.haslayer(Ether)
            and packet.haslayer(Raw)
            and not packet.haslayer(IP)
            and not packet.haslayer(IPv6)):
        return

    if packet.haslayer(UDP) and packet.haslayer(IP):
        src_ip_port: str = str(packet[IP].src) + ":" + str(packet[UDP].sport)
        dst_ip_port: str = str(packet[IP].dst) + ':' + str(packet[UDP].dport)

        if packet.haslayer(SNMP):
            parse_snmp(src_ip_port, dst_ip_port, packet[SNMP])
            return

    logging.debug(load)