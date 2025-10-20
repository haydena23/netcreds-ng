from __future__ import annotations
import logging

from scapy.layers.snmp import SNMP

SNMP_VERSION_MAP = {0: "v1", 1: "v2c", 2: "v2", 3: "v3"}

def parse_snmp(src_ip_port: str, dst_ip_port: str, snmp_packet: SNMP) -> None:
    """Parses SNMP packets to extract the Community String"""
    version = snmp_packet.version.val
    community_bytes = snmp_packet.community.val

    if version == 3:
        logging.debug("SNMPv3 packet received: no community string.")
        return
    
    try:
        community_string = community_bytes.decode("ascii")
    except(AttributeError, UnicodeDecodeError):
        community_string = str(community_bytes)
        
    version_string = SNMP_VERSION_MAP.get(version, f"Unknown({version})")
    logging.info(f"SNMP{version_string} packet from {src_ip_port} to {dst_ip_port}: Community String = '{community_string}'")
    return