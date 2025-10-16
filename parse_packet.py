from __future__ import annotations

import logging
from typing import Optional, Dict
from collections import OrderedDict

from scapy.all import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.snmp import SNMP

from parsers.parse_kerberos import parse_kerberos
from parsers.parse_snmp import parse_snmp

# Global store for packet fragments
# Structure: { ip_port: { ack: payload_str } }
packet_frag_loads: Dict[str, OrderedDict[int, str]] = OrderedDict()

# Constants for limits
MAX_IP_PORTS = 50
MAX_ACKS_PER_IP = 25
MAX_LOAD_LENGTH = 5000
TRUNCATED_LENGTH = 200
MAX_PROCESS_LENGTH = 750

def frag_remover() -> None:
    """
    Trim packet_frag_loads to prevent unbounded growth:
      - Max 50 IP:port entries
      - Max 25 ACKs per IP:port
      - Max 5000 chars per fragment (keep first 500 + last 200)
    """
    # Trim oldest IP:port entries
    while len(packet_frag_loads) > MAX_IP_PORTS:
        oldest_key = next(iter(packet_frag_loads))
        logging.debug(f"Removing oldest IP:port entry: {oldest_key}")
        packet_frag_loads.popitem(last=False)  # type: ignore

    # Trim per-IP:port ACK entries and payload length
    for ip_port, ack_dict in list(packet_frag_loads.items()):
        # Limit ACKs per IP:port
        while len(ack_dict) > MAX_ACKS_PER_IP:
            oldest_ack = next(iter(ack_dict))
            logging.debug(f"Removing oldest ACK {oldest_ack} for IP:port {ip_port}")
            ack_dict.popitem(last=False)

        # Truncate long payloads safely
        for ack, payload in list(ack_dict.items()):
            if len(payload) > MAX_LOAD_LENGTH:
                truncated_payload = payload[:500] + payload[-TRUNCATED_LENGTH:]
                logging.debug(
                    f"Truncating payload for IP:port {ip_port} ACK {ack} "
                    f"from {len(payload)} to {len(truncated_payload)} chars "
                    f"(kept first 500 + last {TRUNCATED_LENGTH})"
                )
                ack_dict[ack] = truncated_payload

    logging.debug(f"Fragment store size after cleanup: {len(packet_frag_loads)} IP:port entries")
    for ip_port, ack_dict in packet_frag_loads.items():
        logging.debug(f"{ip_port}: {len(ack_dict)} ACK entries")

def frag_joiner(src_ip_port: str, ack: int, load: str) -> None:
    """
    Append new fragment to existing fragment buffer for a given IP:port and ACK.
    Creates the structures if they don't exist.
    """
    # Ensure the IP:port entry exists
    if src_ip_port not in packet_frag_loads:
        packet_frag_loads[src_ip_port] = OrderedDict()
        logging.debug(f"Created new fragment buffer for {src_ip_port}")

    ack_dict = packet_frag_loads[src_ip_port]

    if ack in ack_dict:
        old_len = len(ack_dict[ack])
        ack_dict[ack] += load
        logging.debug(
            f"Appended {len(load)} bytes to existing fragment for {src_ip_port} ACK {ack}. "
            f"New length: {len(ack_dict[ack])} (was {old_len})"
        )
    else:
        ack_dict[ack] = load
        logging.debug(
            f"Added new fragment for {src_ip_port} ACK {ack}, length {len(load)}"
        )

    total_fragments = len(ack_dict)
    total_bytes = sum(len(p) for p in ack_dict.values())
    logging.debug(
        f"Current state for {src_ip_port}: {total_fragments} fragments, "
        f"{total_bytes} total bytes"
    )

    # Trim fragments to enforce limits
    frag_remover()

def parse_packet(packet: Ether) -> None:
    """Parse a network packet."""
    load: Optional[bytes] = None
    logging.debug("-" * 25 + " New Packet Captured " + "-" * 25)

    # Extract raw payload if present
    if packet.haslayer(Raw):
        load = packet[Raw].load

    logging.debug(f"Parsing packet: {packet.summary()}")
    if load:
        logging.debug(f"Raw payload data (hex, first 128 bytes): {load.hex()[:128]}")

    # Discard Ethernet packets with just a raw load. These are usually network
    # controls like flow control
    if (packet.haslayer(Ether)
            and packet.haslayer(Raw)
            and not packet.haslayer(IP)
            and not packet.haslayer(IPv6)):
        logging.debug("Discarding non-IP Ethernet packet with raw load.")
        return

    # UDP
    if packet.haslayer(UDP) and packet.haslayer(IP):
        src_ip_port = f"{packet[IP].src}:{packet[UDP].sport}"
        dst_ip_port = f"{packet[IP].dst}:{packet[UDP].dport}"
        logging.debug(f"Processing UDP packet from {src_ip_port} to {dst_ip_port}")

        # SNMP Community Strings
        if packet.haslayer(SNMP):
            logging.debug(f"SNMP layer found in UDP packet. Passing to SNMP parser.")
            parse_snmp(src_ip_port, dst_ip_port, packet[SNMP])
            return

        if packet[UDP].dport == 88 or packet[UDP].sport == 88:
            logging.debug(f"Potential Kerberos traffic detected on port 88/UDP.")
            kerb_data = bytes(packet[UDP].payload)
            if kerb_data:
                logging.debug(f"UDP payload with length {len(kerb_data)} bytes found. Passing to Kerberos parser.")
                parse_kerberos(src_ip_port, dst_ip_port, kerb_data)
            else:
                logging.debug("Kerberos packet detected, but no UDP payload found.")
            return
    
    # TCP
    elif packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):
            ack = int(packet[TCP].ack)
            src_ip_port = f"{packet[IP].src}:{packet[TCP].sport}"
            dst_ip_port = f"{packet[IP].dst}:{packet[TCP].dport}"

            if load:
                load_str = load.decode()
                frag_joiner(src_ip_port, ack, load_str)
                full_load = packet_frag_loads[src_ip_port][ack]

                logging.debug(f"TCP packet from {src_ip_port} to {dst_ip_port} "
                            f"ACK {ack}, fragment length {len(load_str)}, "
                            f"full reassembled length {len(full_load)}")

                if 0 < len(full_load) < MAX_PROCESS_LENGTH:
                    logging.debug(f"Processing TCP payload of length {len(full_load)}")
                    return
                    # FTP parser

                    # Mail parser

                    # IRC parser

                    # Telnet parser
            
                # HTTP and other protocols that run on TCP + raw load
                logging.debug(f"Processing TCP payload of length {len(full_load)} using alternative parser")
                return
    else:
        logging.debug("Packet did not match any parsing criteria.")
        return