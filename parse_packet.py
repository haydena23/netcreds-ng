from __future__ import annotations

import logging
from typing import Optional
from collections import OrderedDict

from scapy.all import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.snmp import SNMP

from parsers.parse_kerberos import parse_kerberos
from parsers.parse_snmp import parse_snmp

# --- Global Fragment Store & Constants ---
packet_frag_loads: OrderedDict[str, OrderedDict[int, str]] = OrderedDict()
MAX_IP_PORTS = 50
MAX_ACKS_PER_IP = 25
MAX_LOAD_LENGTH = 7500
TRUNCATED_LENGTH = 200
MAX_PROCESS_LENGTH = 1500

def frag_remover() -> None:
    """
    Trims the global fragment store to prevent unbounded growth.
    """
    while len(packet_frag_loads) > MAX_IP_PORTS:
        oldest_key = next(iter(packet_frag_loads))
        logging.debug(f"Fragment store full. Removing oldest IP:port entry: {oldest_key}")
        packet_frag_loads.popitem(last=False)

    for ip_port, ack_dict in list(packet_frag_loads.items()):
        while len(ack_dict) > MAX_ACKS_PER_IP:
            oldest_ack = next(iter(ack_dict))
            logging.debug(f"Max ACKs for {ip_port}. Removing oldest ACK: {oldest_ack}")
            ack_dict.popitem(last=False)

        for ack, payload in list(ack_dict.items()):
            if len(payload) > MAX_LOAD_LENGTH:
                ack_dict[ack] = payload[-TRUNCATED_LENGTH:]
                logging.debug(f"Payload for {ip_port} ACK {ack} truncated to last {TRUNCATED_LENGTH} chars.")

def frag_joiner(src_ip_port: str, ack: int, load: str) -> str:
    """
    Appends a new fragment to the buffer and returns the fully reassembled payload.
    """
    if src_ip_port not in packet_frag_loads:
        packet_frag_loads[src_ip_port] = OrderedDict()
        logging.debug(f"Created new fragment buffer for {src_ip_port}")
    
    ack_dict = packet_frag_loads[src_ip_port]
    
    if ack in ack_dict:
        old_len = len(ack_dict[ack])
        ack_dict[ack] += load
        logging.debug(f"Appended {len(load)} bytes to existing fragment for {src_ip_port} ACK {ack}. New length: {len(ack_dict[ack])} (was {old_len})")
    else:
        ack_dict[ack] = load
        logging.debug(f"Added new fragment for {src_ip_port} ACK {ack}, length {len(load)}")
        
    frag_remover()
    return ack_dict[ack]

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
        src_ip_port = f"{packet[IP].src}:{packet[TCP].sport}"
        dst_ip_port = f"{packet[IP].dst}:{packet[TCP].dport}"
        ack, seq, dport = packet[TCP].ack, packet[TCP].seq, packet[TCP].dport
            
        try:
            load_str = load.decode('utf-8', errors='ignore') # type: ignore
        except (UnicodeDecodeError, AttributeError):
            logging.debug(f"Could not decode TCP payload from {src_ip_port}.")
            return
        
        full_load = frag_joiner(src_ip_port, ack, load_str)
        logging.debug(f"TCP from {src_ip_port} ACK:{ack} SEQ:{seq}. Reassembled payload length: {len(full_load)}")

        # Protocol Dispatcher
        dispatched = False

        if dport in {80, 8080, 8000}:
            logging.debug(f"Passing payload to HTTP parser for port {dport}.")
            # parse_http(full_load, src_ip_port, dst_ip_port, ack, seq)
            dispatched = True

        elif 0 < len(full_load) < MAX_PROCESS_LENGTH:
            if dport == 21:
                logging.debug("Passing payload to FTP parser.")
                # parse_ftp(full_load, src_ip_port, dst_ip_port)
                dispatched = True
            elif dport == 23:
                logging.debug("Passing payload to Telnet parser.")
                # parse_telnet(full_load, src_ip_port, dst_ip_port)
                dispatched = True
            elif dport in {25, 110, 143, 587, 993, 995}:
                logging.debug(f"Passing payload to Mail parser for port {dport}")
                # parse_mail(full_load, src_ip_port, dst_ip_port, ack, seq)
                dispatched = True
            elif dport in {6667, 6697}:
                logging.debug(f"Passing payload to IRC parser.")
                # parse_irc(full_load, src_ip_port, dst_ip_port)
                dispatched = True

        # Standalone NTLM (non-HTTP) Fallback Detection
        if b'NTLMSSP\x00' in load: # type: ignore
            logging.debug("NTLMSSP signature detected in raw TCP stream.")
            if b'NTLMSSP\x00\x02\x00\x00\x00' in load: # type: ignore
                # parse_ntlm_challenge_from_raw(load, seq, src_ip_port)
                dispatched = True
            elif b'NTLMSSP\x00\x03\x00\x00\x00' in load: # type: ignore
                # parse_ntlm_response_from_raw(load, seq, src_ip_port)
                dispatched = True

        if not dispatched:
            logging.debug("Payload did not match any specific TCP parsing criteria.")
            
        # HTTP and other protocols that run on TCP + raw load
        logging.debug(f"Processing TCP payload of length {len(full_load)} using alternative parser")
    else:
        logging.debug("Packet did not match any UDP or TCP parsing criteria.")