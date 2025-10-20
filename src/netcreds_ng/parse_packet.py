from __future__ import annotations

import logging
from typing import Optional

from scapy.all import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.snmp import SNMP

from netcreds_ng.parsers.parse_kerberos import parse_kerberos
from netcreds_ng.parsers.parse_snmp import parse_snmp

import netcreds_ng.utils.tcp_reassembly as tcp_reassembly

MAX_PROCESS_LENGTH = 1500

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
        
        full_load = tcp_reassembly.frag_joiner(src_ip_port, ack, load_str)
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