from __future__ import annotations
import logging
from base64 import b64decode
from urllib.parse import unquote_plus
from typing import Optional, Dict, Any

from scapy.packet import Packet, Raw
from scapy.layers.inet import IP, TCP

from netcreds_ng.parsers.base_parser import BaseParser
from netcreds_ng.utils.tcp_reassembly import frag_joiner

class HTTPParser(BaseParser):
    """Parses HTTP traffic for Basic Auth and common form submissions."""

    @property
    def name(self) -> str:
        return "HTTP"

    def can_handle(self, packet: Packet) -> bool:
        """Return True if the packet is HTTP traffic (common web ports)."""
        if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
            return False
        
        dport = packet[TCP].dport
        return dport in {80, 8080, 8000}

    def process(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """
        Processes a potential HTTP packet for credentials.
        """
        if not packet.haslayer(IP):
            return None
            
        src_ip_port = f"{packet[IP].src}:{packet[TCP].sport}"
        dst_ip_port = f"{packet[IP].dst}:{packet[TCP].dport}"
        ack = packet[TCP].ack
        
        try:
            load_str = packet[Raw].load.decode('utf-8', errors='ignore')
        except (UnicodeDecodeError, AttributeError):
            return None

        # Reassemble the TCP stream to get the full payload
        full_load = frag_joiner(src_ip_port, ack, load_str)
        
        # --- Basic Authentication ---
        lower_payload = full_load.lower()
        if "authorization: basic " in lower_payload:
            try:
                # To get the original case, split the original payload
                auth_header = full_load.split("Authorization: Basic ")[1].split("\r\n")[0]
                decoded_auth = b64decode(auth_header).decode('utf-8')
                return {
                    "protocol": self.name,
                    "source": src_ip_port,
                    "destination": dst_ip_port,
                    "type": "Basic Auth",
                    "credential": decoded_auth
                }
            except Exception as e:
                logging.debug(f"Could not decode HTTP Basic Auth from {src_ip_port}: {e}")

        # --- Common Form Submissions ---
        if 'application/x-www-form-urlencoded' in lower_payload and ('pass' in lower_payload and 'user' in lower_payload):
            try:
                # The body is after the double CRLF
                body = full_load.split('\r\n\r\n')[-1]
                # URL Decode the form data for readability
                creds = unquote_plus(body)
                return {
                    "protocol": self.name,
                    "source": src_ip_port,
                    "destination": dst_ip_port,
                    "type": "Form Submission",
                    "credential": creds
                }
            except Exception as e:
                logging.debug(f"Could not parse potential HTTP form from {src_ip_port}: {e}")
        
        logging.debug(f"'{self.name}' parser processed packet but found no credentials.")
        return None