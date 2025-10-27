from __future__ import annotations
import logging
import re
from base64 import b64decode
from urllib.parse import unquote_plus
from typing import Optional, Dict, Any, List

from scapy.packet import Packet, Raw
from scapy.layers.inet import IP, TCP

from netcreds_ng.parsers.base_parser import BaseParser
from netcreds_ng.utils.tcp_reassembly import frag_joiner

class HTTPParser(BaseParser):
    """Parses HTTP traffic for Basic Auth, form submissions, JWT/API keys, and session cookies."""

    JWT_REGEX = re.compile(r'ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*')

    @property
    def name(self) -> str:
        return "HTTP"

    def can_handle(self, packet: Packet) -> bool:
        """Return True if the packet is HTTP traffic (common web ports)."""
        if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
            return False
        
        dport = packet[TCP].dport
        return dport in {80, 8080, 8000}
    
    def _extract_credentials(self, full_load: str, src_ip_port: str, dst_ip_port: str) -> List[Dict[str, Any]]:
        """
        Internal method to orchestrate extraction of all cred types from HTTP payload.
        Returns list of found creds.
        """
        found_credentials: List[Dict[str, Any]] = []
        lines = full_load.splitlines()

        for line in lines:
            lower_line = line.lower()
            
            # Basic Authentication
            if lower_line.startswith("authorization: basic "):
                try:
                    auth_header = line.split(" ")[-1]
                    decoded_auth = b64decode(auth_header).decode('utf-8')
                    found_credentials.append({
                        "protocol": self.name, "source": src_ip_port, "destination": dst_ip_port,
                        "type": "Basic Auth", "credential": decoded_auth
                    })
                except Exception as e:
                    logging.debug(f"Could not decode HTTP Basic Auth from {src_ip_port}: {e}")
            
            # Bearer Tokens (JWT or API Keys)
            elif lower_line.startswith("authorization: bearer "):
                token = line.split(" ", 2)[-1]
                found_credentials.append({
                        "protocol": self.name, "source": src_ip_port, "destination": dst_ip_port,
                        "type": "Bearer Token", "credential": token
                    })
            
            # API Key Headers
            elif lower_line.startswith("x-api-key: "):
                api_key = line.split(" ", 1)[-1]
                found_credentials.append({
                    "protocol": self.name, "source": src_ip_port, "destination": dst_ip_port,
                    "type": "API Key", "credential": api_key
                })

            # Session Cookies
            elif lower_line.startswith("cookie: "):
                cookies = line.split(" ", 1)[-1]
                found_credentials.append({
                    "protocol": self.name, "source": src_ip_port, "destination": dst_ip_port,
                    "type": "Session Cookie", "credential": cookies
                })
        
        body = full_load.split('\r\n\r\n', 1)[-1]

         # Common Form Submissions
        if 'application/x-www-form-urlencoded' in full_load.lower() and ('pass' in body.lower() and 'user' in body.lower()):
            try:
                creds = unquote_plus(body)
                found_credentials.append({
                    "protocol": self.name, "source": src_ip_port, "destination": dst_ip_port,
                    "type": "Form Submission", "credential": creds
                })
            except Exception as e:
                logging.debug(f"Could not parse potential HTTP form from {src_ip_port}: {e}")

        # JWT anywhere in body
        jwt_matches = self.JWT_REGEX.findall(body)
        for jwt in jwt_matches:
            found_credentials.append({
                "protocol": self.name, "source": src_ip_port, "destination": dst_ip_port,
                "type": "JWT", "credential": jwt
            })
            
        return found_credentials

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
        
        all_creds = self._extract_credentials(full_load, src_ip_port, dst_ip_port)

        if all_creds:
            return all_creds[0]
        
        logging.debug(f"'{self.name}' parser processed packet but found no credentials.")
        return None