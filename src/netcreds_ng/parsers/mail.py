from __future__ import annotations
import logging
from base64 import b64decode
from typing import Optional, Dict, Any

from scapy.packet import Packet, Raw
from scapy.layers.inet import IP, TCP

from netcreds_ng.parsers.base_parser import BaseParser
from netcreds_ng import state
from netcreds_ng.utils.tcp_reassembly import frag_joiner

class MailParser(BaseParser):
    """Parses plaintext Mail protocols (POP3, IMAP, SMTP) for credentials."""

    MAIL_PORTS = {25, 110, 143, 587, 993, 995}

    @property
    def name(self) -> str:
        return "Mail"

    def can_handle(self, packet: Packet) -> bool:
        """Return True if the packet is on a common mail port."""
        if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
            return False
        
        return packet[TCP].dport in self.MAIL_PORTS or packet[TCP].sport in self.MAIL_PORTS

    def process(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """
        Processes a potential Mail packet for credentials using a stateful approach.
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

        full_load = frag_joiner(src_ip_port, ack, load_str).strip()
        lower_payload = full_load.lower()
        
        # --- State Trigger: Server initiates AUTH LOGIN ---
        # The server sends a Base64 prompt "VXNlcm5hbWU6" (Username:)
        # or the client sends the command "AUTH LOGIN"
        if "auth login" in lower_payload or "334 vxnlcm5hbwu6" in lower_payload:
            state.mail_auths[dst_ip_port] = [ack]
            state.clean_state_dict(state.mail_auths)
            logging.debug(f"Mail AUTH LOGIN initiated from {src_ip_port}. Setting state.")
            return None

        # --- State Action: Client provides username or password ---
        if src_ip_port in state.mail_auths:
            try:
                # The payload should be a simple Base64 string
                decoded_cred = b64decode(full_load).decode('utf-8')
                
                # If this is the first response, it's the username
                if len(state.mail_auths[src_ip_port]) == 1:
                    state.mail_auths[src_ip_port].append(ack) # Mark that user is found
                    return {
                        "protocol": self.name,
                        "source": src_ip_port,
                        "destination": dst_ip_port,
                        "type": "Username",
                        "credential": decoded_cred
                    }
                # If it's the second response, it's the password
                else:
                    del state.mail_auths[src_ip_port] # Conversation is over, clean up state
                    return {
                        "protocol": self.name,
                        "source": src_ip_port,
                        "destination": dst_ip_port,
                        "type": "Password",
                        "credential": decoded_cred
                    }
            except Exception:
                logging.debug(f"Could not decode mail credential from {src_ip_port}, cleaning state.")
                del state.mail_auths[src_ip_port]

        logging.debug(f"'{self.name}' parser processed packet but found no credentials.")        
        return None