from __future__ import annotations
import logging
from typing import Optional, Dict, Any

from scapy.packet import Packet, Raw
from scapy.layers.inet import IP, TCP

from netcreds_ng.parsers.base_parser import BaseParser
from netcreds_ng import state

class TelnetParser(BaseParser):
    """Parses Telnet traffic for usernames and passwords using state."""

    @property
    def name(self) -> str:
        return "Telnet"

    def can_handle(self, packet: Packet) -> bool:
        """Return True if the packet is Telnet traffic (TCP port 23 or 2323)."""
        return packet.haslayer(TCP) and packet.haslayer(Raw) and (packet[TCP].dport == 23 or packet[TCP].sport == 23 or packet[TCP].dport == 2323 or packet[TCP].sport == 2323) # type: ignore

    def process(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """
        Processes a Telnet packet, either capturing a credential or setting state.
        """
        if not packet.haslayer(IP):
            return None

        src_ip_port = f"{packet[IP].src}:{packet[TCP].sport}"
        dst_ip_port = f"{packet[IP].dst}:{packet[TCP].dport}"

        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
        except (UnicodeDecodeError, AttributeError):
            return None

        # Case 1: Expecting a credential from this source
        if src_ip_port in state.telnet_prompts:
            prompt_type = state.telnet_prompts.pop(src_ip_port)
            credential = payload.strip().replace('\r', '').replace('\n', '')
            if credential:
                return {
                    "protocol": self.name,
                    "source": src_ip_port,
                    "destination": dst_ip_port,
                    "type": prompt_type.capitalize(),
                    "credential": credential
                }
            return None

        # Case 2: The server is prompting for a credential
        lower_payload = payload.lower().strip()
        prompt_to_set = None
        if lower_payload.endswith(('login:', 'username:')):
            prompt_to_set = "username"
        elif lower_payload.endswith('password:'):
            prompt_to_set = "password"

        if prompt_to_set:
            logging.debug(f"Telnet {prompt_to_set} prompt detected from {src_ip_port}. Setting state for {dst_ip_port}.")
            state.telnet_prompts[dst_ip_port] = prompt_to_set
            state.clean_state_dict(state.telnet_prompts)
        
        logging.debug(f"'{self.name}' parser processed packet but found no credentials.")
        return None