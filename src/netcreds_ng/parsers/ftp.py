from __future__ import annotations
import logging
from typing import Optional, Dict, Any

from scapy.packet import Packet, Raw
from scapy.layers.inet import IP, TCP

from netcreds_ng.parsers.base_parser import BaseParser

class FTPParser(BaseParser):
    """Parses FTP traffic for usernames and passwords, with signature detection."""

    FTP_SIGNATURES = [
        b"USER ", b"PASS ", b"ACCT ", b"STOR ", b"RETR ",
        b"220 ", b"230 ", b"331 ", b"530 "
    ]

    @property
    def name(self) -> str:
        return "FTP"

    @property
    def ports(self) -> set[int]:
        return {21}

    def _has_ftp_signature(self, payload: bytes) -> bool:
        """Check if the payload contains known FTP signatures."""
        upper_payload = payload.upper()
        for signature in self.FTP_SIGNATURES:
            if signature in upper_payload:
                logging.debug(f"FTP signature found: {signature.decode()}")
                return True
        return False

    def can_handle(self, packet: Packet) -> bool:
        """Slow-path check for signatures, ignoring standard ports."""
        if not (packet.haslayer(TCP) and packet.haslayer(Raw) and len(packet[Raw].load) > 3):
            return False
        
        return self._has_ftp_signature(packet[Raw].load)

    def process(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """
        Processes a potential FTP packet for credentials.
        """
        if not (packet.haslayer(IP) and packet.haslayer(Raw)):
            return None

        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore').strip()
        except (UnicodeDecodeError, AttributeError):
            return None
        
        if not payload:
            return None
        
        src_ip_port = f"{packet[IP].src}:{packet[TCP].sport}"
        dst_ip_port = f"{packet[IP].dst}:{packet[TCP].dport}"
        
        credential = None
        cred_type = None

        upper_payload = payload.upper()
        if upper_payload.startswith("USER "):
            credential = payload[5:]
            cred_type = "Username"
        elif upper_payload.startswith("PASS "):
            credential = payload[5:]
            cred_type = "Password"
            
        if credential and cred_type:
            logging.debug(f"'{self.name}' parser found credential: {cred_type}")
            return {
                "protocol": self.name,
                "source": src_ip_port,
                "destination": dst_ip_port,
                "type": cred_type,
                "credential": credential
            }

        logging.debug(f"'{self.name}' parser processed packet but found no credentials.")
        return None