from __future__ import annotations
import logging
from binascii import hexlify
from typing import Optional, Dict, Any

from scapy.packet import Packet, Raw
from scapy.layers.inet import IP, TCP

from netcreds_ng.parsers.base_parser import BaseParser
from netcreds_ng import state

try:
    from impacket.ntlm import NTLMAuthChallenge, NTLMAuthChallengeResponse
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False # type: ignore

class NTLMParser(BaseParser):
    """Parses NTLMv2 hashes from various protocols (e.g., SMB, HTTP)."""

    @property
    def name(self) -> str:
        return "NTLM"

    def can_handle(self, packet: Packet) -> bool:
        """Return True if the packet contains an NTLMSSP signature."""
        if not IMPACKET_AVAILABLE or not (packet.haslayer(TCP) and packet.haslayer(Raw)):
            return False
        
        return b'NTLMSSP\x00' in packet[Raw].load

    def process(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """
        Processes NTLM Challenge (Type 2) and Response (Type 3) packets.
        """
        if not packet.haslayer(IP):
            return None

        src_ip_port = f"{packet[IP].src}:{packet[TCP].sport}"
        dst_ip_port = f"{packet[IP].dst}:{packet[TCP].dport}"
        payload = packet[Raw].load

        # --- NTLM Challenge (Type 2) from Server to Client ---
        if b'\x02\x00\x00\x00' in payload[8:12]:
            try:
                challenge = NTLMAuthChallenge(payload) # type: ignore
                # The server sends the challenge TO the client. Need to remember it
                # for when the client sends its response back.
                client_addr = dst_ip_port
                state.ntlm_challenges[client_addr] = challenge['challenge'].getData() # type: ignore
                state.clean_state_dict(state.ntlm_challenges)
                logging.debug(f"Captured NTLM Challenge for client {client_addr}")
            except Exception as e:
                logging.debug(f"Could not parse NTLM Challenge from {src_ip_port}: {e}")
            return None # A challenge is not a credential

        # --- NTLM Response (Type 3) from Client to Server ---
        elif b'\x03\x00\x00\x00' in payload[8:12]:
            # The client sends the response FROM its address.
            client_addr = src_ip_port
            if client_addr in state.ntlm_challenges: # type: ignore
                try:
                    server_challenge = state.ntlm_challenges.pop(client_addr)
                    response = NTLMAuthChallengeResponse(payload) # type: ignore
                    
                    username = response['user_name'].decode('utf-16le') # type: ignore
                    domain = response['domain_name'].decode('utf-16le') # type: ignore
                    ntlm_response = response['ntlm_response'].getData() # type: ignore
                    
                    # Only interested in Net-NTLMv2, which is the modern standard.
                    if len(ntlm_response) > 24: # NTLMv1 response is exactly 24 bytes # type: ignore
                        # Net-NTLMv2 hash format for Hashcat/John
                        # username::domain:server_challenge:nt_proof:ntlmv2_response
                        nt_proof_str = hexlify(ntlm_response[16:32]).decode() # type: ignore
                        ntlmv2_response = hexlify(ntlm_response[32:]).decode() # type: ignore
                        server_challenge_hex = hexlify(server_challenge).decode() # type: ignore
                        
                        hash_str = f"{username}::{domain}:{server_challenge_hex}:{nt_proof_str}:{ntlmv2_response}"
                        
                        return {
                            "protocol": "Net-NTLMv2",
                            "source": src_ip_port,
                            "destination": dst_ip_port,
                            "type": "Hash",
                            "credential": hash_str
                        }
                except Exception as e:
                    logging.debug(f"Could not parse NTLM Response from {src_ip_port}: {e}")
        
        logging.debug(f"'{self.name}' parser processed packet but found no credentials.")
        return None