from __future__ import annotations
import logging
from binascii import hexlify
from typing import Optional, Dict, Any

from scapy.packet import Packet
from scapy.layers.inet import IP, UDP

from netcreds_ng.parsers.base_parser import BaseParser

try:
    from impacket.krb5.asn1 import AS_REQ
    from impacket.krb5 import constants
    from pyasn1.codec.der import decoder
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False # type: ignore

class KerberosParser(BaseParser):
    """Parses Kerberos AS-REQ packets for crackable hashes."""

    @property
    def name(self) -> str:
        return "Kerberos"

    def can_handle(self, packet: Packet) -> bool:
        """Return True if the packet is Kerberos AS-REQ traffic (UDP port 88)."""
        if not IMPACKET_AVAILABLE:
            return False
        # Check for port and the AS-REQ application tag (0x6a)
        return packet.haslayer(UDP) and (packet[UDP].dport == 88 or packet[UDP].sport == 88) and bytes(packet[UDP].payload).startswith(b'\x6a') # type: ignore

    def process(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """
        Processes a Kerberos AS-REQ packet.
        
        Returns a dictionary with the hash if found, otherwise None.
        """
        if not (packet.haslayer(IP) and packet.haslayer(UDP) and packet[UDP].payload):
            return None
            
        kerb_data = bytes(packet[UDP].payload)
        src_ip_port = f"{packet[IP].src}:{packet[UDP].sport}"
        dst_ip_port = f"{packet[IP].dst}:{packet[UDP].dport}"

        try:
            as_req_message, _ = decoder.decode(kerb_data, asn1Spec=AS_REQ()) # type: ignore
            
            for pre_auth_entry in as_req_message['padata']: # type: ignore
                if pre_auth_entry['padata-type'] == constants.PreAuthenticationDataTypes.PA_ENC_TIMESTAMP.value: # type: ignore
                    encrypted_timestamp = pre_auth_entry['padata-value'] # type: ignore
                    username = str(as_req_message['req-body']['cname']['name-string'][0]) # type: ignore
                    realm = str(as_req_message['req-body']['realm']) # type: ignore
                    
                    encrypted_timestamp_hex = hexlify(bytes(encrypted_timestamp)).decode('utf-8') # type: ignore
                    
                    crackable_hash = f"$krb5pa$23${username}${realm}$DummySalt${encrypted_timestamp_hex}"
                    
                    return {
                        "protocol": self.name,
                        "source": src_ip_port,
                        "destination": dst_ip_port,
                        "type": "AS-REQ Hash",
                        "credential": crackable_hash
                    }
        except Exception as e:
            logging.debug(f"Could not parse potential Kerberos AS-REQ from {src_ip_port}: {e}")

        logging.debug(f"'{self.name}' parser processed packet but found no credentials.")    
        return None