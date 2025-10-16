from __future__ import annotations

import logging
from typing import Optional, ByteString
from binascii import hexlify

from scapy.all import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.snmp import SNMP

from impacket.krb5.asn1 import AS_REQ
from impacket.krb5 import constants
from pyasn1.codec.der import decoder

SNMP_VERSION_MAP = {0: "v1", 1: "v2c", 2: "v2", 3: "v3"}

def parse_snmp(src_ip_port: str, dst_ip_port: str, snmp_packet: SNMP) -> None:
    """Parses SNMP packets to extract the Community String"""
    version = snmp_packet.version.val
    community_bytes = snmp_packet.community.val

    if version == 3:
        logging.debug("SNMPv3 packet received: no community string.")
        return
    
    try:
        community_string = community_bytes.decode("ascii")
    except(AttributeError, UnicodeDecodeError):
        community_string = str(community_bytes)
        
    version_string = SNMP_VERSION_MAP.get(version, f"Unknown({version})")
    logging.info(f"SNMP{version_string} packet from {src_ip_port} to {dst_ip_port}: Community String = '{community_string}'")
    return

def parse_kerberos(src_ip_port: str, dst_ip_port: str, kerb_data: bytes) -> None:
    """
    Parses Kerberos AS-REQ data to extract hash.
    """
    application_tag = hexlify(kerb_data[:1]).decode('ascii')
    # KRB_AS_REQ has an application tag of 10, which is 0x6a in hex.
    # This check ensures trying to parse AS-REQ packets.
    if not kerb_data.startswith(b'\x6a'):
        logging.debug(f"Invalid Kerberos AS-REQ packet - Application Tag mismatch. Expecting 0x6a, got 0x{application_tag}")
        return

    try:
        logging.debug(f"Valid Application Tag Match: {application_tag}")
        # The Kerberos message is encoded in ASN.1 DER format.
        # Use the pyasn1 decoder to turn the raw bytes into a structured object.
        # The 'asn1Spec' tells the decoder what structure to expect (an AS_REQ).
        # The decoder returns the object and any remaining bytes (ignore).
        as_req_message, _ = decoder.decode(kerb_data, asn1Spec=AS_REQ()) # type: ignore
        logging.debug(f"Decoded AS-REQ message structure: {as_req_message.prettyPrint()}") # type: ignore
        # The 'padata' field contains a list of pre-authentication entries.
        pre_authentication_data_list = as_req_message['padata'] # type: ignore
        logging.debug(f"Found {len(pre_authentication_data_list)} pre-authentication data entries.") # type: ignore

        for pre_auth_entry in pre_authentication_data_list: # type: ignore

            # Look for the entry that contains the user's encrypted timestamp.
            # Entry is the source of the crackable hash.
            entry_type = pre_auth_entry['padata-type'] # type: ignore
            logging.debug(f"Processing pre-authentication entry of type: {entry_type}")
            if entry_type == constants.PreAuthenticationDataTypes.PA_ENC_TIMESTAMP.value:
                logging.debug("Found PA-ENC-TIMESTAMP pre-authentication entry.")
                # --- Data Extraction ---
                # This is the encrypted data for the hash.
                encrypted_timestamp = pre_auth_entry['padata-value'] # type: ignore

                # Cast the pyasn1 'KerberosString' objects to standard Python strings.
                username = str(as_req_message['req-body']['cname']['name-string'][0]) # type: ignore
                realm = str(as_req_message['req-body']['realm']) # type: ignore
                logging.debug(f"Extracted Username: {username}")
                logging.debug(f"Extracted Realm: {realm}")

                # Cast the pyasn1 'OctetString' to 'bytes' before passing to hexlify.
                encrypted_timestamp_hex = hexlify(bytes(encrypted_timestamp)).decode('utf-8') # type: ignore
                logging.debug(f"Extracted Encrypted Timestamp (Hex): {encrypted_timestamp_hex[:64]}...")

                # --- Hash Construction ---
                # Assemble the components into the standard format recognized by tools
                # like Hashcat ($krb5pa$23$...).
                crackable_hash = f"$krb5pa$23${username}${realm}$DummySalt${encrypted_timestamp_hex}"
                logging.debug(f"Constructed crackable hash: {crackable_hash}")

                logging.info(f"MS Kerberos from {src_ip_port} to {dst_ip_port}: {crackable_hash}")
                
                return

    except Exception as error:
        # Error for any Kerberos packet that isn't a valid AS-REQ with
        # a hash (e.g., a TGS-REQ or an error message)
        logging.debug(f"Could not parse Kerberos AS-REQ from {src_ip_port}: {error}")
        logging.debug(f"Exception type: {type(error).__name__}")
        logging.debug(f"Payload: {kerb_data.hex()}")

def parse_packet(packet: Ether) -> None:
    """Parse a network packet."""
    load: Optional[ByteString] = None
    logging.info("-" * 25 + " New Packet Captured " + "-" * 25)
    if packet.haslayer(Raw):
        load = packet[Raw].load

    logging.debug(f"Parsing packet: {packet.summary()}")
    if load:
        logging.debug(f"Raw payload data: {load.hex()}")

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
        src_ip_port: str = str(packet[IP].src) + ":" + str(packet[UDP].sport)
        dst_ip_port: str = str(packet[IP].dst) + ':' + str(packet[UDP].dport)
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
        
    logging.info("Packet did not match any parsing criteria.")