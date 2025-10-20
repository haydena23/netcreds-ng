from __future__ import annotations
import logging

from binascii import hexlify
from impacket.krb5.asn1 import AS_REQ
from impacket.krb5 import constants
from pyasn1.codec.der import decoder

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