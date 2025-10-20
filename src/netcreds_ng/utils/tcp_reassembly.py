from __future__ import annotations

import logging
from collections import OrderedDict

# --- Global Fragment Store & Constants ---
packet_frag_loads: OrderedDict[str, OrderedDict[int, str]] = OrderedDict()
MAX_IP_PORTS = 50
MAX_ACKS_PER_IP = 25
MAX_LOAD_LENGTH = 7500
TRUNCATED_LENGTH = 200

def frag_remover() -> None:
    """Trims the global fragment store to prevent unbounded growth."""
    while len(packet_frag_loads) > MAX_IP_PORTS:
        oldest_key = next(iter(packet_frag_loads))
        logging.debug(f"Fragment store full. Removing oldest IP:port entry: {oldest_key}")
        packet_frag_loads.popitem(last=False)

    for ip_port, ack_dict in list(packet_frag_loads.items()):
        while len(ack_dict) > MAX_ACKS_PER_IP:
            oldest_ack = next(iter(ack_dict))
            logging.debug(f"Max ACKs for {ip_port}. Removing oldest ACK: {oldest_ack}")
            ack_dict.popitem(last=False)

        for ack, payload in list(ack_dict.items()):
            if len(payload) > MAX_LOAD_LENGTH:
                ack_dict[ack] = payload[-TRUNCATED_LENGTH:]
                logging.debug(f"Payload for {ip_port} ACK {ack} truncated.")

def frag_joiner(src_ip_port: str, ack: int, load: str) -> str:
    """Appends a new fragment to the buffer and returns the fully reassembled payload."""
    if src_ip_port not in packet_frag_loads:
        packet_frag_loads[src_ip_port] = OrderedDict()
        logging.debug(f"Created new fragment buffer for {src_ip_port}")
    
    ack_dict = packet_frag_loads[src_ip_port]
    if ack in ack_dict:
        old_len = len(ack_dict[ack])
        ack_dict[ack] += load
        logging.debug(f"Appended {len(load)} bytes to existing fragment for {src_ip_port} ACK {ack}. New length: {len(ack_dict[ack])} (was {old_len})")
    else:
        ack_dict[ack] = load
        logging.debug(f"Added new fragment for {src_ip_port} ACK {ack}, length {len(load)}")
        
    frag_remover()
    return ack_dict[ack]