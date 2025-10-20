from __future__ import annotations

import logging

from typing import Optional, Dict, Any, Union
from scapy.packet import Packet
from scapy.layers.inet import TCP, UDP

from netcreds_ng.core.parser_manager import PORT_MAP, SIGNATURE_PARSERS

def dispatch_packet(packet: Packet) -> Optional[Union[Dict[str, Any], bool]]:
    """
    Dispatches a packet using a fast-path port map first, then falling
    back to a slow-path signature check.
    """

    from netcreds_ng.core.packet_processing import ANALYSIS_TRACKER

    port: int = 0
    if packet.haslayer(TCP):
        port = packet[TCP].dport or packet[TCP].sport
    elif packet.haslayer(UDP):
        port = packet[UDP].dport or packet[UDP].sport

    # 1. FAST PATH
    if port in PORT_MAP:
        parser = PORT_MAP[port]
        logging.debug(f"Fast path: Port {port} matched parser '{parser.name}'.")
        if ANALYSIS_TRACKER:
            ANALYSIS_TRACKER.increment_interesting(parser.name)
        result = parser.process(packet)
        return result if result is not None else True

    # 2. SLOW PATH (Signature-based)
    logging.debug(f"Fast path miss on port {port}. Trying {len(SIGNATURE_PARSERS)} signature-based parsers.")
    for parser in SIGNATURE_PARSERS:
        if parser.can_handle(packet):
            logging.debug(f"Slow path: Signature matched parser '{parser.name}'.")
            if ANALYSIS_TRACKER:
                ANALYSIS_TRACKER.increment_interesting(parser.name)
            result = parser.process(packet)
            return result if result is not None else True
            
    return None