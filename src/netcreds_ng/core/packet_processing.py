from __future__ import annotations
import logging
from queue import Queue
from threading import Event
from typing import Optional, Dict, Any, List

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP

from netcreds_ng.core.parser_manager import initialize_parsers
from netcreds_ng.core.dispatcher import dispatch_packet
from netcreds_ng.analytics import AnalyticsTracker
from netcreds_ng.output_writer import BaseWriter

# --- THREADING & MODULE GLOBALS ---
PARSER_INIT_EVENT = Event()
DATA_QUEUE: Optional[Queue[Dict[str, Any]]] = None
loaded_parsers: Optional[List[Any]] = None

OUTPUT_WRITER: Optional[BaseWriter] = None
ANALYSIS_TRACKER: Optional[AnalyticsTracker] = None

def initialize_parsers_threaded():
    """
    Target function for the background loader thread.
    Loads parsers, builds tables, and sets the event to unblock packet processing.
    """
    global loaded_parsers
    try:
        loaded_parsers = initialize_parsers()
    except Exception as e:
        logging.error(f"Failed to initialize parsers in background thread: {e}")
    finally:
        PARSER_INIT_EVENT.set()

def set_data_queue(queue: Queue[Dict[str, Any]]):
    """Sets the queue for communicating credential data to the UI."""
    global DATA_QUEUE
    DATA_QUEUE = queue # type: ignore

def set_analysis_tracker(tracker: AnalyticsTracker):
    """Sets the tracker for communicating analytics to the UI."""
    global ANALYSIS_TRACKER
    ANALYSIS_TRACKER = tracker

def set_output_writer(writer: BaseWriter):
    """Sets the file handle for writing credentials."""
    global OUTPUT_WRITER
    OUTPUT_WRITER = writer

def handle_result(result: Optional[Dict[str, Any]]):
    """
    Handles a result for LIVE CAPTURE mode by routing it to all configured outputs.
    """
    if not result:
        return
        
    if ANALYSIS_TRACKER:
        ANALYSIS_TRACKER.add_credential(result)

    if DATA_QUEUE:
        DATA_QUEUE.put(result)
    else:
        cred_str = result.get('credential', 'N/A')
        proto = result.get('protocol', 'UNKNOWN')
        src = result.get('source', 'N/A')
        dst = result.get('destination', 'N/A')
        cred_type = result.get('type', 'Credential')
        logging.info(f"[{proto}] {cred_type} from {src} to {dst}: {cred_str}")

    if OUTPUT_WRITER:
        OUTPUT_WRITER.write(result)
    
def parse_packet(packet: Ether) -> Optional[Dict[str, Any]]:
    """
    Parses a network packet using the parser system, waiting for parsers to be loaded.
    """

    PARSER_INIT_EVENT.wait()

    if loaded_parsers is None:
        return None
    
    if ANALYSIS_TRACKER and packet.haslayer(IP):
        ANALYSIS_TRACKER.increment_packets(packet[IP].src, packet[IP].dst)

    logging.debug("-" * 25 + " New Packet Captured " + "-" * 25)
    logging.debug(f"Parsing packet: {packet.summary()}")

    result = dispatch_packet(packet)
    if isinstance(result, dict):
        return result
    if result is True:
        return None
    
    logging.debug("Packet did not match any parsers.")
    return None