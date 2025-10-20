from __future__ import annotations
import logging
from typing import List, Dict, Any
from scapy.all import PcapReader, sniff, conf
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from rich.progress import track

from netcreds_ng.core.packet_processing import parse_packet, handle_result
from netcreds_ng.utils.bpf import build_filter
from netcreds_ng.analytics import AnalyticsTracker

def read_pcap_batch(pcap_path: str, filter_ips: List[str], tracker: AnalyticsTracker) -> List[Dict[str, Any]]:
    """
    Reads and processes a PCAP file in batch mode, showing a progress bar.
    Returns a list of all found credentials.
    """
    logging.info(f"Analyzing PCAP: {pcap_path}")
    if filter_ips:
        logging.info(f"Applying manual filter to exclude hosts: {', '.join(filter_ips)}")

    found_credentials = []
    try:
        packet_count = 0
        with PcapReader(pcap_path) as pcap_for_count:
            for _ in pcap_for_count:
                packet_count += 1
        
        with PcapReader(pcap_path) as pcap_reader:
            for packet in track(pcap_reader, description="Processing packets...", total=packet_count):
                if filter_ips and packet.haslayer(IP):
                    if packet[IP].src in filter_ips or packet[IP].dst in filter_ips:
                        continue

                result = parse_packet(packet)
                if result:
                    found_credentials.append(result) # type: ignore
                    if tracker:
                        tracker.add_credential(result) # type: ignore

    except Exception as e:
        logging.error(f"Error while reading PCAP file: {e}")
    
    return found_credentials # type: ignore

def start_sniffing(interface: str, filter_ips: List[str], tracker: AnalyticsTracker):
    """Starts live packet capturing and sends results to the TUI or logger."""
    conf.iface = interface
    bpf = build_filter(filter_ips)
    
    if bpf:
        logging.info(f"Applying BPF Filter: {bpf}")

    def process_and_handle(packet: Ether):
        """Wrapper function called by Scapy for each live packet."""
        result = parse_packet(packet)
        handle_result(result)

    sniff(
        iface=interface,
        prn=process_and_handle,
        store=0,
        filter=bpf
    )