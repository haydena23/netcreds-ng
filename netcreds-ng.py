#!/usr/bin/python

from __future__ import annotations

import argparse
import logging
from typing import Optional, Sequence, List
from pathlib import Path

from scapy.all import PcapReader, sniff, conf
import platform
import os
import sys

from logging_config import setup_logging
import src.netcreds_ng.utils.network as network
from parse_packet import parse_packet

from src.netcreds_ng.utils import bpf

APP_NAME = "netcreds-ng"
__version__ = "1.1.4"

REPO_PATH = Path(__file__).parent

SUCCESS = 0
ERROR = 1
INTERRUPT = 130
ROOT = 0

def is_admin() -> bool:
    """Check if the script is running with administrative privileges."""
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0 # type: ignore
    except Exception:
        return False

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog=APP_NAME
    )

    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument("-i", "--interface", help="Choose an interface for live capture")
    source_group.add_argument("-p", "--pcap", help="Parse credentials from a PCAP file")

    parser.add_argument("-u", "--update", help="Update to the latest version of netcreds-ng", action="store_true")
    parser.add_argument("--version", help="Display current version", action="store_true")

    filter_group = parser.add_mutually_exclusive_group()
    filter_group.add_argument("-f", "--filter", help="Do not sniff packets from host1,host2,...", type=str)
    filter_group.add_argument("-F", "--filterfile", help="Do not sniff packets new-line delimeted file", type=str)
    
    verbose_group = parser.add_mutually_exclusive_group()
    verbose_group.add_argument("-v", "--verbose", help="Display entire URLs and POST loads rather than truncating at 100 characters", action="store_true")
    verbose_group.add_argument("-q", "--quiet", help="Supress logging", action="store_true")
    
    args = parser.parse_args(argv)

    setup_logging(args.verbose, args.quiet)

    if args.version:
        logging.info(f"{APP_NAME} Installed version: {__version__}")
        return SUCCESS
    
    if args.update:
        try:
            logging.error(f"[!] Netcreds updating not available. It is being reworked")
            return ERROR
        except Exception as e:
            logging.error(f"[!] Error updating netcreds-ng: {e}")
            return ERROR

    if args.pcap is not None:
        try:
            for packet in PcapReader(args.pcap):
                parse_packet(packet)
        except IOError as e:
            logging.error(f"Could not open PCAP file: {e}")
            return ERROR
        except ImportError as e:
            logging.error(f"Scapy is required to examine PCAP files: {e}")
            return ERROR
    else:       
        if not is_admin():
           logging.error(f"Please run as root/admin.")
           return ERROR
        
        internal_interface_name = args.interface
        friendly_interface_name = args.interface

        if not internal_interface_name:
            found_interfaces = network.interface_finder()
            if found_interfaces:
                internal_interface_name, friendly_interface_name = found_interfaces
            else:
                return ERROR
        if friendly_interface_name is None:
            friendly_interface_name = network.get_friendly_name(internal_interface_name)


        logging.info(f"Using Interface: {conf.iface}") # type: ignore

        filter_ips: List[str] = []
        if args.filter:
            filter_ips.extend([ip.strip() for ip in args.filter.split(",") if ip.strip()])
        elif args.filterfile:
            try:
                with open(args.filterfile, "r") as f:
                    filter_ips.extend([line.strip() for line in f if line.strip()])
            except IOError as e:
                logging.error(f"Could not open filter file: {e}")
                return ERROR 
            
        sniff(
            iface=conf.iface, # type: ignore
            prn=parse_packet, 
            store=0, 
            filter=bpf.build_filter(filter_ips)
        )

    return SUCCESS

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(INTERRUPT)