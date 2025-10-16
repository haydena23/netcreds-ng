#!/usr/bin/python

"""
To-Do:
* PCAP-NG Parsing
* Update function
* Multiple OS support
* Packet Parsing
* Rich for better dashboard
* Parse SNMP & Kerberos UDP/TCP
* TCP
* Telnet
* FTP
"""

from __future__ import annotations

import argparse
import logging
import subprocess
from typing import Optional, Sequence, List
from pathlib import Path

from scapy.all import PcapReader, sniff, conf
from os import geteuid # type: ignore

from logging_config import setup_logging
from utils import interface_finder, bpf_filter
from parse_packet import parse_packet

APP_NAME = "netcreds-ng"
__version__ = "1.1.1"

REPO_PATH = Path(__file__).parent

SUCCESS = 0
ERROR = 1
INTERRUPT = 130
ROOT = 0

def update() -> None:
    """Update the tool from GitHub if possible."""
    logging.info("Checking for updates...")
    git_dir = REPO_PATH / ".git"
    if not git_dir.exists():
        logging.error("Cannot update: this installation is not a git repository.")
        return

    try:
        subprocess.run(["git", "fetch", "--all"], cwd=REPO_PATH, check=True, stdout=subprocess.PIPE)
        subprocess.run(["git", "pull"], cwd=REPO_PATH, check=True)
        logging.info(f"Successfully updated {APP_NAME}.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to update: {e}")

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog=APP_NAME
    )

    parser.add_argument("-i", "--interface", help="Choose an interface")
    parser.add_argument("-p", "--pcap", help="Parse info from a pcap file")
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
        logging.info(f"{APP_NAME} version: {__version__}")
        return SUCCESS
    
    if args.update:
        try:
            update()
            return SUCCESS
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
        if geteuid() is not ROOT:
           logging.error(f"Please run as root. Current UID: {geteuid()}")
           return ERROR
        if args.interface:
            conf.iface = args.interface
        else:
            conf.iface = interface_finder()

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
            filter=bpf_filter(filter_ips)
        )

    return SUCCESS

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(INTERRUPT)
    except Exception:
        raise SystemExit(ERROR)