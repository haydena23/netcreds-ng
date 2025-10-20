from __future__ import annotations

import argparse
import logging
import sys
import os
import platform
import time
from typing import Optional, Sequence, List
from pathlib import Path
from queue import Queue
from threading import Thread

from rich.console import Console

from netcreds_ng.core import capture
from netcreds_ng.core.packet_processing import set_data_queue, set_analysis_tracker, set_output_writer, initialize_parsers_threaded
from netcreds_ng.utils import network
from netcreds_ng.logging_config import setup_logging
from netcreds_ng.analytics import AnalyticsTracker
from netcreds_ng.output_writer import get_writer
from netcreds_ng.tui.static_display import display_results_table
from netcreds_ng.tui.dashboard import run_dashboard # type: ignore

APP_NAME = "netcreds-ng"
__version__ = "1.2.0"

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
            from os import geteuid # type: ignore
            return geteuid() == 0 # type: ignore
    except Exception:
        return False

def main(argv: Optional[Sequence[str]] = None) -> int:
    if platform.system() == "Windows":
        try:
            import win32api # type: ignore
            def ctrl_c_handler(ctrl_type): # type: ignore
                """Handler that performs a hard exit on Ctrl+C."""
                time.sleep(0.5)
                os._exit(INTERRUPT)
                return True
            win32api.SetConsoleCtrlHandler(ctrl_c_handler, True) # type: ignore
        except ImportError:
            logging.warning("pywin32 not installed. Ctrl+C may not work reliably in TUI mode on Windows.")

    parser = argparse.ArgumentParser(
        prog=APP_NAME
    )

    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument("-i", "--interface", help="Choose an interface for live capture")
    source_group.add_argument("-p", "--pcap", help="Parse credentials from a PCAP file")

    parser.add_argument("-u", "--update", help="Update to the latest version of netcreds-ng", action="store_true")
    parser.add_argument("--version", help="Display current version", action="store_true")
    parser.add_argument("-o", "--output", help="Append captured credentials to a file")
    parser.add_argument("--format", help="Output file format", choices=['log', 'csv', 'jsonl', 'jtr'], default='log')
    parser.add_argument("--no-tui", help="Disable the Text User Interface for live capture", action="store_true")
    parser.add_argument("-v", "--verbose", help="Show the analytics panel in the TUI", action="store_true")

    filter_group = parser.add_mutually_exclusive_group()
    filter_group.add_argument("-f", "--filter", help="Do not sniff packets from host1,host2,...", type=str)
    filter_group.add_argument("-F", "--filterfile", help="Do not sniff packets new-line delimeted file", type=str)
        
    log_level_group = parser.add_mutually_exclusive_group()
    log_level_group.add_argument("--debug", help="Enable debug logging (to console in --no-tui, to file in TUI mode)", action="store_true")
    log_level_group.add_argument("-q", "--quiet", help="Suppress all console output", action="store_true")
    
    args = parser.parse_args(argv)

    if args.version:
        print(f"{APP_NAME} {__version__}")
        return SUCCESS
    
    log_file_name = "netcreds-ng.log"

    if args.update:
        try:
            logging.error(f"[!] Netcreds updating not available. It is being reworked")
            return ERROR
        except Exception as e:
            logging.error(f"[!] Error updating netcreds-ng: {e}")
            return ERROR
    
    if not args.no_tui and not args.pcap:
        if args.debug:
            setup_logging(is_debug=True, is_quiet=True, log_file=log_file_name)
            print(f"[+] TUI active. Debug logs will be written to: {log_file_name}")
        else:
            logging.disable(logging.CRITICAL)
    else:
        setup_logging(is_debug=args.debug, is_quiet=args.quiet)
    
    parser_loader_thread = Thread(target=initialize_parsers_threaded, daemon=True)
    parser_loader_thread.start()

    filter_ips: List[str] = []
    if args.filter:
        filter_ips.extend([ip.strip() for ip in args.filter.split(",") if ip.strip()])
    elif args.filterfile:
        try:
            with open(args.filterfile, "r") as f:
                filter_ips.extend([line.strip() for line in f if line.strip()])
        except IOError as e:
            print(f"[ERROR] Could not open filter file: {e}", file=sys.stderr)
            return ERROR

    writer = None
    try:
        if args.output:
            is_new_file = not os.path.exists(args.output) or os.path.getsize(args.output) == 0
            output_file_handle = open(args.output, "a")
            writer = get_writer(args.format, output_file_handle)
            if is_new_file:
                writer.write_header()
            set_output_writer(writer)
            if not args.quiet:
                print(f"[+] Credentials will be appended to: {args.output} (Format: {args.format})")

        if args.pcap:
            # BATCH MODE
            pcap_size = os.path.getsize(args.pcap)
            tracker = AnalyticsTracker(is_pcap=True, pcap_size=pcap_size)
            set_analysis_tracker(tracker)
            results = capture.read_pcap_batch(args.pcap, filter_ips, tracker)
            if writer:
                for cred in results:
                    writer.write(cred)
            if not args.quiet:
                display_results_table(results, tracker)
        
        elif args.interface or (not args.pcap and not args.interface):
            # LIVE MODE
            if not is_admin():
                 print(f"[ERROR] Please run as root/admin", file=sys.stderr)
                 return ERROR
            
            internal_interface_name = args.interface
            friendly_interface_name = args.interface

            if not internal_interface_name:
                found_interfaces = network.interface_finder()

                if found_interfaces:
                    internal_interface_name, friendly_interface_name = found_interfaces
                else:
                    Console().print("[bold red]ERROR:[/] Could not automatically find a valid interface. Please specify one with -i.")
                    return ERROR
            
            if friendly_interface_name is None:
                friendly_interface_name = internal_interface_name

            if not args.quiet:
                print(f"Using Interface: {friendly_interface_name}")
            
            tracker = AnalyticsTracker()
            set_analysis_tracker(tracker)
            capture_thread = Thread(target=capture.start_sniffing, args=(internal_interface_name, filter_ips, tracker), daemon=True)
            capture_thread.start()
            if args.no_tui:
                capture_thread.join()
            else:
                data_queue = Queue() # type: ignore
                set_data_queue(data_queue) # type: ignore
                time.sleep(0.1)
                run_dashboard(data_queue, args.verbose, tracker, friendly_interface_name) # type: ignore
    
    except FileNotFoundError:
        print(f"[ERROR] PCAP file not found: {args.pcap}", file=sys.stderr)
        return ERROR
    except IOError as e:
        print(f"[ERROR] Could not write to output file: {e}", file=sys.stderr)
        return ERROR
    except Exception as e:
        print(f"\n[ERROR] An unexpected error occurred: {e}", file=sys.stderr)
        return ERROR
    finally:
        if writer:
            writer.close()
            if not args.quiet and args.output:
                print(f"[+] Finished writing credentials to: {args.output}")


    return SUCCESS

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(INTERRUPT)