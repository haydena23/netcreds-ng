from __future__ import annotations
import logging
import platform
from typing import Optional, Tuple

from scapy.config import conf

if platform.system() == "Windows":
    try:
        from scapy.arch.windows import get_windows_if_list
    except ImportError:
        get_windows_if_list = None
else:
    get_windows_if_list = None

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False # type: ignore

def get_friendly_name(internal_name: str) -> str:
    """
    Helper to translate a Windows device name to its friendly description.
    Returns the original name if translation isn't possible or not on Windows.
    """
    if platform.system() != "Windows" or not get_windows_if_list:
        return internal_name

    try:
        iface_map = {iface.get("name"): iface.get("description") for iface in get_windows_if_list()}
        return iface_map.get(internal_name, internal_name)# type: ignore
    except Exception as e:
        logging.warning(f"Could not get friendly interface name: {e}")
        return internal_name

def interface_finder() -> Optional[Tuple[str, str]]:
    """
    Finds the best active network interface.

    Returns a tuple containing:
    (internal_name_for_scapy, user_friendly_name)
    or None if no suitable interface is found.
    """
    if not NETIFACES_AVAILABLE:
        logging.warning("netifaces is not installed. Cannot auto-find interface. Please specify with -i.")
        return None

    try:
        gateways = netifaces.gateways() # type: ignore
        default_gateway_info = gateways.get('default', {}).get(netifaces.AF_INET) # type: ignore
        
        if not default_gateway_info:
            logging.warning("Could not determine default gateway from netifaces.")
            return None
            
        gateway_ip = default_gateway_info[0] # type: ignore
        logging.debug(f"Found default gateway IP: {gateway_ip}")

        route_to_gateway = conf.route.route(gateway_ip, verbose=False) # type: ignore

        if not route_to_gateway:
             logging.warning(f"Scapy could not determine a route to the default gateway {gateway_ip}.")
             return None
        
        internal_name = route_to_gateway[0] # type: ignore
        
        if not internal_name or "lo" in internal_name.lower(): # type: ignore
            logging.warning("Scapy's route points to a loopback or invalid interface.")
            return None

        logging.debug(f"Found internal interface name for Scapy: {internal_name}")
        
        friendly_name = get_friendly_name(internal_name) # type: ignore
        
        logging.info(f"Automatically selected active interface: {friendly_name} ({internal_name})")
        
        return (internal_name, friendly_name) # type: ignore

    except Exception as e:
        logging.error(f"An unexpected error occurred while auto-finding interface: {e}")
        return None