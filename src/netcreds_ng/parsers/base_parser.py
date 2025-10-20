from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, Set
from scapy.packet import Packet

class BaseParser(ABC):
    """Abstract Base Class for all netcreds-ng parsers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """The user-friendly name of the parser."""
        raise NotImplementedError

    @property
    def ports(self) -> Set[int]:
        """
        A set of IANA-registered TCP/UDP port numbers this parser handles.
        This is used to build a fast-path dispatch table.
        Return an empty set if the parser is purely signature-based.
        """
        return set()

    @abstractmethod
    def can_handle(self, packet: Packet) -> bool:
        """
        Return True if this parser can parse the given packet.
        This check is used for the slow-path (non-standard ports).
        """
        raise NotImplementedError

    @abstractmethod
    def process(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """
        Process the packet and extract credentials.
        """
        raise NotImplementedError