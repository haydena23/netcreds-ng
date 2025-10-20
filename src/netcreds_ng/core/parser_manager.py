from __future__ import annotations
import os
import importlib
import inspect
import logging
from typing import List, Dict

from netcreds_ng.parsers.base_parser import BaseParser

PORT_MAP: Dict[int, BaseParser] = {}
SIGNATURE_PARSERS: List[BaseParser] = []

PARSERS_DIR = os.path.join(os.path.dirname(__file__), '..', 'parsers')

def _load_parsers_from_disk() -> List[BaseParser]:
    """Internal function to discover and load all parser classes."""
    parsers: List[BaseParser] = []
    for filename in os.listdir(PARSERS_DIR):
        if filename.endswith(".py") and not filename.startswith("__") and "base_parser" not in filename:
            module_name = f"netcreds_ng.parsers.{filename[:-3]}"
            try:
                module = importlib.import_module(module_name)
                for _, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, BaseParser) and obj is not BaseParser:
                        parsers.append(obj())
            except ImportError as e:
                logging.error(f"Failed to import parser module {module_name}: {e}")
    return parsers

def initialize_parsers():
    """
    Loads all parsers, builds the fast-path dispatch tables, and populates
    the global state. This is the single entry point for parser setup.
    """
    global PORT_MAP, SIGNATURE_PARSERS
    
    parsers = _load_parsers_from_disk()
    
    PORT_MAP.clear()
    SIGNATURE_PARSERS.clear()

    for parser in parsers:
        for port in parser.ports:
            PORT_MAP[port] = parser
        
        SIGNATURE_PARSERS.append(parser)
    
    logging.info(f"Loaded {len(parsers)} parsers and built dispatch tables.")
    
    return parsers