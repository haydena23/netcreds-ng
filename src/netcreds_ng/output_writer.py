from __future__ import annotations
import csv
import json
from abc import ABC, abstractmethod
from typing import TextIO, Dict, Any
from datetime import datetime

class BaseWriter(ABC):
    """Abstract base class for all output writers."""
    def __init__(self, file_handle: TextIO):
        self.file_handle = file_handle

    def write_header(self):
        """Writes a header to the file, if applicable for the format."""
        pass

    @abstractmethod
    def write(self, result: Dict[str, Any]): # type: ignore
        """Writes a single credential result to the file."""
        raise NotImplementedError

    def close(self):
        """Closes the file handle."""
        self.file_handle.close()

class LogWriter(BaseWriter):
    """Writes credentials in a human-readable log format."""
    def write(self, result: Dict[str, Any]):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        proto = result.get('protocol', 'UNKNOWN')
        src = result.get('source', 'N/A')
        dst = result.get('destination', 'N/A')
        cred_type = result.get('type', 'Credential')
        cred = result.get('credential', 'N/A').strip()
        line = f"[{timestamp}] [{proto}] {cred_type} from {src} to {dst}: {cred}\n"
        self.file_handle.write(line)

class CsvWriter(BaseWriter):
    """Writes credentials in CSV format."""
    def __init__(self, file_handle: TextIO):
        super().__init__(file_handle)
        self.writer = csv.writer(file_handle)
        self.fieldnames = ["timestamp", "protocol", "source", "destination", "type", "credential"]

    def write_header(self):
        self.writer.writerow(self.fieldnames)

    def write(self, result: Dict[str, Any]):
        row = [ # type: ignore
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            result.get('protocol', ''),
            result.get('source', ''),
            result.get('destination', ''),
            result.get('type', ''),
            result.get('credential', '').strip()
        ]
        self.writer.writerow(row) # type: ignore

class JsonlWriter(BaseWriter):
    """Writes credentials in JSON Lines format."""
    def write(self, result: Dict[str, Any]):
        result['timestamp'] = datetime.now().isoformat()
        if 'credential' in result:
            result['credential'] = result['credential'].strip()
        self.file_handle.write(json.dumps(result) + "\n")

class JtrWriter(BaseWriter):
    """Writes only crackable hashes in a format suitable for John the Ripper."""
    def write(self, result: Dict[str, Any]):
        cred_type = result.get('type', '').lower()
        if 'hash' in cred_type:
            self.file_handle.write(result.get('credential', '').strip() + "\n")

def get_writer(format_type: str, file_handle: TextIO) -> BaseWriter:
    """Factory function to get the correct writer instance."""
    writers = { # type: ignore
        "log": LogWriter,
        "csv": CsvWriter,
        "jsonl": JsonlWriter,
        "jtr": JtrWriter,
    }
    writer_class = writers.get(format_type.lower(), LogWriter) # type: ignore
    return writer_class(file_handle) # type: ignore