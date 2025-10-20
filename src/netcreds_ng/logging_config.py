from __future__ import annotations

import logging

class LoggingFormatter(logging.Formatter):
    """Custom logging formatter. Handles different formats for INFO and DEBUG."""
    def __init__(self, fmt_debug: str, fmt_info: str):
        super().__init__()
        self.fmt_debug = fmt_debug
        self.fmt_info = fmt_info

        # Default to info format
        self._style._fmt = self.fmt_info

    def format(self, record: logging.LogRecord) -> str:
        original_format = self._style._fmt

        if record.levelno == logging.DEBUG:
            self._style._fmt = self.fmt_debug
        else:
            self._style._fmt = self.fmt_info

        result = super().format(record)

        # Restore the original format
        self._style._fmt = original_format

        return result

def setup_logging(is_verbose: bool, is_quiet: bool) -> None:
    """Set up the global logging configuration."""
    fmt_debug = "[%(asctime)s] [DEBUG] %(filename)s:%(lineno)d: %(message)s"
    fmt_info = fmt_debug if is_verbose else "[%(asctime)s] [%(levelname)s] %(message)s"

    handler = logging.StreamHandler()
    handler.setFormatter(LoggingFormatter(fmt_debug, fmt_info))

    if is_verbose:
        log_level = logging.DEBUG
    elif is_quiet:
        log_level = logging.CRITICAL
    else:
        log_level = logging.INFO

    root_logger = logging.getLogger()
    # Clear any existing handlers
    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    logging.basicConfig(
        handlers=[handler],
        level=log_level
    )