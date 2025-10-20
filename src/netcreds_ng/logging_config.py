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

def setup_logging(is_debug: bool, is_quiet: bool, log_file: str | None = None) -> None:
    """
    Set up the global logging configuration.
    
    Args:
        is_debug: If True, set the logging level to DEBUG.
        is_quiet: If True, suppress console logging.
        log_file: If provided, add a file handler to write all DEBUG logs.
    """
    handlers = []

    if not is_quiet:
        fmt_debug = "[%(asctime)s] [DEBUG] [%(filename)s:%(lineno)d] %(message)s"
        fmt_info = fmt_debug if is_debug else "[%(asctime)s] [%(levelname)s] %(message)s"
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(LoggingFormatter(fmt_debug, fmt_info))
        handlers.append(console_handler) # type: ignore

    if log_file:
        fmt_file = "[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s"
        file_handler = logging.FileHandler(log_file, mode='a')
        file_handler.setFormatter(logging.Formatter(fmt_file))
        file_handler.setLevel(logging.DEBUG)
        handlers.append(file_handler) # type: ignore

    if is_debug or log_file:
        log_level = logging.DEBUG
    elif is_quiet:
        log_level = logging.CRITICAL
    else:
        log_level = logging.INFO

    root_logger = logging.getLogger()
    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    logging.basicConfig(
        handlers=handlers, # type: ignore
        level=log_level,
        force=True
    )