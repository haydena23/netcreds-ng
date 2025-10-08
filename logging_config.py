from __future__ import annotations

import logging

class LoggingFormatter(logging.Formatter):
    """Custom logging formatter."""
    def __init__(self, fmt_debug: str, fmt_info: str):
        super().__init__()
        self.fmt_debug = fmt_debug
        self.fmt_info = fmt_info
        self._style._fmt = self.fmt_info

    def format(self, record: logging.LogRecord) -> str:
        original_format = self._style._fmt

        if record.levelno == logging.DEBUG:
            self._style._fmt = self.fmt_debug
        else:
            self._style._fmt = self.fmt_info

        result = super().format(record)

        self._style._fmt = original_format

        return result

def setup_logging(is_verbose: bool, is_quiet: bool) -> None:
    """Set up the logging configuration."""
    fmt_debug = "[%(asctime)s] [DEBUG] %(filename)s:%(lineno)d: %(message)s"
    fmt_info = "[%(levelname)s] %(message)s"

    handler = logging.StreamHandler()
    handler.setFormatter(LoggingFormatter(fmt_debug, fmt_info))

    log_level: int = (
        logging.DEBUG if is_verbose
        else logging.CRITICAL if is_quiet
        else logging.INFO
    )

    root_logger = logging.getLogger()
    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    logging.basicConfig(
        handlers=[handler],
        level=log_level
    )