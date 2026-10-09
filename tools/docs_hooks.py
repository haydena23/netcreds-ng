"""MkDocs hooks for the documentation site (see ``hooks:`` in mkdocs.yml).

Docstrings use a few Sphinx cross-reference roles (``:class:`Finding```). mkdocstrings
renders them literally, so this hook turns them into plain code spans, keeping only the
last path component for ``~``-prefixed targets, as Sphinx does.
"""

from __future__ import annotations

import re
from typing import Any

_ROLE = re.compile(r":(?:py:)?(?:class|meth|func|attr|mod|data|exc|obj):<code>(~?)([^<]*)</code>")


def _code(match: re.Match[str]) -> str:
    target = match.group(2)
    if match.group(1):
        target = target.rsplit(".", 1)[-1]
    return f"<code>{target}</code>"


def on_page_content(html: str, **kwargs: Any) -> str:
    return _ROLE.sub(_code, html)
