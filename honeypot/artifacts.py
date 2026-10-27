"""URL extraction and ``url.observed`` event emission (Commit 13).

Pure, zero-risk extraction: no network access, no host filesystem writes.
Turns URLs spotted inside attacker commands into structured, deduplicated
entities for the artifact chain (Commits 13–16).
"""

from __future__ import annotations

import re
from typing import List, Tuple

from .logger import log_event

# Conservative regex for http/https URLs anywhere inside a command line.
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")

# Characters that can trail a URL in prose but are not part of the URL itself.
_TRAILING_PUNCT = ".,);]\"'}"


def extract_urls(cmd_line: str) -> List[Tuple[str, str]]:
    """Return ``[(url, tool), ...]`` for URLs found in ``cmd_line``.

    Two sources:

    1. ``https?://...`` URLs anywhere in the line → tool ``raw``.
    2. Bare ``host/path`` tokens (no scheme) only when the command is
       ``wget`` or ``curl`` → tool ``wget`` / ``curl``.

    Results are deduplicated by URL within this call. Order is stable
    (first occurrence wins). No network access is performed.
    """
    found: List[Tuple[str, str]] = []
    seen = set()

    tokens = cmd_line.split()
    is_fetch = bool(tokens) and tokens[0] in ("wget", "curl")
    tool = tokens[0] if is_fetch else "raw"

    # 1) http(s):// URLs anywhere in the line.
    for match in _URL_RE.finditer(cmd_line):
        url = match.group(0).rstrip(_TRAILING_PUNCT)
        if url and url not in seen:
            seen.add(url)
            found.append((url, tool if is_fetch else "raw"))

    # 2) Bare host/path after wget/curl (no scheme), e.g. ``wget evil.com/x.sh``.
    if is_fetch:
        for token in tokens[1:]:
            if token.startswith("-") or token == "-":
                continue
            url = _bare_url(token)
            if url and url not in seen:
                seen.add(url)
                found.append((url, tool))

    return found


def _bare_url(token: str) -> str:
    """Return ``token`` if it looks like a bare host/path URL, else ``""``.

    Heuristic: contains both a dot and a slash, no scheme, doesn't start with
    ``/`` or ``.``. Strips trailing punctuation.
    """
    if "://" in token:
        return ""
    if "/" not in token or "." not in token:
        return ""
    if token.startswith("/") or token.startswith("."):
        return ""
    return token.rstrip(_TRAILING_PUNCT)


def emit_url_observed(shell, url: str, tool: str, command: str) -> None:
    """Emit ``url.observed`` for a URL spotted in a command.

    Makes no real network call. Session identity (session_id, source_ip,
    source_port, username) is taken from ``shell.session``.
    """
    session = shell.session
    log_event(
        "url.observed",
        session_id=session.session_id,
        source_ip=session.source_ip,
        source_port=session.source_port,
        username=session.username,
        url=url,
        tool=tool,
        command=command,
    )
