"""URL extraction, ``url.observed`` emission, and safe payload fetch.

Commit 13: URL extraction and ``url.observed`` emission — pure, zero-risk
extraction: no network access, no host filesystem writes.

Commit 14: safe payload fetch + SHA256 (opt-in). Turns extracted URLs into
stored, deduplicated payloads under ``data/artifacts/<sha256>``, bounded by
the §14.3 safety controls. The only commit introducing outbound network
capability; stays opt-in.
"""

from __future__ import annotations

import hashlib
import os
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import List, Optional, Tuple

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


# --------------------------------------------------------------------------- #
# Commit 14 — safe payload fetch + SHA256 (opt-in, §14.3 safety controls)
# --------------------------------------------------------------------------- #

FETCH_ARTIFACT_DIR = "data/artifacts"
MAX_DEFAULT_SIZE = 5 * 1024 * 1024      # 5 MB cap
DEFAULT_TIMEOUT = 10                    # 10 s connect + read
DEFAULT_MAX_REDIRECTS = 3               # max redirect hops
USER_AGENT = "SSHintel/3.0"
ALLOWED_SCHEMES = {"http", "https"}
_INTERNAL_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                      "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                      "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                      "172.30.", "172.31.", "192.168.", "127.", "169.254.",
                      "0.")


def _is_internal_host(host):
    if not host:
        return True
    h = host.lower().strip()
    if h in ("localhost", "localhost.localdomain", "ip6-loopback",
             "ip6-localdomain"):
        return True
    if h.endswith(".localhost"):
        return True
    if h == "::1" or h.startswith("::ffff:127.") or h.startswith("fe80:") \
            or h.startswith("fd00:"):
        return True
    parts = h.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        try:
            a = int(parts[0])
            b = int(parts[1])
        except ValueError:
            return False
        if a == 127 or a == 10 or a == 0:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
        if a == 169 and b == 254:
            return True
    return any(h.startswith(p) for p in _INTERNAL_PREFIXES)


class _RedirectCounter(urllib.request.HTTPRedirectHandler):
    """HTTP redirect handler that enforces a maximum redirect count."""

    def __init__(self, max_redirects):
        self.max_redirects = max_redirects
        self.count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.count += 1
        if self.count > self.max_redirects:
            raise urllib.error.HTTPError(
                newurl, 0, "too many redirects", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_payload(url, config=None, session_id=None, source_ip=None,
                  source_port=None, username=None):
    if config is None:
        config = {}

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return None
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return None

    if _is_internal_host(parsed.hostname or ""):
        return None

    max_size = int(config.get("fetch_max_size", MAX_DEFAULT_SIZE))
    timeout = int(config.get("fetch_timeout", DEFAULT_TIMEOUT))
    max_redirects = int(config.get("fetch_max_redirects", DEFAULT_MAX_REDIRECTS))

    req = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT}, method="GET"
    )
    opener = urllib.request.build_opener(_RedirectCounter(max_redirects))

    try:
        response = opener.open(req, timeout=timeout)
    except Exception:
        return None

    content_type = ""
    try:
        headers = response.headers
        if headers is not None:
            content_type = headers.get("Content-Type", "")
    except Exception:
        pass

    data = bytearray()
    try:
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            if len(data) + len(chunk) > max_size:
                return None
            data.extend(chunk)
    except Exception:
        return None
    finally:
        try:
            response.close()
        except Exception:
            pass

    content = bytes(data)
    sha256 = hashlib.sha256(content).hexdigest()
    stored_path = os.path.join(FETCH_ARTIFACT_DIR, sha256)

    try:
        os.makedirs(FETCH_ARTIFACT_DIR, exist_ok=True)
        fd = os.open(stored_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            os.write(fd, content)
        finally:
            os.close(fd)
    except FileExistsError:
        pass
    except Exception:
        return None

    try:
        os.chmod(stored_path, 0o644)
    except Exception:
        pass

    result = {
        "url": url,
        "sha256": sha256,
        "size": len(content),
        "content_type": content_type,
        "stored_path": stored_path,
    }

    if session_id is not None:
        try:
            log_event(
                "payload.downloaded",
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port,
                username=username,
                **result,
            )
        except Exception:
            pass

    return result


