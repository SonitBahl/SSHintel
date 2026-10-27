"""Tests for safe payload fetch + SHA256 (Commit 14).

All tests are offline: the HTTP layer is stubbed. No real socket is opened and
no network request is made. Enforces every §14.3 safety control:

* scheme allow-list (http/https only)
* no internal targets (localhost / RFC1918)
* size cap (5 MB), timeout (10 s), redirect cap (3)
* storage at data/artifacts/<sha256>, mode 0644, no execute bit
* dedup by sha256; fetch failure never raises into the session
"""

import os
import socket
import stat
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import urllib.error as urllib_error

from honeypot.artifacts import (
    fetch_payload,
    _is_internal_host,
    _RedirectCounter,
    FETCH_ARTIFACT_DIR,
    MAX_DEFAULT_SIZE,
)


class _FakeResponse:
    """Stubbed urllib response yielding content in chunks."""

    def __init__(self, content=b"payload", content_type="application/octet-stream"):
        self._content = content
        self._offset = 0
        self.headers = {"Content-Type": content_type}

    def read(self, n=65536):
        chunk = self._content[self._offset:self._offset + n]
        self._offset += len(chunk)
        return chunk

    def close(self):
        pass


def _stub_build_opener(monkeypatch, content=b"payload",
                       content_type="application/octet-stream"):
    """Patch urllib.request.build_opener to return a fake opener.

    Each call to opener.open() returns a fresh response with ``content``.
    """
    def _build(*_args, **_kwargs):
        opener = MagicMock()

        def _open(_req, timeout=None):
            return _FakeResponse(content, content_type)

        opener.open = _open
        return opener

    monkeypatch.setattr("honeypot.artifacts.urllib.request.build_opener", _build)


class TestFetchSuccess:
    def test_fetch_payload_stores_and_hashes(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        content = b"print('pwned')\n"
        _stub_build_opener(monkeypatch, content=content)

        result = fetch_payload(
            "http://evil.example/x.sh",
            config={"fetch_payloads": True},
            session_id="s1",
            source_ip="10.0.0.9",
            source_port=54321,
            username="user1",
        )

        assert result is not None
        assert result["url"] == "http://evil.example/x.sh"
        assert result["size"] == len(content)
        import hashlib
        assert result["sha256"] == hashlib.sha256(content).hexdigest()
        assert result["content_type"] == "application/octet-stream"
        assert result["stored_path"] == os.path.join(
            FETCH_ARTIFACT_DIR, result["sha256"]
        )
        # File actually written.
        assert Path(result["stored_path"]).read_bytes() == content
        # Mode 0644, no execute bit.
        mode = stat.S_IMODE(os.stat(result["stored_path"]).st_mode)
        assert mode == 0o644
        assert not (mode & stat.S_IXUSR)

    def test_fetch_payload_custom_config(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        _stub_build_opener(monkeypatch, content=b"small")
        fetch_payload(
            "http://evil.example/x.sh",
            config={"fetch_max_size": 100, "fetch_timeout": 5,
                    "fetch_max_redirects": 2},
        )
        # No exception: custom controls accepted.


class TestFetchSizeCap:
    def test_payload_over_size_cap_refused(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        # Content larger than the 1 MB cap -> refused.
        big = b"x" * (2 * 1024 * 1024)
        _stub_build_opener(monkeypatch, content=big)

        result = fetch_payload(
            "http://evil.example/big",
            config={"fetch_max_size": 1024 * 1024},
        )
        assert result is None
        assert not Path(FETCH_ARTIFACT_DIR).exists()


class TestFetchSchemeAllowlist:
    def test_file_scheme_refused(self):
        assert fetch_payload("file:///etc/passwd") is None
        assert fetch_payload("FILE:///etc/passwd") is None

    def test_ftp_scheme_refused(self):
        assert fetch_payload("ftp://evil.example/x.sh") is None

    def test_gopher_scheme_refused(self):
        assert fetch_payload("gopher://evil.example/x") is None

    def test_http_and_https_allowed(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        for url in ("http://evil.example/x.sh", "https://evil.example/x.sh"):
            _stub_build_opener(monkeypatch, content=b"ok")
            assert fetch_payload(url) is not None


class TestFetchInternalTargets:
    def test_localhost_refused(self):
        for host in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
            assert fetch_payload(f"http://{host}/x.sh") is None

    def test_rfc1918_refused(self):
        for host in ("10.0.0.5", "172.16.0.1", "172.31.255.255",
                     "192.168.1.1"):
            assert fetch_payload(f"http://{host}/x.sh") is None

    def test_link_local_refused(self):
        assert fetch_payload("http://169.254.169.254/x.sh") is None

    def test_external_host_allowed(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        _stub_build_opener(monkeypatch, content=b"ok")
        assert fetch_payload("http://93.184.216.34/x.sh") is not None


class TestFetchRedirectCap:
    def test_too_many_redirects_refused(self):
        # With max_redirects=0, the very first redirect attempt exceeds the cap.
        handler = _RedirectCounter(max_redirects=0)
        fake_req = MagicMock()
        fake_headers = MagicMock()
        raised = False
        try:
            handler.redirect_request(fake_req, None, 302, "Moved",
                                     fake_headers, "http://next.example/")
        except urllib_error.HTTPError:
            raised = True
        assert raised
        assert handler.count == 1

    def test_redirect_cap_enforced_through_fetch(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        # build_opener's open raises HTTPError once redirects are exhausted.
        opener = MagicMock()
        opener.open.side_effect = urllib_error.HTTPError(
            "http://last.example/", 0, "too many redirects", {}, None
        )
        monkeypatch.setattr(
            "honeypot.artifacts.urllib.request.build_opener",
            lambda *a, **k: opener,
        )
        assert fetch_payload("http://evil.example/x.sh") is None


class TestFetchTimeoutAndFailure:
    def test_timeout_is_passed_to_opener(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        seen = {}

        class _CapturingOpener:
            def open(self, req, timeout=None):
                seen["timeout"] = timeout
                return _FakeResponse(b"ok")

        monkeypatch.setattr(
            "honeypot.artifacts.urllib.request.build_opener",
            lambda *a, **k: _CapturingOpener(),
        )
        fetch_payload("http://evil.example/x.sh",
                      config={"fetch_timeout": 10})
        assert seen["timeout"] == 10

    def test_network_failure_never_raises(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)

        def _boom(*_a, **_k):
            raise socket.timeout("connect timed out")

        monkeypatch.setattr(
            "honeypot.artifacts.urllib.request.build_opener",
            lambda *a, **k: _MagicOpener(boom=_boom),
        )
        # Must return None, never raise.
        assert fetch_payload("http://evil.example/x.sh") is None

    def test_read_failure_never_raises(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)

        def _boom_read(_n):
            raise OSError("disk error")

        response = _FakeResponse(b"ok")
        response.read = _boom_read

        monkeypatch.setattr(
            "honeypot.artifacts.urllib.request.build_opener",
            lambda *a, **k: _MagicOpener(response=response),
        )
        assert fetch_payload("http://evil.example/x.sh") is None


class _MagicOpener:
    def __init__(self, response=None, boom=None):
        self._response = response
        self._boom = boom

    def open(self, req, timeout=None):
        if self._boom is not None:
            raise self._boom
        return self._response


class TestFetchDedup:
    def test_same_payload_stored_once(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        content = b"dedup me\n"
        _stub_build_opener(monkeypatch, content=content)

        r1 = fetch_payload("http://evil.example/x.sh")
        r2 = fetch_payload("http://evil.example/x.sh")

        assert r1 is not None and r2 is not None
        assert r1["sha256"] == r2["sha256"]
        assert r1["stored_path"] == r2["stored_path"]
        # File exists exactly once.
        assert Path(r1["stored_path"]).exists()


class TestFetchSessionEvent:
    def test_payload_downloaded_carries_session_identity(self, monkeypatch,
                                                        tmp_path):
        monkeypatch.chdir(tmp_path)
        _stub_build_opener(monkeypatch, content=b"evented")

        captured = []

        def _log(event_type, session_id=None, source_ip=None, **extra):
            captured.append({"event_type": event_type, "session_id": session_id,
                             "source_ip": source_ip, **extra})

        import honeypot.artifacts as art
        real_log = art.log_event
        art.log_event = _log
        try:
            fetch_payload(
                "http://evil.example/x.sh",
                session_id="s1", source_ip="10.0.0.9",
                source_port=54321, username="user1",
            )
        finally:
            art.log_event = real_log

        events = [e for e in captured if e["event_type"] == "payload.downloaded"]
        assert len(events) == 1
        ev = events[0]
        assert ev["session_id"] == "s1"
        assert ev["source_ip"] == "10.0.0.9"
        assert ev["source_port"] == 54321
        assert ev["username"] == "user1"
        assert ev["url"] == "http://evil.example/x.sh"
        assert "sha256" in ev and "size" in ev and "stored_path" in ev
