"""Tests for the SQLite telemetry store."""
import json
import os
import sqlite3
import tempfile
import threading
from pathlib import Path

import pytest

from honeypot.telemetry_store import TelemetryStore, SCHEMA_VERSION


@pytest.fixture
def tmp_db(tmp_path):
    """Return a path to a temporary SQLite database for each test."""
    return str(tmp_path / "test.db")


@pytest.fixture
def store(tmp_db):
    """Return an opened TelemetryStore backed by a temporary database."""
    s = TelemetryStore(tmp_db)
    s.open()
    yield s
    s.close()


# ---------------------------------------------------------------------------
# Database initialization
# ---------------------------------------------------------------------------


class TestDatabaseInitialization:
    def test_creates_database_file(self, tmp_db):
        s = TelemetryStore(tmp_db)
        s.open()
        assert Path(tmp_db).exists()
        s.close()

    def test_creates_parent_directory(self, tmp_path):
        db = str(tmp_path / "subdir" / "nested.db")
        s = TelemetryStore(db)
        s.open()
        assert Path(db).exists()
        s.close()

    def test_creates_schema(self, store):
        tables = {
            row[0]
            for row in store._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert {"events", "sessions", "meta"}.issubset(tables)

    def test_schema_version_recorded(self, store):
        ver = store._conn.execute(
            "SELECT value FROM meta WHERE key='schema_version'"
        ).fetchone()[0]
        assert ver == str(SCHEMA_VERSION)

    def test_creates_indexes(self, store):
        indexes = {
            row[0]
            for row in store._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
        }
        for expected in (
            "idx_events_timestamp",
            "idx_events_event_type",
            "idx_events_session_id",
            "idx_events_source_ip",
            "idx_events_username",
            "idx_sessions_source_ip",
            "idx_sessions_started_at",
        ):
            assert expected in indexes

    def test_open_is_idempotent(self, store):
        store.open()  # second call should be a no-op
        assert store.is_open

    def test_is_open_false_before_open(self, tmp_db):
        s = TelemetryStore(tmp_db)
        assert not s.is_open

    def test_is_open_false_after_close(self, store):
        store.close()
        assert not store.is_open


# ---------------------------------------------------------------------------
# Event insertion
# ---------------------------------------------------------------------------


class TestEventInsertion:
    def test_insert_connect_event(self, store):
        store.log_event({
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "connect",
            "session_id": "abc",
            "source_ip": "10.0.0.1",
        })
        row = store._conn.execute("SELECT event_type, session_id, source_ip FROM events").fetchone()
        assert row == ("connect", "abc", "10.0.0.1")

    def test_insert_auth_attempt_event(self, store):
        store.log_event({
            "timestamp": "2026-01-01T00:00:01Z",
            "event_type": "auth_attempt",
            "session_id": "abc",
            "source_ip": "10.0.0.1",
            "username": "root",
            "auth_method": "password",
            "password": "toor",
        })
        row = store._conn.execute(
            "SELECT event_type, username, command FROM events WHERE session_id='abc'"
        ).fetchone()
        assert row[0] == "auth_attempt"
        assert row[1] == "root"
        assert row[2] is None

    def test_insert_command_event(self, store):
        store.log_event({
            "timestamp": "2026-01-01T00:00:02Z",
            "event_type": "command",
            "session_id": "abc",
            "source_ip": "10.0.0.1",
            "username": "root",
            "command": "ls -la",
            "cwd": "/home/root",
        })
        row = store._conn.execute(
            "SELECT command, cwd FROM events WHERE event_type='command'"
        ).fetchone()
        assert row == ("ls -la", "/home/root")

    def test_insert_disconnect_event(self, store):
        store.log_event({
            "timestamp": "2026-01-01T00:01:00Z",
            "event_type": "disconnect",
            "session_id": "abc",
            "source_ip": "10.0.0.1",
            "username": "root",
            "duration_seconds": 60.5,
            "reason": None,
        })
        row = store._conn.execute(
            "SELECT event_type, username FROM events WHERE event_type='disconnect'"
        ).fetchone()
        assert row == ("disconnect", "root")

    def test_insert_connection_rejected_event(self, store):
        store.log_event({
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "connection_rejected",
            "source_ip": "10.0.0.2",
            "reason": "connection_limit",
        })
        row = store._conn.execute(
            "SELECT event_type, source_ip, metadata FROM events WHERE event_type='connection_rejected'"
        ).fetchone()
        assert row[0] == "connection_rejected"
        assert row[1] == "10.0.0.2"
        meta = json.loads(row[2])
        assert meta["reason"] == "connection_limit"

    def test_insert_tarpit_event(self, store):
        store.log_event({
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "tarpit",
            "session_id": "abc",
            "source_ip": "10.0.0.1",
        })
        row = store._conn.execute(
            "SELECT event_type FROM events WHERE event_type='tarpit'"
        ).fetchone()
        assert row[0] == "tarpit"

    def test_multiple_events_preserve_values(self, store):
        events = [
            {"timestamp": f"2026-01-01T00:00:0{i}Z", "event_type": "command",
             "session_id": "s1", "source_ip": "10.0.0.1", "command": f"cmd{i}"}
            for i in range(5)
        ]
        for e in events:
            store.log_event(e)
        rows = store._conn.execute(
            "SELECT command FROM events WHERE session_id='s1' ORDER BY id"
        ).fetchall()
        assert [r[0] for r in rows] == ["cmd0", "cmd1", "cmd2", "cmd3", "cmd4"]

    def test_metadata_stored_as_json(self, store):
        store.log_event({
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "command",
            "session_id": "abc",
            "source_ip": "10.0.0.1",
            "command": "ls",
            "extra_field": "should_go_to_metadata",
        })
        raw = store._conn.execute(
            "SELECT metadata FROM events WHERE event_type='command'"
        ).fetchone()[0]
        meta = json.loads(raw)
        assert meta["extra_field"] == "should_go_to_metadata"

    def test_null_session_id_allowed(self, store):
        store.log_event({
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "connection_rejected",
            "source_ip": "10.0.0.5",
        })
        row = store._conn.execute(
            "SELECT session_id FROM events WHERE source_ip='10.0.0.5'"
        ).fetchone()
        assert row[0] is None


# ---------------------------------------------------------------------------
# Session recording
# ---------------------------------------------------------------------------


class TestSessionRecording:
    def test_record_connect(self, store):
        store.record_session_connect("s1", "10.0.0.1", "2026-01-01T00:00:00Z")
        row = store._conn.execute(
            "SELECT session_id, source_ip, started_at FROM sessions"
        ).fetchone()
        assert row == ("s1", "10.0.0.1", "2026-01-01T00:00:00Z")

    def test_record_finalize(self, store):
        store.record_session_connect("s1", "10.0.0.1", "2026-01-01T00:00:00Z")
        store.record_session_finalize(
            "s1", "root", "2026-01-01T00:01:00Z", 60.0, "success", None
        )
        row = store._conn.execute(
            "SELECT username, ended_at, duration, status FROM sessions WHERE session_id='s1'"
        ).fetchone()
        assert row == ("root", "2026-01-01T00:01:00Z", 60.0, "success")

    def test_finalize_without_connect(self, store):
        store.record_session_finalize(
            "orphan", "root", "2026-01-01T00:01:00Z", 5.0, "failure", "auth_timeout"
        )
        row = store._conn.execute(
            "SELECT status, disconnect_reason FROM sessions WHERE session_id='orphan'"
        ).fetchone()
        assert row == ("failure", "auth_timeout")


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------


class TestQueries:
    @pytest.fixture
    def populated(self, store):
        """Insert a realistic mix of events and sessions."""
        events = [
            {"timestamp": "2026-01-01T00:00:00Z", "event_type": "connect",
             "session_id": "s1", "source_ip": "10.0.0.1"},
            {"timestamp": "2026-01-01T00:00:01Z", "event_type": "auth_attempt",
             "session_id": "s1", "source_ip": "10.0.0.1", "username": "root"},
            {"timestamp": "2026-01-01T00:00:02Z", "event_type": "auth_success",
             "session_id": "s1", "source_ip": "10.0.0.1", "username": "root"},
            {"timestamp": "2026-01-01T00:00:10Z", "event_type": "command",
             "session_id": "s1", "source_ip": "10.0.0.1", "username": "root",
             "command": "ls"},
            {"timestamp": "2026-01-01T00:00:15Z", "event_type": "command",
             "session_id": "s1", "source_ip": "10.0.0.1", "username": "root",
             "command": "whoami"},
            {"timestamp": "2026-01-01T00:01:00Z", "event_type": "disconnect",
             "session_id": "s1", "source_ip": "10.0.0.1", "username": "root"},
            {"timestamp": "2026-01-01T00:02:00Z", "event_type": "connect",
             "session_id": "s2", "source_ip": "10.0.0.2"},
            {"timestamp": "2026-01-01T00:02:01Z", "event_type": "auth_attempt",
             "session_id": "s2", "source_ip": "10.0.0.2", "username": "admin"},
            {"timestamp": "2026-01-01T00:02:02Z", "event_type": "auth_failure",
             "session_id": "s2", "source_ip": "10.0.0.2", "username": "admin"},
            {"timestamp": "2026-01-01T00:02:03Z", "event_type": "disconnect",
             "session_id": "s2", "source_ip": "10.0.0.2", "username": "admin"},
            {"timestamp": "2026-01-01T00:03:00Z", "event_type": "connection_rejected",
             "source_ip": "10.0.0.3", "reason": "connection_limit"},
        ]
        for e in events:
            store.log_event(e)
        store.record_session_connect("s1", "10.0.0.1", "2026-01-01T00:00:00Z")
        store.record_session_finalize("s1", "root", "2026-01-01T00:01:00Z", 60.0, "success", None)
        store.record_session_connect("s2", "10.0.0.2", "2026-01-01T00:02:00Z")
        store.record_session_finalize("s2", "admin", "2026-01-01T00:02:03Z", 3.0, "failure", None)
        return store

    def test_count_sessions(self, populated):
        assert populated.count_sessions() == 2

    def test_unique_ips(self, populated):
        assert populated.unique_ips() == 3

    def test_count_events(self, populated):
        assert populated.count_events() == 11

    def test_total_auth_attempts(self, populated):
        assert populated.total_auth_attempts() == 2

    def test_successful_auths(self, populated):
        assert populated.successful_auths() == 1

    def test_failed_auth_attempts(self, populated):
        assert populated.failed_auth_attempts() == 1

    def test_total_commands(self, populated):
        assert populated.total_commands() == 2

    def test_top_commands(self, populated):
        rows = populated.top_commands()
        assert len(rows) == 2
        assert rows[0]["command"] in ("ls", "whoami")
        assert rows[0]["count"] == 1

    def test_top_commands_with_duplicates(self, store):
        for cmd in ("ls", "ls", "whoami"):
            store.log_event({"timestamp": "2026-01-01T00:00:00Z", "event_type": "command",
                            "session_id": "s1", "source_ip": "10.0.0.1", "command": cmd})
        rows = store.top_commands()
        assert rows[0] == {"command": "ls", "count": 2}
        assert rows[1] == {"command": "whoami", "count": 1}

    def test_top_usernames(self, populated):
        rows = populated.top_usernames()
        assert len(rows) == 2

    def test_top_source_ips(self, populated):
        rows = populated.top_source_ips()
        assert rows[0]["source_ip"] == "10.0.0.1"
        assert rows[0]["count"] == 6

    def test_get_session_events(self, populated):
        rows = populated.get_session_events("s1")
        assert len(rows) == 6
        types = [r["event_type"] for r in rows]
        assert "connect" in types
        assert "command" in types
        assert "disconnect" in types

    def test_get_events_by_ip(self, populated):
        rows = populated.get_events_by_ip("10.0.0.2")
        assert len(rows) == 4
        for r in rows:
            assert r["source_ip"] == "10.0.0.2"

    def test_get_recent_events(self, populated):
        rows = populated.get_recent_events(limit=3)
        assert len(rows) == 3

    def test_get_recent_sessions(self, populated):
        rows = populated.get_recent_sessions()
        assert len(rows) == 2

    def test_events_in_range(self, populated):
        # Range 00:00:00 - 00:00:30 includes 5 events (connect, auth_attempt,
        # auth_success, 2 commands). The disconnect at 00:01:00 is outside.
        rows = populated.events_in_range("2026-01-01T00:00:00Z", "2026-01-01T00:00:30Z")
        assert len(rows) == 5

    def test_sessions_in_range(self, populated):
        rows = populated.sessions_in_range("2026-01-01T00:00:00Z", "2026-01-01T00:01:30Z")
        assert len(rows) == 1

    def test_empty_store_queries(self, store):
        assert store.count_sessions() == 0
        assert store.unique_ips() == 0
        assert store.count_events() == 0
        assert store.top_commands() == []
        assert store.get_recent_events() == []


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


class TestConcurrency:
    def test_concurrent_event_writes(self, store):
        errors = []

        def writer(session_id, n):
            try:
                for i in range(n):
                    store.log_event({
                        "timestamp": f"2026-01-01T00:00:0{i}Z",
                        "event_type": "command",
                        "session_id": session_id,
                        "source_ip": "10.0.0.1",
                        "command": f"cmd{i}",
                    })
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(f"s{i}", 20)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert store.count_events() == 100

    def test_concurrent_session_recording(self, store):
        def recorder(i):
            sid = f"session-{i}"
            store.record_session_connect(sid, f"10.0.0.{i}", "2026-01-01T00:00:00Z")
            store.record_session_finalize(sid, f"user{i}", "2026-01-01T00:01:00Z", 60.0, "success", None)

        threads = [threading.Thread(target=recorder, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert store.count_sessions() == 10


# ---------------------------------------------------------------------------
# Failure handling
# ---------------------------------------------------------------------------


class TestFailureHandling:
    def test_query_on_closed_store_returns_defaults(self, tmp_db):
        s = TelemetryStore(tmp_db)
        # Never opened
        assert s.count_sessions() == 0
        assert s.count_events() == 0
        assert s.top_commands() == []
        assert s.get_recent_events() == []

    def test_log_event_on_closed_store_does_not_raise(self, tmp_db):
        s = TelemetryStore(tmp_db)
        s.log_event({"timestamp": "t", "event_type": "connect", "session_id": "s1"})

    def test_close_is_idempotent(self, store):
        store.close()
        store.close()  # second close should not raise

    def test_record_session_on_closed_store_does_not_raise(self, tmp_db):
        s = TelemetryStore(tmp_db)
        s.record_session_connect("s1", "10.0.0.1", "2026-01-01T00:00:00Z")
        s.record_session_finalize("s1", "root", "2026-01-01T00:01:00Z", 60.0, "success", None)


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------


class TestSecurity:
    def test_sql_injection_in_event_does_not_alter_schema(self, store):
        malicious = "'; DROP TABLE events; --"
        store.log_event({
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "command",
            "session_id": malicious,
            "source_ip": "10.0.0.1",
            "command": malicious,
        })
        # Table should still exist
        count = store._conn.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]
        assert count == 1

    def test_sql_injection_in_query_does_not_drop_table(self, store):
        store.log_event({
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "command",
            "session_id": "s1",
            "source_ip": "10.0.0.1",
            "command": "ls",
        })
        # Attempt injection via query parameter
        store.get_events_by_ip("10.0.0.1' OR '1'='1")
        # Table intact
        assert store.count_events() == 1

    def test_attacker_command_stored_as_data(self, store):
        store.log_event({
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "command",
            "session_id": "s1",
            "source_ip": "10.0.0.1",
            "command": "' OR 1=1; DROP TABLE sessions; --",
        })
        row = store._conn.execute(
            "SELECT command FROM events WHERE session_id='s1'"
        ).fetchone()
        assert row[0] == "' OR 1=1; DROP TABLE sessions; --"
        # sessions table still exists
        assert store.count_sessions() == 0

    def test_metadata_with_special_chars(self, store):
        store.log_event({
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "command",
            "session_id": "s1",
            "source_ip": "10.0.0.1",
            "command": "echo hello",
            "injected": "'; DELETE FROM events; --",
        })
        assert store.count_events() == 1
