"""Tests for the dotted event-type namespace (Commit 06).

Verifies that flat v1/v2 event-type names are translated to dotted v3
namespace names, that the original flat name is preserved in
``legacy_event_type``, and that both store queries and the dashboard
accept either form.
"""

import sqlite3

import pytest

from honeypot.logger import build_event
from honeypot.telemetry_store import (
    EVENT_TYPES,
    TelemetryStore,
    normalize_event_type,
    SCHEMA_VERSION,
)


# ---------------------------------------------------------------------------
# Mapping table
# ---------------------------------------------------------------------------


class TestEventTypeMapping:
    """The EVENT_TYPES map is complete and consistent."""

    def test_all_known_types_mapped(self):
        assert EVENT_TYPES == {
            "connect": "session.started",
            "auth_attempt": "auth.attempted",
            "auth_success": "auth.succeeded",
            "auth_failure": "auth.failed",
            "command": "command.executed",
            "disconnect": "session.disconnected",
            "tarpit": "session.tarpit",
            "connection_rejected": "session.rejected",
        }

    def test_no_flat_name_maps_to_itself(self):
        for flat, dotted in EVENT_TYPES.items():
            assert flat != dotted

    def test_no_collisions(self):
        dotted = list(EVENT_TYPES.values())
        assert len(dotted) == len(set(dotted))


# ---------------------------------------------------------------------------
# normalize_event_type
# ---------------------------------------------------------------------------


class TestNormalizeEventType:
    def test_known_flat_name_translated(self):
        assert normalize_event_type("connect") == "session.started"
        assert normalize_event_type("command") == "command.executed"
        assert normalize_event_type("auth_success") == "auth.succeeded"

    def test_dotted_name_passthrough(self):
        assert normalize_event_type("session.started") == "session.started"
        assert normalize_event_type("command.executed") == "command.executed"

    def test_unknown_name_passthrough(self):
        assert normalize_event_type("weird.custom.event") == "weird.custom.event"


# ---------------------------------------------------------------------------
# build_event
# ---------------------------------------------------------------------------


class TestBuildEventDottedNames:
    def test_connect(self):
        event = build_event(
            event_type="connect",
            session_id="s1",
            source_ip="10.0.0.1",
        )
        assert event["event_type"] == "session.started"
        assert event["legacy_event_type"] == "connect"

    def test_command(self):
        event = build_event(
            event_type="command",
            session_id="s1",
            source_ip="10.0.0.1",
            command="ls",
        )
        assert event["event_type"] == "command.executed"
        assert event["legacy_event_type"] == "command"

    def test_auth_success(self):
        event = build_event(
            event_type="auth_success",
            session_id="s1",
            source_ip="10.0.0.1",
            username="root",
        )
        assert event["event_type"] == "auth.succeeded"
        assert event["legacy_event_type"] == "auth_success"

    def test_schema_version_is_3(self):
        event = build_event("connect", "s1", "10.0.0.1")
        assert event["schema_version"] == str(SCHEMA_VERSION)

    def test_event_id_is_uuid4(self):
        import uuid as uuid_module

        event = build_event("connect", "s1", "10.0.0.1")
        uuid_module.UUID(event["event_id"], version=4)


# ---------------------------------------------------------------------------
# TelemetryStore log_event normalizes names
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path):
    return str(tmp_path / "test.db")


@pytest.fixture
def store(tmp_db):
    s = TelemetryStore(tmp_db)
    s.open()
    yield s
    s.close()


class TestStoreNormalization:
    def test_flat_name_normalized_on_insert(self, store):
        store.log_event({
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "connect",
            "session_id": "s1",
            "source_ip": "10.0.0.1",
        })
        row = store._conn.execute(
            "SELECT event_type, legacy_event_type FROM events WHERE session_id='s1'"
        ).fetchone()
        assert row == ("session.started", "connect")

    def test_dotted_name_passthrough(self, store):
        store.log_event({
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "session.started",
            "session_id": "s1",
            "source_ip": "10.0.0.1",
        })
        row = store._conn.execute(
            "SELECT event_type, legacy_event_type FROM events WHERE session_id='s1'"
        ).fetchone()
        assert row == ("session.started", None)

    def test_legacy_event_type_is_queryable(self, store):
        store.log_event({
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "command",
            "session_id": "s1",
            "source_ip": "10.0.0.1",
            "command": "ls",
        })
        rows = store._conn.execute(
            "SELECT event_type FROM events WHERE legacy_event_type='command'"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0][0] == "command.executed"

    def test_schema_version_recorded(self, store):
        ver = store._conn.execute(
            "SELECT value FROM meta WHERE key='schema_version'"
        ).fetchone()[0]
        assert ver == str(SCHEMA_VERSION)

    def test_migration_legacy_event_type_column_added(self, tmp_db):
        # Build a genuine v1 DB (no event_id/schema_version/legacy_event_type).
        conn = sqlite3.connect(tmp_db)
        conn.execute(
            "CREATE TABLE events ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "timestamp TEXT NOT NULL,"
            "event_type TEXT NOT NULL,"
            "session_id TEXT,"
            "source_ip TEXT,"
            "source_port INTEGER,"
            "username TEXT,"
            "command TEXT,"
            "cwd TEXT,"
            "metadata TEXT"
            ")"
        )
        conn.execute(
            "CREATE TABLE sessions ("
            "session_id TEXT PRIMARY KEY,"
            "source_ip TEXT,"
            "username TEXT,"
            "started_at TEXT,"
            "ended_at TEXT,"
            "duration REAL,"
            "status TEXT,"
            "disconnect_reason TEXT"
            ")"
        )
        conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute(
            "INSERT INTO events (timestamp, event_type, session_id, source_ip, "
            "source_port, username, command, cwd, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("2026-01-01T00:00:00Z", "connect", "s1", "10.0.0.1", None, None,
             None, None, None),
        )
        conn.execute(
            "INSERT INTO meta(key, value) VALUES('schema_version', '1')"
        )
        conn.commit()
        conn.close()

        store = TelemetryStore(tmp_db)
        store.open()

        cols = {
            row[1]
            for row in store._conn.execute("PRAGMA table_info(events)")
        }
        assert "legacy_event_type" in cols
        assert store.count_events() == 1
        store.close()