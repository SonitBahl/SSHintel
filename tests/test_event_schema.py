"""Tests for event schema versioning, ``event_id``, and v1->v2 migration."""
import sqlite3

import pytest

from honeypot.logger import build_event
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
# Event building
# ---------------------------------------------------------------------------


class TestEventFields:
    def test_event_has_event_id_and_schema_version(self):
        event = build_event(
            event_type="connect",
            session_id="abc-123",
            source_ip="10.0.0.1",
        )
        assert "event_id" in event
        assert "schema_version" in event
        assert event["schema_version"] == str(SCHEMA_VERSION)

    def test_event_id_is_uuid4(self):
        import uuid as uuid_module

        event = build_event(
            event_type="connect",
            session_id="abc",
            source_ip="10.0.0.1",
        )
        uuid_module.UUID(event["event_id"], version=4)

    def test_event_ids_are_unique(self):
        ids = {
            build_event(
                event_type="connect", session_id="abc", source_ip="10.0.0.1"
            )["event_id"]
            for _ in range(50)
        }
        assert len(ids) == 50

    def test_db_meta_schema_version_matches_constant(self, store):
        ver = store._conn.execute(
            "SELECT value FROM meta WHERE key='schema_version'"
        ).fetchone()[0]
        assert ver == str(SCHEMA_VERSION)


# ---------------------------------------------------------------------------
# Event storage
# ---------------------------------------------------------------------------


class TestEventStorage:
    def test_logged_event_stores_event_id_and_schema_version(self, store):
        event = {
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "connect",
            "session_id": "abc",
            "source_ip": "10.0.0.1",
            "event_id": "eee-111",
            "schema_version": str(SCHEMA_VERSION),
        }
        store.log_event(event)
        row = store._conn.execute(
            "SELECT event_id, schema_version FROM events WHERE session_id='abc'"
        ).fetchone()
        assert row == ("eee-111", str(SCHEMA_VERSION))

    def test_get_session_events_includes_new_columns(self, store):
        store.log_event({
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "connect",
            "session_id": "abc",
            "source_ip": "10.0.0.1",
            "event_id": "eee-111",
            "schema_version": str(SCHEMA_VERSION),
        })
        events = store.get_session_events("abc")
        assert events[0]["event_id"] == "eee-111"
        assert events[0]["schema_version"] == str(SCHEMA_VERSION)

    def test_get_events_after_includes_new_columns(self, store):
        store.log_event({
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "connect",
            "session_id": "abc",
            "source_ip": "10.0.0.1",
            "event_id": "eee-111",
            "schema_version": str(SCHEMA_VERSION),
        })
        events = store.get_events_after(0)
        assert events[0]["event_id"] == "eee-111"
        assert events[0]["schema_version"] == str(SCHEMA_VERSION)


# ---------------------------------------------------------------------------
# v1 -> v2 migration
# ---------------------------------------------------------------------------


class TestV1ToV2Migration:
    def _make_v1_db(self, path):
        """Create a pre-v2 database without ``event_id``/``schema_version``
        columns, populated with two rows and schema_version = 1 in ``meta``."""
        conn = sqlite3.connect(path)
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
            "INSERT INTO events (timestamp, event_type, session_id, source_ip, "
            "source_port, username, command, cwd, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("2026-01-01T00:01:00Z", "command", "s1", "10.0.0.1", None, "root",
             "ls", "/", None),
        )
        conn.execute(
            "INSERT INTO meta(key, value) VALUES('schema_version', '1')"
        )
        conn.commit()
        conn.close()

    def test_migration_adds_columns_and_preserves_data(self, tmp_db):
        self._make_v1_db(tmp_db)

        # Confirm the fixture is a genuine v1 DB (no v2/v3 columns yet).
        conn = sqlite3.connect(tmp_db)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(events)")}
        conn.close()
        assert "event_id" not in cols
        assert "schema_version" not in cols
        assert "legacy_event_type" not in cols

        store = TelemetryStore(tmp_db)
        store.open()

        # Migration added the v2/v3 columns.
        cols = {row[1] for row in store._conn.execute("PRAGMA table_info(events)")}
        assert "event_id" in cols
        assert "schema_version" in cols
        assert "legacy_event_type" in cols

        # Schema version bumped to 2.
        ver = store._conn.execute(
            "SELECT value FROM meta WHERE key='schema_version'"
        ).fetchone()[0]
        assert ver == str(SCHEMA_VERSION)

        # Existing data preserved.
        assert store.count_events() == 2
        rows = store._conn.execute(
            "SELECT event_type, session_id FROM events ORDER BY id"
        ).fetchall()
        assert rows == [("connect", "s1"), ("command", "s1")]
        store.close()

    def test_migration_is_idempotent(self, tmp_db):
        self._make_v1_db(tmp_db)
        store = TelemetryStore(tmp_db)
        store.open()
        store.open()  # second open re-runs _create_schema + migration
        cols = {row[1] for row in store._conn.execute("PRAGMA table_info(events)")}
        assert "event_id" in cols
        assert "schema_version" in cols
        assert "legacy_event_type" in cols
        assert store.count_events() == 2
        store.close()
