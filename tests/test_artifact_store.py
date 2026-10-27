"""Tests for artifact storage, metadata and dedup (Commit 15).

The ``artifacts`` SQLite table tracks payloads as first-class records:
sha256 primary key, size, content_type, first_seen, last_seen, times_seen,
stored_path, kind. Repeat sightings increment ``times_seen`` and update
``last_seen`` while preserving ``first_seen``. Offline — no network.
"""

import tempfile
from pathlib import Path

import pytest

from honeypot.telemetry_store import TelemetryStore


class TestArtifactStore:
    @pytest.fixture
    def store(self):
        db_path = Path(tempfile.mkdtemp()) / "test_artifacts.db"
        store = TelemetryStore(db_path=str(db_path))
        store.open()
        yield store
        store.close()

    def test_table_exists_after_open(self, store):
        rows = store._query_all(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='artifacts'"
        )
        assert len(rows) == 1

    def test_first_sighting_inserts(self, store):
        store.log_artifact(
            sha256="abc123",
            size=1024,
            content_type="application/octet-stream",
            stored_path="data/artifacts/abc123",
            kind="downloaded",
            timestamp="2026-01-01T00:00:00",
        )
        rows = store._query_all(
            "SELECT sha256, size, content_type, first_seen, last_seen, "
            "times_seen, stored_path, kind FROM artifacts"
        )
        assert len(rows) == 1
        r = rows[0]
        assert r == ("abc123", 1024, "application/octet-stream",
                     "2026-01-01T00:00:00", "2026-01-01T00:00:00", 1,
                     "data/artifacts/abc123", "downloaded")

    def test_repeat_sighting_increments_times_seen(self, store):
        store.log_artifact(
            sha256="abc123", size=1024, content_type="application/octet-stream",
            stored_path="data/artifacts/abc123", kind="downloaded",
            timestamp="2026-01-01T00:00:00",
        )
        store.log_artifact(
            sha256="abc123", size=1024, content_type="application/octet-stream",
            stored_path="data/artifacts/abc123", kind="downloaded",
            timestamp="2026-01-02T00:00:00",
        )
        rows = store._query_all(
            "SELECT sha256, first_seen, last_seen, times_seen FROM artifacts"
        )
        assert len(rows) == 1
        assert rows[0][0] == "abc123"
        assert rows[0][1] == "2026-01-01T00:00:00"   # first_seen preserved
        assert rows[0][2] == "2026-01-02T00:00:00"   # last_seen updated
        assert rows[0][3] == 2                       # times_seen incremented

    def test_multiple_artifacts_dedup_independently(self, store):
        store.log_artifact(
            sha256="aaa", size=10, content_type="text/plain",
            stored_path="p/aaa", kind="downloaded",
            timestamp="2026-01-01T00:00:00",
        )
        store.log_artifact(
            sha256="aaa", size=10, content_type="text/plain",
            stored_path="p/aaa", kind="downloaded",
            timestamp="2026-01-02T00:00:00",
        )
        store.log_artifact(
            sha256="bbb", size=20, content_type="text/plain",
            stored_path="p/bbb", kind="downloaded",
            timestamp="2026-01-01T00:00:00",
        )
        rows = store._query_all(
            "SELECT sha256, times_seen FROM artifacts ORDER BY sha256"
        )
        assert len(rows) == 2
        assert rows[0] == ("aaa", 2)
        assert rows[1] == ("bbb", 1)

    def test_log_artifact_returns_new_vs_repeat(self, store):
        assert store.log_artifact(
            sha256="x", size=1, content_type="text/plain",
            stored_path="p/x", kind="downloaded",
            timestamp="2026-01-01T00:00:00",
        ) is True
        assert store.log_artifact(
            sha256="x", size=1, content_type="text/plain",
            stored_path="p/x", kind="downloaded",
            timestamp="2026-01-02T00:00:00",
        ) is False

    def test_no_store_is_noop(self):
        # TelemetryStore with no open connection must not raise.
        store = TelemetryStore()
        assert store.log_artifact(
            sha256="x", size=1, content_type="text/plain",
            stored_path="p/x", kind="downloaded",
            timestamp="2026-01-01T00:00:00",
        ) is False
        store.close()
