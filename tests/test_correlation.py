"""Tests for artifact links and correlation pass (Commit 16).

``artifact_links`` rows tie a payload sha256 to the session/IP that fetched it.
The idempotent correlation pass populates ``entities`` and ``relations``.
Offline — no network, no real sockets.
"""

import tempfile
from pathlib import Path

import pytest

from honeypot.telemetry_store import TelemetryStore


class TestArtifactLinks:
    @pytest.fixture
    def store(self):
        db_path = Path(tempfile.mkdtemp()) / "test_links.db"
        store = TelemetryStore(db_path=str(db_path))
        store.open()
        yield store
        store.close()

    def test_table_exists_after_open(self, store):
        rows = store._query_all(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='artifact_links'"
        )
        assert len(rows) == 1

    def test_link_row_created(self, store):
        store.log_artifact_link(
            sha256="abc123",
            session_id="s1",
            source_ip="10.0.0.9",
            sensor_id="sensor-1",
            url="http://evil.example/x.sh",
            observed_at="2026-01-01T00:00:00",
        )
        rows = store._query_all(
            "SELECT sha256, session_id, source_ip, sensor_id, url, "
            "observed_at FROM artifact_links"
        )
        assert len(rows) == 1
        r = rows[0]
        assert r == ("abc123", "s1", "10.0.0.9", "sensor-1",
                     "http://evil.example/x.sh", "2026-01-01T00:00:00")

    def test_multiple_links_same_sha256(self, store):
        store.log_artifact_link(
            sha256="abc123", session_id="s1", source_ip="10.0.0.9",
            sensor_id="sensor-1", url="http://evil.example/x.sh",
            observed_at="2026-01-01T00:00:00",
        )
        store.log_artifact_link(
            sha256="abc123", session_id="s2", source_ip="10.0.0.8",
            sensor_id="sensor-1", url="http://evil.example/x.sh",
            observed_at="2026-01-02T00:00:00",
        )
        rows = store._query_all(
            "SELECT session_id FROM artifact_links WHERE sha256 = ? "
            "ORDER BY observed_at",
            ("abc123",),
        )
        assert [r[0] for r in rows] == ["s1", "s2"]

    def test_no_store_is_noop(self):
        store = TelemetryStore()
        assert store.log_artifact_link(
            sha256="abc123", session_id="s1",
            source_ip="10.0.0.9", url="http://evil.example/x.sh",
            observed_at="2026-01-01T00:00:00",
        ) is None
        store.close()


class TestCorrelationPass:
    @pytest.fixture
    def store(self):
        db_path = Path(tempfile.mkdtemp()) / "test_corr.db"
        store = TelemetryStore(db_path=str(db_path))
        store.open()
        yield store
        store.close()

    def test_run_correlation_creates_entities_and_relations(self, store):
        store.log_artifact_link(
            sha256="abc123", session_id="s1", source_ip="10.0.0.9",
            sensor_id="sensor-1", url="http://evil.example/x.sh",
            observed_at="2026-01-01T00:00:00",
        )
        processed = store.run_correlation()
        assert processed == 1

        # Entities created.
        ents = store._query_all(
            "SELECT kind, value FROM entities ORDER BY kind, value"
        )
        kinds = {r[0] for r in ents}
        assert "sha256" in kinds
        assert "ip" in kinds
        assert "url" in kinds
        assert "session" in kinds
        assert "sensor" in kinds

        # Relations created.
        rels = store._query_all(
            "SELECT entity_a_id, entity_b_id, kind FROM relations "
            "ORDER BY kind"
        )
        rel_kinds = {r[2] for r in rels}
        assert "fetched" in rel_kinds
        assert "from_url" in rel_kinds
        assert "session_fetched" in rel_kinds
        assert "ip_session" in rel_kinds

    def test_correlation_is_idempotent(self, store):
        store.log_artifact_link(
            sha256="abc123", session_id="s1", source_ip="10.0.0.9",
            sensor_id="sensor-1", url="http://evil.example/x.sh",
            observed_at="2026-01-01T00:00:00",
        )
        store.run_correlation()
        ent_count = store._query_scalar("SELECT COUNT(*) FROM entities")
        rel_count = store._query_scalar("SELECT COUNT(*) FROM relations")
        store.run_correlation()  # second pass should not duplicate
        assert store._query_scalar("SELECT COUNT(*) FROM entities") == ent_count
        assert store._query_scalar("SELECT COUNT(*) FROM relations") == rel_count

    def test_two_sessions_shared_payload_yields_relation(self, store):
        # Two different sessions fetch the same payload.
        store.log_artifact_link(
            sha256="shared123", session_id="s1", source_ip="10.0.0.9",
            sensor_id="sensor-1", url="http://evil.example/payload.sh",
            observed_at="2026-01-01T00:00:00",
        )
        store.log_artifact_link(
            sha256="shared123", session_id="s2", source_ip="10.0.0.8",
            sensor_id="sensor-1", url="http://evil.example/payload.sh",
            observed_at="2026-01-02T00:00:00",
        )
        store.run_correlation()

        # The sha256 entity should have relations from both IPs/sessions.
        ent_rows = store._query_all(
            "SELECT id FROM entities WHERE kind = 'sha256' AND value = ?",
            ("shared123",),
        )
        assert len(ent_rows) == 1
        sha_entity_id = ent_rows[0][0]

        rels = store.get_relations_for_entity(sha_entity_id)
        fetched_rels = [r for r in rels if r["kind"] == "fetched"]
        # Two distinct IPs fetched the same artifact.
        assert len(fetched_rels) >= 2

    def test_get_sessions_by_artifact(self, store):
        store.log_artifact_link(
            sha256="abc123", session_id="s1", source_ip="10.0.0.9",
            sensor_id="sensor-1", url="http://evil.example/x.sh",
            observed_at="2026-01-01T00:00:00",
        )
        store.log_artifact_link(
            sha256="abc123", session_id="s2", source_ip="10.0.0.8",
            sensor_id="sensor-1", url="http://evil.example/x.sh",
            observed_at="2026-01-02T00:00:00",
        )
        store.log_artifact_link(
            sha256="def456", session_id="s1", source_ip="10.0.0.9",
            sensor_id="sensor-1", url="http://evil.example/y.sh",
            observed_at="2026-01-03T00:00:00",
        )
        sessions = store.get_sessions_by_artifact("abc123")
        assert len(sessions) == 2
        session_ids = {s["session_id"] for s in sessions}
        assert session_ids == {"s1", "s2"}

        # Other artifact not included.
        sessions_other = store.get_sessions_by_artifact("def456")
        assert len(sessions_other) == 1
        assert sessions_other[0]["session_id"] == "s1"

    def test_get_artifacts_by_session(self, store):
        store.log_artifact_link(
            sha256="abc123", session_id="s1", source_ip="10.0.0.9",
            sensor_id="sensor-1", url="http://evil.example/x.sh",
            observed_at="2026-01-01T00:00:00",
        )
        store.log_artifact_link(
            sha256="def456", session_id="s1", source_ip="10.0.0.9",
            sensor_id="sensor-1", url="http://evil.example/y.sh",
            observed_at="2026-01-02T00:00:00",
        )
        artifacts = store.get_artifacts_by_session("s1")
        assert len(artifacts) == 2
        sha256s = {a["sha256"] for a in artifacts}
        assert sha256s == {"abc123", "def456"}

    def test_get_artifacts_by_ip(self, store):
        store.log_artifact_link(
            sha256="abc123", session_id="s1", source_ip="10.0.0.9",
            sensor_id="sensor-1", url="http://evil.example/x.sh",
            observed_at="2026-01-01T00:00:00",
        )
        store.log_artifact_link(
            sha256="abc123", session_id="s2", source_ip="10.0.0.9",
            sensor_id="sensor-1", url="http://evil.example/x.sh",
            observed_at="2026-01-02T00:00:00",
        )
        artifacts = store.get_artifacts_by_ip("10.0.0.9")
        assert len(artifacts) == 1
        assert artifacts[0]["sha256"] == "abc123"
        assert artifacts[0]["times_seen"] == 2

    def test_run_correlation_no_store(self):
        store = TelemetryStore()
        assert store.run_correlation() == 0
        store.close()
