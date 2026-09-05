"""Tests for the SSHintel web dashboard."""
from __future__ import annotations

import json

import pytest

from dashboard.app import create_app
from honeypot.telemetry_store import TelemetryStore


@pytest.fixture()
def empty_client(tmp_path):
    """Create a test client with an empty database (no telemetry)."""
    db_path = tmp_path / "empty.db"
    app = create_app(db_path)
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture()
def client(tmp_path):
    """Create a test client with a fresh temporary database."""
    db_path = tmp_path / "test.db"
    store = TelemetryStore(db_path)
    store.open()

    store.log_event({
        "timestamp": "2026-09-05T10:00:00.000000Z",
        "event_type": "connect",
        "session_id": "sess-001",
        "source_ip": "10.0.0.1",
    })
    store.log_event({
        "timestamp": "2026-09-05T10:00:01.000000Z",
        "event_type": "auth_attempt",
        "session_id": "sess-001",
        "source_ip": "10.0.0.1",
        "username": "root",
    })
    store.log_event({
        "timestamp": "2026-09-05T10:00:02.000000Z",
        "event_type": "auth_success",
        "session_id": "sess-001",
        "source_ip": "10.0.0.1",
        "username": "root",
    })
    store.log_event({
        "timestamp": "2026-09-05T10:00:10.000000Z",
        "event_type": "command",
        "session_id": "sess-001",
        "source_ip": "10.0.0.1",
        "username": "root",
        "command": "ls -la",
        "cwd": "/root",
    })
    store.log_event({
        "timestamp": "2026-09-05T10:00:15.000000Z",
        "event_type": "command",
        "session_id": "sess-001",
        "source_ip": "10.0.0.1",
        "username": "root",
        "command": "cat /etc/passwd",
        "cwd": "/root",
    })
    store.log_event({
        "timestamp": "2026-09-05T10:01:00.000000Z",
        "event_type": "auth_attempt",
        "session_id": "sess-002",
        "source_ip": "10.0.0.2",
        "username": "admin",
    })
    store.log_event({
        "timestamp": "2026-09-05T10:01:05.000000Z",
        "event_type": "auth_failure",
        "session_id": "sess-002",
        "source_ip": "10.0.0.2",
        "username": "admin",
    })
    store.record_session_finalize(
        "sess-001", "root", "2026-09-05T10:05:00.000000Z", 300.0, "closed", None
    )
    store.record_session_finalize(
        "sess-002", "admin", "2026-09-05T10:01:10.000000Z", 10.0, "closed", None
    )
    store.close()

    app = create_app(db_path)
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


class TestDashboardStarts:
    """Verify the dashboard initializes correctly."""

    def test_index_returns_200(self, client):
        response = client.get("/")
        assert response.status_code == 200

    def test_index_contains_app_name(self, client):
        response = client.get("/")
        assert b"SSHintel" in response.data

    def test_empty_db_index_returns_200(self, empty_client):
        response = empty_client.get("/")
        assert response.status_code == 200


class TestDashboardMetrics:
    """Verify KPI metrics are returned correctly."""

    def test_metrics_endpoint(self, client):
        response = client.get("/api/metrics")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "sessions" in data
        assert "unique_ips" in data
        assert "auth_attempts" in data
        assert "auth_successes" in data
        assert "auth_failures" in data
        assert "commands" in data

    def test_metrics_values(self, client):
        response = client.get("/api/metrics")
        data = json.loads(response.data)
        assert data["sessions"] == 2
        assert data["unique_ips"] == 2
        assert data["auth_attempts"] == 2
        assert data["auth_successes"] == 1
        assert data["auth_failures"] == 1
        assert data["commands"] == 2

    def test_empty_db_metrics(self, empty_client):
        response = empty_client.get("/api/metrics")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["sessions"] == 0
        assert data["unique_ips"] == 0
        assert data["auth_attempts"] == 0
        assert data["commands"] == 0


class TestDashboardTopCommands:
    """Verify top commands ranking."""

    def test_top_commands(self, client):
        response = client.get("/api/top-commands")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data) == 2
        commands = [row["command"] for row in data]
        assert "ls -la" in commands
        assert "cat /etc/passwd" in commands

    def test_top_commands_respects_limit(self, client):
        response = client.get("/api/top-commands?limit=1")
        data = json.loads(response.data)
        assert len(data) == 1

    def test_empty_db_top_commands(self, empty_client):
        response = empty_client.get("/api/top-commands")
        assert json.loads(response.data) == []


class TestDashboardTopIPs:
    """Verify top source IPs."""

    def test_top_ips(self, client):
        response = client.get("/api/top-ips")
        assert response.status_code == 200
        data = json.loads(response.data)
        ips = [row["source_ip"] for row in data]
        assert "10.0.0.1" in ips
        assert "10.0.0.2" in ips


class TestDashboardRecentEvents:
    """Verify recent events endpoint."""

    def test_recent_events(self, client):
        response = client.get("/api/recent-events")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data) > 0
        for event in data:
            assert "timestamp" in event
            assert "event_type" in event

    def test_recent_events_respects_limit(self, client):
        response = client.get("/api/recent-events?limit=3")
        data = json.loads(response.data)
        assert len(data) <= 3


class TestDashboardRecentSessions:
    """Verify recent sessions endpoint."""

    def test_recent_sessions(self, client):
        response = client.get("/api/recent-sessions")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data) == 2
        session_ids = [s["session_id"] for s in data]
        assert "sess-001" in session_ids
        assert "sess-002" in session_ids


class TestDashboardActivity:
    """Verify activity chart data."""

    def test_activity_endpoint(self, client):
        response = client.get("/api/activity")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, list)

    def test_empty_db_activity(self, empty_client):
        response = empty_client.get("/api/activity")
        assert response.status_code == 200
        assert json.loads(response.data) == []


class TestDashboardSecurity:
    """Verify the dashboard handles malicious telemetry safely."""

    @pytest.fixture()
    def xss_client(self, tmp_path):
        db_path = tmp_path / "xss.db"
        store = TelemetryStore(db_path)
        store.open()
        store.log_event({
            "timestamp": "2026-09-05T10:00:00.000000Z",
            "event_type": "command",
            "session_id": "sess-xss",
            "source_ip": "10.0.0.99",
            "username": '<script>alert("xss")</script>',
            "command": '"; DROP TABLE events; --',
            "cwd": "/tmp",
        })
        store.close()
        app = create_app(db_path)
        app.config["TESTING"] = True
        with app.test_client() as client:
            yield client

    def test_xss_payload_stored_as_data(self, xss_client):
        response = xss_client.get("/api/recent-events")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data) == 1
        assert data[0]["command"] == '"; DROP TABLE events; --'

    def test_sql_injection_does_not_alter_schema(self, xss_client):
        response = xss_client.get("/api/metrics")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["commands"] == 1

    def test_xss_in_username(self, xss_client):
        response = xss_client.get("/api/top-usernames")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data) == 1
        assert data[0]["username"] == '<script>alert("xss")</script>'
