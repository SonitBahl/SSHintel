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


class TestSessionInvestigation:
    """Verify the session investigation API and page."""

    def test_session_page_returns_200(self, client):
        response = client.get("/session/sess-001")
        assert response.status_code == 200
        assert b"Session Investigation" in response.data

    def test_session_page_404_for_unknown(self, client):
        response = client.get("/session/nonexistent")
        assert response.status_code == 404

    def test_session_page_404_for_empty_db(self, empty_client):
        response = empty_client.get("/session/anything")
        assert response.status_code == 404

    def test_api_session_returns_data(self, client):
        response = client.get("/api/session/sess-001")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "session" in data
        assert "events" in data
        assert data["session"]["session_id"] == "sess-001"
        assert data["session"]["source_ip"] == "10.0.0.1"
        assert data["session"]["username"] == "root"

    def test_api_session_events_chronological(self, client):
        response = client.get("/api/session/sess-001")
        data = json.loads(response.data)
        events = data["events"]
        assert len(events) >= 4
        timestamps = [e["timestamp"] for e in events]
        assert timestamps == sorted(timestamps)

    def test_api_session_only_returns_own_events(self, client):
        response = client.get("/api/session/sess-001")
        data = json.loads(response.data)
        for event in data["events"]:
            assert event["session_id"] == "sess-001"

    def test_api_session_404_for_unknown(self, client):
        response = client.get("/api/session/nonexistent")
        assert response.status_code == 404
        data = json.loads(response.data)
        assert data["error"] == "not_found"

    def test_api_session_404_for_empty_db(self, empty_client):
        response = empty_client.get("/api/session/anything")
        assert response.status_code == 404

    def test_session_summary_fields(self, client):
        response = client.get("/api/session/sess-001")
        data = json.loads(response.data)
        session = data["session"]
        assert session["session_id"] == "sess-001"
        assert session["source_ip"] == "10.0.0.1"
        assert session["username"] == "root"
        assert session["duration"] == 300.0
        assert session["status"] == "closed"

    def test_session_command_count(self, client):
        response = client.get("/api/session/sess-001")
        data = json.loads(response.data)
        commands = [e for e in data["events"] if e["event_type"] == "command"]
        assert len(commands) == 2
        assert commands[0]["command"] == "ls -la"
        assert commands[1]["command"] == "cat /etc/passwd"

    def test_session_with_failed_auth(self, client):
        response = client.get("/api/session/sess-002")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["session"]["status"] == "closed"
        auth_events = [e for e in data["events"] if e["event_type"] == "auth_failure"]
        assert len(auth_events) == 1

    def test_session_events_no_disconnect(self, tmp_path):
        """Sessions without a disconnect event should still render."""
        db_path = tmp_path / "nodc.db"
        store = TelemetryStore(db_path)
        store.open()
        store.log_event({
            "timestamp": "2026-09-05T10:00:00.000000Z",
            "event_type": "connect",
            "session_id": "sess-nodc",
            "source_ip": "10.0.0.5",
        })
        store.log_event({
            "timestamp": "2026-09-05T10:00:05.000000Z",
            "event_type": "command",
            "session_id": "sess-nodc",
            "source_ip": "10.0.0.5",
            "username": "root",
            "command": "whoami",
            "cwd": "/root",
        })
        store.close()
        app = create_app(db_path)
        app.config["TESTING"] = True
        with app.test_client() as c:
            response = c.get("/api/session/sess-nodc")
            assert response.status_code == 200
            data = json.loads(response.data)
            assert len(data["events"]) == 2
            # Session is synthesized from events when no finalize record exists
            assert data["session"] is not None
            assert data["session"]["session_id"] == "sess-nodc"
            assert data["session"]["source_ip"] == "10.0.0.5"
            assert data["session"]["username"] == "root"
            assert data["session"]["status"] == "unknown"

    def test_session_xss_in_command(self, tmp_path):
        """Attacker-controlled commands must be stored as data, not executed."""
        db_path = tmp_path / "sess-xss.db"
        store = TelemetryStore(db_path)
        store.open()
        store.log_event({
            "timestamp": "2026-09-05T10:00:00.000000Z",
            "event_type": "command",
            "session_id": "sess-xss2",
            "source_ip": "10.0.0.99",
            "username": "<script>alert(1)</script>",
            "command": "'; DROP TABLE events; --",
            "cwd": "/tmp",
        })
        store.close()
        app = create_app(db_path)
        app.config["TESTING"] = True
        with app.test_client() as c:
            response = c.get("/api/session/sess-xss2")
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["events"][0]["command"] == "'; DROP TABLE events; --"
            assert data["events"][0]["username"] == "<script>alert(1)</script>"
            # Verify the table still exists (injection didn't work)
            resp2 = c.get("/api/metrics")
            assert resp2.status_code == 200

    def test_session_not_found_page_message(self, client):
        response = client.get("/session/does-not-exist")
        assert response.status_code == 404


class TestLiveTelemetry:
    """Verify the live telemetry API endpoint for incremental updates."""

    def test_events_after_returns_new_events(self, client):
        """Events with id > given id should be returned."""
        # The fixture has events with ids 1-7
        response = client.get("/api/events/after/3")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "events" in data
        assert "latest_id" in data
        # All returned events should have id > 3
        for event in data["events"]:
            assert event["id"] > 3

    def test_events_after_returns_empty_when_up_to_date(self, client):
        """When no new events exist, empty list is returned."""
        response = client.get("/api/events/after/9999")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["events"] == []

    def test_events_after_includes_id_field(self, client):
        """Returned events should include the id field for tracking."""
        response = client.get("/api/events/after/0")
        data = json.loads(response.data)
        if data["events"]:
            assert "id" in data["events"][0]

    def test_events_after_latest_id(self, client):
        """latest_id should reflect the highest event id."""
        response = client.get("/api/events/after/0")
        data = json.loads(response.data)
        assert data["latest_id"] > 0

    def test_events_after_limit_clamped(self, client):
        """Limit parameter should be clamped to sane range."""
        response = client.get("/api/events/after/0?limit=10000")
        assert response.status_code == 200
        data = json.loads(response.data)
        # Should not return more than 500 events
        assert len(data["events"]) <= 500

    def test_events_after_no_database(self, empty_client):
        """When no database exists, return empty events with latest_id 0."""
        response = empty_client.get("/api/events/after/0")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["events"] == []
        assert data["latest_id"] == 0

    def test_events_after_invalid_id(self, client):
        """Non-integer event_id should return 404 (Flask route mismatch)."""
        response = client.get("/api/events/after/abc")
        assert response.status_code == 404

    def test_incremental_update_no_duplicates(self, tmp_path):
        """Incremental polling should not return already-seen events."""
        db_path = tmp_path / "incr.db"
        store = TelemetryStore(db_path)
        store.open()
        # Insert initial events
        for i in range(3):
            store.log_event({
                "timestamp": f"2026-09-05T10:00:0{i}.000000Z",
                "event_type": "command",
                "session_id": "sess-001",
                "source_ip": "10.0.0.1",
                "command": f"cmd{i}",
            })
        store.close()

        app = create_app(db_path)
        app.config["TESTING"] = True
        with app.test_client() as c:
            # First poll: get all events
            resp1 = c.get("/api/events/after/0")
            data1 = json.loads(resp1.data)
            assert len(data1["events"]) == 3
            latest = data1["latest_id"]

            # Second poll: no new events
            resp2 = c.get(f"/api/events/after/{latest}")
            data2 = json.loads(resp2.data)
            assert len(data2["events"]) == 0

    def test_new_event_appears_after_insert(self, tmp_path):
        """After inserting a new event, it should appear in the next poll."""
        db_path = tmp_path / "newevt.db"
        store = TelemetryStore(db_path)
        store.open()
        store.log_event({
            "timestamp": "2026-09-05T10:00:00.000000Z",
            "event_type": "connect",
            "session_id": "sess-001",
            "source_ip": "10.0.0.1",
        })
        store.close()

        app = create_app(db_path)
        app.config["TESTING"] = True
        with app.test_client() as c:
            # Get initial state
            resp1 = c.get("/api/events/after/0")
            data1 = json.loads(resp1.data)
            assert len(data1["events"]) == 1
            latest = data1["latest_id"]

            # Insert a new event directly into the database
            store2 = TelemetryStore(db_path)
            store2.open()
            store2.log_event({
                "timestamp": "2026-09-05T10:00:05.000000Z",
                "event_type": "command",
                "session_id": "sess-001",
                "source_ip": "10.0.0.1",
                "command": "whoami",
            })
            store2.close()

            # Poll again: new event should appear
            resp2 = c.get(f"/api/events/after/{latest}")
            data2 = json.loads(resp2.data)
            assert len(data2["events"]) == 1
            assert data2["events"][0]["command"] == "whoami"
