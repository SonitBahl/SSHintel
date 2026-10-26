"""Tests for network.attempt events (Commit 11).

Simulated ssh/scp record attacker intent without opening a socket.
Missing targets emit the existing usage string and no event.
"""

import socket

import pytest

from honeypot.logger import build_event
from honeypot.session import Session
from honeypot.shell import FakeShell


@pytest.fixture
def shell():
    session = Session(source_ip="10.0.0.9")
    session.source_port = 54321
    session.username = "user1"
    return FakeShell(session)


@pytest.fixture
def events(monkeypatch):
    captured = []

    def _log(event_type, session_id=None, source_ip=None, **extra):
        record = {
            "event_type": event_type,
            "session_id": session_id,
            "source_ip": source_ip,
        }
        record.update(extra)
        captured.append(record)

    monkeypatch.setattr("honeypot.shell.log_event", _log)
    return captured


def _net_events(events):
    return [e for e in events if e.get("event_type") == "network.attempt"]


class TestSshNetworkAttempt:
    def test_ssh_emits_attempt(self, shell, events):
        out = shell.execute("ssh root@10.0.0.8")
        assert out == "ssh: connect to host 10.0.0.8 port 22: Connection refused"
        net = _net_events(events)
        assert len(net) == 1
        assert net[0]["target"] == "10.0.0.8"
        assert net[0]["port"] == 22
        assert net[0]["protocol"] == "ssh"

    def test_ssh_dash_p_port(self, shell, events):
        out = shell.execute("ssh -p 2222 user@evil.example")
        assert out == "ssh: connect to host evil.example port 22: Connection refused"
        net = _net_events(events)
        assert net[0]["target"] == "evil.example"
        assert net[0]["port"] == 2222
        assert net[0]["protocol"] == "ssh"

    def test_ssh_missing_target_emits_nothing(self, shell, events):
        out = shell.execute("ssh")
        assert out.startswith("usage: ssh")
        assert _net_events(events) == []


class TestScpNetworkAttempt:
    def test_scp_emits_attempt_and_strips_path(self, shell, events):
        out = shell.execute("scp file user@10.0.0.8:/tmp/x")
        assert out == "ssh: connect to host 10.0.0.8:/tmp/x port 22: Connection refused"
        net = _net_events(events)
        assert len(net) == 1
        assert net[0]["target"] == "10.0.0.8"
        assert net[0]["port"] == 22
        assert net[0]["protocol"] == "scp"

    def test_scp_dash_P_port(self, shell, events):
        shell.execute("scp -P 2200 notes.txt user@box:/tmp/")
        net = _net_events(events)
        assert net[0]["target"] == "box"
        assert net[0]["port"] == 2200
        assert net[0]["protocol"] == "scp"

    def test_scp_missing_target_emits_nothing(self, shell, events):
        out = shell.execute("scp file")
        assert out.startswith("usage: scp")
        assert _net_events(events) == []


class TestNoRealNetwork:
    def test_socket_is_never_created(self, shell, events, monkeypatch):
        def boom(*_args, **_kwargs):
            raise AssertionError("socket.socket must not be called")

        monkeypatch.setattr(socket, "socket", boom)
        out = shell.execute("ssh attacker@10.0.0.8")
        assert "Connection refused" in out
        assert len(_net_events(events)) == 1

    def test_ordinary_commands_do_not_emit_network(self, shell, events):
        shell.execute("pwd")
        shell.execute("ls")
        shell.execute("echo hello")
        assert _net_events(events) == []


class TestEventFields:
    def test_events_carry_session_identity(self, shell, events):
        shell.execute("ssh user1@10.1.2.3")
        event = _net_events(events)[0]
        assert event["session_id"] == shell.session.session_id
        assert event["source_ip"] == "10.0.0.9"
        assert event["source_port"] == 54321
        assert event["username"] == "user1"

    def test_dotted_name_passthrough(self):
        event = build_event(
            "network.attempt",
            session_id="s1",
            source_ip="10.0.0.9",
            target="10.0.0.8",
            port=22,
            protocol="ssh",
        )
        assert event["event_type"] == "network.attempt"
        assert event.get("legacy_event_type") is None
        assert event["target"] == "10.0.0.8"
        assert event["port"] == 22
        assert event["protocol"] == "ssh"
