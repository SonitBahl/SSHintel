"""Tests for filesystem.read/.write/.create/.delete events (Commit 10).

Successful file operations emit dotted filesystem events with path and
estimated bytes. Failed operations (ENOENT, is-a-directory) emit nothing.
"""

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


def _fs_events(events):
    return [e for e in events if str(e.get("event_type", "")).startswith("filesystem.")]


class TestCreateEvents:
    def test_mkdir_emits_create(self, shell, events):
        assert shell.execute("mkdir /tmp/newdir") == ""
        fs = _fs_events(events)
        assert len(fs) == 1
        assert fs[0]["event_type"] == "filesystem.create"
        assert fs[0]["path"] == "/tmp/newdir"
        assert fs[0]["bytes"] == 0

    def test_touch_new_file_emits_create(self, shell, events):
        assert shell.execute("touch /tmp/created.txt") == ""
        fs = _fs_events(events)
        assert len(fs) == 1
        assert fs[0]["event_type"] == "filesystem.create"
        assert fs[0]["path"] == "/tmp/created.txt"
        assert fs[0]["bytes"] == 0

    def test_mkdir_missing_parent_emits_nothing(self, shell, events):
        out = shell.execute("mkdir /no/such/dir")
        assert "No such file or directory" in out
        assert _fs_events(events) == []

    def test_mkdir_existing_emits_nothing(self, shell, events):
        out = shell.execute("mkdir /tmp")
        assert "File exists" in out
        assert _fs_events(events) == []


class TestWriteEvents:
    def test_echo_redirect_new_file_emits_create_and_write(self, shell, events):
        content = "hello world"
        assert shell.execute('echo hello world > /tmp/out.txt') == ""
        fs = _fs_events(events)
        assert [e["event_type"] for e in fs] == [
            "filesystem.create",
            "filesystem.write",
        ]
        assert fs[0]["path"] == "/tmp/out.txt"
        assert fs[1]["path"] == "/tmp/out.txt"
        assert fs[1]["bytes"] == len(content)

    def test_echo_redirect_existing_file_emits_write_only(self, shell, events):
        shell.execute("touch /tmp/out.txt")
        events.clear()
        assert shell.execute('echo payload > /tmp/out.txt') == ""
        fs = _fs_events(events)
        assert [e["event_type"] for e in fs] == ["filesystem.write"]
        assert fs[0]["path"] == "/tmp/out.txt"
        assert fs[0]["bytes"] == len("payload")

    def test_touch_existing_file_emits_write(self, shell, events):
        shell.execute("touch /tmp/out.txt")
        events.clear()
        assert shell.execute("touch /tmp/out.txt") == ""
        fs = _fs_events(events)
        assert [e["event_type"] for e in fs] == ["filesystem.write"]
        assert fs[0]["path"] == "/tmp/out.txt"
        assert fs[0]["bytes"] == 0

    def test_echo_redirect_missing_parent_emits_nothing(self, shell, events):
        out = shell.execute("echo hi > /no/such/file.txt")
        assert "No such file or directory" in out
        assert _fs_events(events) == []


class TestDeleteEvents:
    def test_rm_file_emits_delete_with_size(self, shell, events):
        shell.execute("echo abc > /tmp/gone.txt")
        events.clear()
        assert shell.execute("rm /tmp/gone.txt") == ""
        fs = _fs_events(events)
        assert len(fs) == 1
        assert fs[0]["event_type"] == "filesystem.delete"
        assert fs[0]["path"] == "/tmp/gone.txt"
        assert fs[0]["bytes"] == 3

    def test_rm_missing_emits_nothing(self, shell, events):
        out = shell.execute("rm /tmp/missing.txt")
        assert "No such file or directory" in out
        assert _fs_events(events) == []

    def test_rm_force_missing_emits_nothing(self, shell, events):
        assert shell.execute("rm -f /tmp/missing.txt") == ""
        assert _fs_events(events) == []


class TestReadEvents:
    def test_cat_emits_read(self, shell, events):
        content = shell.execute("cat /etc/hostname")
        fs = _fs_events(events)
        assert len(fs) == 1
        assert fs[0]["event_type"] == "filesystem.read"
        assert fs[0]["path"] == "/etc/hostname"
        assert fs[0]["bytes"] == len(content)

    def test_cat_missing_emits_nothing(self, shell, events):
        out = shell.execute("cat /tmp/nope.txt")
        assert "No such file or directory" in out
        assert _fs_events(events) == []

    def test_cat_directory_emits_nothing(self, shell, events):
        out = shell.execute("cat /tmp")
        assert "Is a directory" in out
        assert _fs_events(events) == []

    def test_head_successful_read_emits_read(self, shell, events):
        shell.execute("head /etc/hostname")
        fs = _fs_events(events)
        assert [e["event_type"] for e in fs] == ["filesystem.read"]
        assert fs[0]["path"] == "/etc/hostname"

    def test_cat_multiple_files_emits_one_read_each(self, shell, events):
        shell.execute("cat /etc/hostname /etc/hosts")
        fs = _fs_events(events)
        assert [e["event_type"] for e in fs] == [
            "filesystem.read",
            "filesystem.read",
        ]
        assert [e["path"] for e in fs] == ["/etc/hostname", "/etc/hosts"]


class TestEventFields:
    def test_events_carry_session_identity(self, shell, events):
        shell.execute("mkdir /tmp/tracked")
        event = _fs_events(events)[0]
        assert event["session_id"] == shell.session.session_id
        assert event["source_ip"] == "10.0.0.9"
        assert event["source_port"] == 54321
        assert event["username"] == "user1"

    def test_dotted_name_passthrough_has_no_legacy_alias(self):
        event = build_event(
            "filesystem.read",
            session_id="s1",
            source_ip="10.0.0.9",
            path="/tmp/x",
            bytes=4,
        )
        assert event["event_type"] == "filesystem.read"
        assert event.get("legacy_event_type") is None
        assert event["path"] == "/tmp/x"
        assert event["bytes"] == 4

    def test_shell_execute_does_not_emit_command_events(self, shell, events):
        shell.execute("mkdir /tmp/x")
        shell.execute("echo hi > /tmp/x/f.txt")
        shell.execute("cat /tmp/x/f.txt")
        shell.execute("rm /tmp/x/f.txt")
        assert all(
            e["event_type"].startswith("filesystem.") for e in events
        )
        assert {e["event_type"] for e in events} == {
            "filesystem.create",
            "filesystem.write",
            "filesystem.read",
            "filesystem.delete",
        }
