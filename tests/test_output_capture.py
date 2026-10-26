"""Tests for bounded command output capture (Commit 12).

The ``command.executed`` event carries ``output_preview`` (capped at
``output_preview_chars``, default 500) and ``output_bytes``. Output is
truncated with an explicit marker so the telemetry store never grows
unbounded. Simulated ssh/scp from Commit 11 is untouched; no real socket is
opened anywhere here.
"""

import sys
from unittest.mock import MagicMock

import pytest

# handlers.py imports paramiko at module load; stub it so the module is
# importable in this environment without a real SSH library.
sys.modules.setdefault("paramiko", MagicMock())
sys.modules.setdefault("paramiko.ssh_exception", MagicMock())

from honeypot.config import load_config  # noqa: E402
from honeypot.handlers import _output_preview  # noqa: E402
from honeypot.logger import build_event  # noqa: E402
from honeypot.session import Session  # noqa: E402


class TestConfigDefault:
    def test_output_preview_chars_defaults_to_500(self):
        settings = load_config(cli={})
        assert settings["output_preview_chars"] == 500

    def test_output_preview_chars_from_cli(self):
        settings = load_config(cli={"output_preview_chars": 100})
        assert settings["output_preview_chars"] == 100

    def test_output_preview_chars_must_be_positive_int(self):
        with pytest.raises(Exception):
            load_config(cli={"output_preview_chars": -5})
        with pytest.raises(Exception):
            load_config(cli={"output_preview_chars": "not-an-int"})


class TestOutputPreview:
    def test_under_limit_returned_as_is(self):
        assert _output_preview("hello world", 500) == "hello world"

    def test_exactly_at_limit_returned_as_is(self):
        text = "a" * 500
        assert _output_preview(text, 500) == text

    def test_over_limit_truncated_with_marker(self):
        text = "a" * 1000
        preview = _output_preview(text, 10)
        assert len(preview) <= 10 + len("\n... <output truncated>")
        assert preview.startswith("a" * 10)
        assert preview.endswith("\n... <output truncated>")

    def test_empty_output(self):
        assert _output_preview("", 500) == ""

    def test_none_output(self):
        assert _output_preview(None, 500) == ""

    def test_zero_limit(self):
        assert _output_preview("anything", 0) == ""


class TestEventFields:
    def test_command_event_carries_output_preview_and_bytes(self):
        event = build_event(
            "command",
            session_id="s1",
            source_ip="10.0.0.9",
            source_port=54321,
            username="user1",
            command="ls -la",
            cwd="/home/user1",
            output_preview="total 0\n",
            output_bytes=9,
        )
        assert event["event_type"] == "command.executed"
        assert event["output_preview"] == "total 0\n"
        assert event["output_bytes"] == 9
        assert event["command"] == "ls -la"

    def test_output_preview_none_is_omitted(self):
        event = build_event("command", session_id="s1", output_preview=None)
        assert "output_preview" not in event


class TestEmulatedShellOutputCapture:
    """Drive emulated_shell with a fake channel to prove capture works end to
    end without opening a real socket."""

    class FakeChannel:
        def __init__(self, input_bytes):
            self._data = iter(bytes([b]) for b in input_bytes)
            self.sent = []
            self.timeout_set = False

        def settimeout(self, value):
            self.timeout_set = True

        def recv(self, _size):
            try:
                return next(self._data)
            except StopIteration:
                return b""

        def send(self, data):
            self.sent.append(data)

        def close(self):
            pass

    def _run_command(self, cmd_line, config=None):
        from honeypot.handlers import emulated_shell

        session = Session(source_ip="10.0.0.9")
        session.source_port = 54321
        session.username = "user1"
        channel = self.FakeChannel(cmd_line.encode() + b"\r")
        captured = []

        def _log(event_type, session_id=None, source_ip=None, **extra):
            record = {"event_type": event_type, "session_id": session_id,
                      "source_ip": source_ip}
            record.update(extra)
            captured.append(record)

        import honeypot.handlers as handlers_module
        handlers_module.log_event = _log
        emulated_shell(channel, session, config=config)
        return captured, channel

    def test_output_preview_and_bytes_recorded(self):
        captured, _ = self._run_command("echo hello")
        events = [e for e in captured if e.get("event_type") == "command"]
        assert len(events) == 1
        ev = events[0]
        assert ev["command"] == "echo hello"
        assert "output_preview" in ev
        assert "output_bytes" in ev
        assert ev["output_bytes"] > 0

    def test_huge_output_truncated_to_cap(self):
        # A long line of 'x' echoed back produces output far over the 500 cap.
        long_text = "x" * 2000
        captured, channel = self._run_command(f"echo {long_text}")
        events = [e for e in captured if e.get("event_type") == "command"]
        assert len(events) == 1
        ev = events[0]
        assert ev["output_bytes"] == len(long_text)  # echo returns the text as-is
        preview = ev["output_preview"]
        assert len(preview) <= 500 + len("\n... <output truncated>")
        assert preview.endswith("\n... <output truncated>")
        # No unbounded growth stored.
        assert ev["output_preview"] != ev.get("command")

    def test_custom_cap_honoured(self):
        long_text = "z" * 1000
        captured, _ = self._run_command(f"echo {long_text}",
                                        config={"output_preview_chars": 50})
        events = [e for e in captured if e.get("event_type") == "command"]
        ev = events[0]
        preview = ev["output_preview"]
        assert len(preview) <= 50 + len("\n... <output truncated>")
        assert preview.endswith("\n... <output truncated>")

