"""Tests for event serialization and JSONL format."""
import json

import pytest

from honeypot.logger import build_event, serialize_event


class TestSerializeEvent:
    """Verify serialization produces valid JSON."""

    def test_returns_string(self):
        event = build_event('connect', session_id='abc', source_ip='127.0.0.1')
        result = serialize_event(event)
        assert isinstance(result, str)

    def test_is_valid_json(self):
        event = build_event('command', session_id='abc', source_ip='127.0.0.1', command='ls')
        result = serialize_event(event)
        parsed = json.loads(result)
        assert parsed['event_type'] == 'command'

    def test_json_has_double_quotes(self):
        event = build_event('connect', session_id='abc', source_ip='127.0.0.1')
        result = serialize_event(event)
        assert '"' in result
        assert result.startswith('{')
        assert result.endswith('}')

    def test_special_characters_escaped(self):
        event = build_event(
            'command',
            session_id='abc',
            source_ip='127.0.0.1',
            command='echo "; rm -rf /"',
        )
        result = serialize_event(event)
        parsed = json.loads(result)
        assert parsed['command'] == 'echo "; rm -rf /"'

    def test_unicode_characters_preserved(self):
        event = build_event(
            'command',
            session_id='abc',
            source_ip='127.0.0.1',
            command='cat café.txt',
        )
        result = serialize_event(event)
        parsed = json.loads(result)
        assert 'café' in parsed['command']


class TestJSONLLines:
    """Verify each event occupies exactly one JSON line."""

    def test_single_line(self):
        event = build_event('connect', session_id='abc', source_ip='127.0.0.1')
        result = serialize_event(event)
        lines = result.strip().split('\n')
        assert len(lines) == 1

    def test_no_trailing_newline_in_serialized(self):
        event = build_event('connect', session_id='abc', source_ip='127.0.0.1')
        result = serialize_event(event)
        assert not result.endswith('\n')

    def test_multiple_events_are_separate_lines(self):
        events = [
            build_event('connect', session_id='abc', source_ip='127.0.0.1'),
            build_event('command', session_id='abc', source_ip='127.0.0.1', command='ls'),
            build_event('disconnect', session_id='abc', source_ip='127.0.0.1'),
        ]
        lines = [serialize_event(e) for e in events]
        for line in lines:
            parsed = json.loads(line)
            assert 'event_type' in parsed


class TestMalformedInput:
    """Verify unusual commands don't break serialization."""

    def test_empty_command(self):
        event = build_event('command', session_id='abc', source_ip='127.0.0.1', command='')
        result = serialize_event(event)
        json.loads(result)

    def test_command_with_null_bytes(self):
        event = build_event('command', session_id='abc', source_ip='127.0.0.1', command='cat \x00file')
        result = serialize_event(event)
        json.loads(result)

    def test_command_with_newlines(self):
        event = build_event('command', session_id='abc', source_ip='127.0.0.1', command='echo \nhello')
        result = serialize_event(event)
        json.loads(result)

    def test_command_with_backslashes(self):
        event = build_event('command', session_id='abc', source_ip='127.0.0.1', command='echo \\n')
        result = serialize_event(event)
        json.loads(result)

    def test_very_long_command(self):
        long_cmd = 'A' * 10000
        event = build_event('command', session_id='abc', source_ip='127.0.0.1', command=long_cmd)
        result = serialize_event(event)
        parsed = json.loads(result)
        assert parsed['command'] == long_cmd

    def test_none_values_excluded(self):
        event = build_event('connect', session_id='abc', source_ip='127.0.0.1', username=None)
        result = serialize_event(event)
        parsed = json.loads(result)
        assert 'username' not in parsed
