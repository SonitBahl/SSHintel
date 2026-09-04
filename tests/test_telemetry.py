"""Tests for structured JSONL security event logging - event building and serialization."""
import json

import pytest

from honeypot.logger import build_event, serialize_event, new_session_id, utc_now_iso


class TestSessionIdGeneration:
    """Verify session IDs are unique and valid."""

    def test_returns_string(self):
        assert isinstance(new_session_id(), str)

    def test_is_uuid_format(self):
        sid = new_session_id()
        parts = sid.split('-')
        assert len(parts) == 5
        assert len(parts[0]) == 8
        assert len(parts[4]) == 12

    def test_unique_per_call(self):
        ids = {new_session_id() for _ in range(100)}
        assert len(ids) == 100


class TestTimestampGeneration:
    """Verify timestamps are valid ISO-8601 UTC."""

    def test_returns_string(self):
        assert isinstance(utc_now_iso(), str)

    def test_contains_t_separator(self):
        assert 'T' in utc_now_iso()

    def test_ends_with_utc_offset(self):
        ts = utc_now_iso()
        assert '+' in ts or 'Z' in ts

    def test_parsable_as_datetime(self):
        from datetime import datetime
        datetime.fromisoformat(utc_now_iso())
