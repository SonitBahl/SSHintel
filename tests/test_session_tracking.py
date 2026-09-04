"""Tests for session tracking."""
import time

import pytest

from honeypot.session import Session
from honeypot.fs import create_filesystem


class TestSessionCreation:
    """Verify sessions are created with required fields."""

    def test_has_session_id(self):
        s = Session(source_ip='127.0.0.1')
        assert isinstance(s.session_id, str)
        assert len(s.session_id) > 0

    def test_has_source_ip(self):
        s = Session(source_ip='10.0.0.1')
        assert s.source_ip == '10.0.0.1'

    def test_has_connected_at(self):
        s = Session(source_ip='127.0.0.1')
        assert isinstance(s.connected_at, str)
        assert 'T' in s.connected_at

    def test_has_fake_filesystem(self):
        s = Session(source_ip='127.0.0.1')
        assert isinstance(s.fake_filesystem, dict)
        assert 'etc' in s.fake_filesystem
        assert 'home' in s.fake_filesystem

    def test_has_cwd(self):
        s = Session(source_ip='127.0.0.1')
        assert s.cwd == '/home/user1'

    def test_disconnected_at_initially_none(self):
        s = Session(source_ip='127.0.0.1')
        assert s.disconnected_at is None

    def test_duration_initially_none(self):
        s = Session(source_ip='127.0.0.1')
        assert s.duration_seconds is None


class TestSessionUniqueness:
    """Verify each session is unique."""

    def test_different_ids(self):
        s1 = Session(source_ip='127.0.0.1')
        s2 = Session(source_ip='127.0.0.1')
        assert s1.session_id != s2.session_id

    def test_different_filesystems(self):
        s1 = Session(source_ip='127.0.0.1')
        s2 = Session(source_ip='127.0.0.1')
        assert s1.fake_filesystem is not s2.fake_filesystem


class TestAuthenticationTracking:
    """Verify authentication attempts are tracked."""

    def test_record_auth_attempt(self):
        s = Session(source_ip='127.0.0.1')
        s.record_auth_attempt('root')
        assert s.username == 'root'

    def test_record_auth_success(self):
        s = Session(source_ip='127.0.0.1')
        s.record_auth_success('user1')
        assert s.username == 'user1'
        assert s.authenticated_at is not None
        assert s.auth_result == 'success'

    def test_record_auth_failure(self):
        s = Session(source_ip='127.0.0.1')
        s.record_auth_attempt('admin')
        s.record_auth_failure()
        assert s.username == 'admin'
        assert s.auth_result == 'failure'

    def test_multiple_auth_attempts_same_session(self):
        s = Session(source_ip='127.0.0.1')
        s.record_auth_attempt('root')
        s.record_auth_attempt('admin')
        s.record_auth_success('user1')
        # Username should reflect the latest
        assert s.username == 'user1'
        assert s.auth_result == 'success'


class TestSessionFinalization:
    """Verify session finalization is idempotent and calculates duration."""

    def test_finalize_sets_disconnected_at(self):
        s = Session(source_ip='127.0.0.1')
        s.finalize()
        assert s.disconnected_at is not None

    def test_finalize_sets_duration(self):
        s = Session(source_ip='127.0.0.1')
        s.finalize()
        assert s.duration_seconds is not None
        assert s.duration_seconds >= 0

    def test_finalize_is_idempotent(self):
        s = Session(source_ip='127.0.0.1')
        result1 = s.finalize()
        result2 = s.finalize()
        assert result1 is True
        assert result2 is False

    def test_duration_increases_with_time(self):
        s1 = Session(source_ip='127.0.0.1')
        s1.finalize()
        time.sleep(0.1)
        s2 = Session(source_ip='127.0.0.1')
        s2.finalize()
        assert s2.duration_seconds > s1.duration_seconds

    def test_disconnect_reason_preserved(self):
        s = Session(source_ip='127.0.0.1')
        s.disconnect_reason = 'idle_timeout'
        s.finalize()
        assert s.disconnect_reason == 'idle_timeout'


class TestSessionFields:
    """Verify session has all required fields."""

    def test_has_session_id(self):
        s = Session(source_ip='127.0.0.1')
        assert hasattr(s, 'session_id')

    def test_has_source_ip(self):
        s = Session(source_ip='127.0.0.1')
        assert hasattr(s, 'source_ip')

    def test_has_connected_at(self):
        s = Session(source_ip='127.0.0.1')
        assert hasattr(s, 'connected_at')

    def test_has_authenticated_at(self):
        s = Session(source_ip='127.0.0.1')
        assert hasattr(s, 'authenticated_at')

    def test_has_disconnected_at(self):
        s = Session(source_ip='127.0.0.1')
        assert hasattr(s, 'disconnected_at')

    def test_has_username(self):
        s = Session(source_ip='127.0.0.1')
        assert hasattr(s, 'username')

    def test_has_auth_result(self):
        s = Session(source_ip='127.0.0.1')
        assert hasattr(s, 'auth_result')

    def test_has_duration_seconds(self):
        s = Session(source_ip='127.0.0.1')
        assert hasattr(s, 'duration_seconds')

    def test_has_fake_filesystem(self):
        s = Session(source_ip='127.0.0.1')
        assert hasattr(s, 'fake_filesystem')

    def test_has_cwd(self):
        s = Session(source_ip='127.0.0.1')
        assert hasattr(s, 'cwd')

    def test_has_disconnect_reason(self):
        s = Session(source_ip='127.0.0.1')
        assert hasattr(s, 'disconnect_reason')
