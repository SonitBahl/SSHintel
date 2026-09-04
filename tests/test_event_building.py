"""Tests for event building."""
import pytest

from honeypot.logger import build_event


class TestBuildEvent:
    """Verify event construction produces the required fields."""

    def test_connect_event(self):
        event = build_event(
            event_type='connect',
            session_id='abc-123',
            source_ip='127.0.0.1',
        )
        assert event['event_type'] == 'connect'
        assert event['session_id'] == 'abc-123'
        assert event['source_ip'] == '127.0.0.1'
        assert 'timestamp' in event

    def test_auth_attempt_event(self):
        event = build_event(
            event_type='auth_attempt',
            session_id='abc',
            source_ip='10.0.0.1',
            username='root',
            password='toor',
            auth_method='password',
        )
        assert event['event_type'] == 'auth_attempt'
        assert event['username'] == 'root'
        assert event['password'] == 'toor'
        assert event['auth_method'] == 'password'

    def test_auth_success_event(self):
        event = build_event(
            event_type='auth_success',
            session_id='abc',
            source_ip='10.0.0.1',
            username='user1',
        )
        assert event['event_type'] == 'auth_success'
        assert event['username'] == 'user1'

    def test_auth_failure_event(self):
        event = build_event(
            event_type='auth_failure',
            session_id='abc',
            source_ip='10.0.0.1',
            username='admin',
        )
        assert event['event_type'] == 'auth_failure'
        assert event['username'] == 'admin'

    def test_command_event(self):
        event = build_event(
            event_type='command',
            session_id='abc',
            source_ip='10.0.0.1',
            username='user1',
            command='ls -la',
            cwd='/home/user1',
        )
        assert event['event_type'] == 'command'
        assert event['command'] == 'ls -la'
        assert event['cwd'] == '/home/user1'

    def test_disconnect_event(self):
        event = build_event(
            event_type='disconnect',
            session_id='abc',
            source_ip='10.0.0.1',
            username='user1',
            auth_result='success',
            duration_seconds=43.21,
        )
        assert event['event_type'] == 'disconnect'
        assert event['duration_seconds'] == 43.21
        assert event['auth_result'] == 'success'

    def test_tarpit_event(self):
        event = build_event(
            event_type='tarpit',
            session_id='abc',
            source_ip='10.0.0.1',
        )
        assert event['event_type'] == 'tarpit'

    def test_connection_rejected_event(self):
        event = build_event(
            event_type='connection_rejected',
            session_id='abc',
            source_ip='10.0.0.1',
            reason='connection_limit',
        )
        assert event['event_type'] == 'connection_rejected'
        assert event['reason'] == 'connection_limit'

    def test_extra_fields_preserved(self):
        event = build_event(
            event_type='command',
            session_id='abc',
            source_ip='127.0.0.1',
            custom_field='custom_value',
        )
        assert event['custom_field'] == 'custom_value'

    def test_timestamp_is_included(self):
        event = build_event(
            event_type='connect',
            session_id='abc',
            source_ip='127.0.0.1',
        )
        assert 'timestamp' in event
