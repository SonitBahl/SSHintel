import json
import unittest
from datetime import datetime, timedelta, timezone

from honeypot import logger


class TestStructuredLogging(unittest.TestCase):
    def test_event_is_serialized_as_valid_json(self):
        event = logger.build_event(
            'command',
            session_id=logger.new_session_id(),
            source_ip='127.0.0.1',
            command='ls',
            cwd='/home/user1',
        )
        line = logger.serialize_event(event)
        parsed = json.loads(line)  # raises if not valid JSON
        self.assertIsInstance(parsed, dict)
        self.assertEqual(parsed['command'], 'ls')

    def test_each_event_is_one_jsonl_line(self):
        event = logger.build_event(
            'connect', session_id=logger.new_session_id(), source_ip='10.0.0.1'
        )
        line = logger.serialize_event(event)
        self.assertNotIn('\n', line)

    def test_required_fields_present_for_all_event_types(self):
        for event_type in (
            'connect',
            'auth_attempt',
            'auth_success',
            'auth_failure',
            'command',
            'disconnect',
            'tarpit',
        ):
            with self.subTest(event_type=event_type):
                event = logger.build_event(
                    event_type, session_id=logger.new_session_id(), source_ip='127.0.0.1'
                )
                self.assertIn('timestamp', event)
                self.assertIn('session_id', event)
                self.assertIn('source_ip', event)
                self.assertEqual(event['event_type'], event_type)

    def test_timestamp_is_valid_iso8601_utc(self):
        event = logger.build_event(
            'connect', session_id=logger.new_session_id(), source_ip='127.0.0.1'
        )
        ts = datetime.fromisoformat(event['timestamp'])
        self.assertEqual(ts.utcoffset(), timedelta(0))  # UTC
        self.assertLessEqual(ts, datetime.now(timezone.utc))

    def test_session_id_is_present_and_string(self):
        sid = logger.new_session_id()
        self.assertIsInstance(sid, str)
        self.assertTrue(sid)

    def test_different_sessions_get_different_ids(self):
        self.assertNotEqual(logger.new_session_id(), logger.new_session_id())

    def test_event_specific_fields_are_preserved(self):
        event = logger.build_event(
            'auth_attempt',
            session_id=logger.new_session_id(),
            source_ip='127.0.0.1',
            username='user1',
            auth_method='password',
            password='pass123',
        )
        self.assertEqual(event['username'], 'user1')
        self.assertEqual(event['auth_method'], 'password')
        self.assertEqual(event['password'], 'pass123')

    def test_malformed_command_does_not_break_serialization(self):
        weird = 'ls\nrm -rf /\x7f\x03"quoted\' \\ ' + 'émoji🙂'
        event = logger.build_event(
            'command',
            session_id=logger.new_session_id(),
            source_ip='127.0.0.1',
            command=weird,
            cwd='/home/user1',
        )
        line = logger.serialize_event(event)
        parsed = json.loads(line)  # must not raise
        self.assertEqual(parsed['command'], weird)

    def test_output_is_real_json_not_python_repr(self):
        event = {'timestamp': 'x', 'event_type': 'command'}
        line = logger.serialize_event(event)
        self.assertNotIn("'", line)  # single quotes would mean a Python repr
        self.assertIn('"event_type":"command"', line)

    def test_none_fields_are_omitted(self):
        event = logger.build_event(
            'command',
            session_id=logger.new_session_id(),
            source_ip='127.0.0.1',
            username=None,
        )
        self.assertNotIn('username', event)


if __name__ == '__main__':
    unittest.main()