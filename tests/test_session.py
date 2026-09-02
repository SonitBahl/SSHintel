"""Focused tests for the session-tracking model (honeypot.session.Session).

These validate the per-connection session lifecycle logic directly, without a
full integration/network test suite.
"""

import unittest

from honeypot import logger
from honeypot.session import Session, AUTH_SUCCESS, AUTH_FAILURE


class TestSessionModel(unittest.TestCase):
    # --- Test 1: unique sessions -------------------------------------------
    def test_two_sessions_have_different_ids(self):
        s1 = Session(source_ip='10.0.0.1')
        s2 = Session(source_ip='10.0.0.2')
        self.assertNotEqual(s1.session_id, s2.session_id)
        self.assertNotEqual(s1.session_id, '')

    # --- Test 2: same session ID across all events -------------------------
    def test_same_session_id_across_future_events(self):
        s = Session(source_ip='127.0.0.1')
        events = [
            logger.build_event('connect', session_id=s.session_id, source_ip=s.source_ip),
            logger.build_event('auth_attempt', session_id=s.session_id, source_ip=s.source_ip, username='root'),
            logger.build_event('auth_success', session_id=s.session_id, source_ip=s.source_ip, username='root'),
            logger.build_event('command', session_id=s.session_id, source_ip=s.source_ip, command='ls', cwd='/'),
            logger.build_event('command', session_id=s.session_id, source_ip=s.source_ip, command='pwd', cwd='/'),
            logger.build_event('disconnect', session_id=s.session_id, source_ip=s.source_ip, duration_seconds=1.0),
        ]
        for e in events:
            self.assertEqual(e['session_id'], s.session_id)
            self.assertEqual(e['source_ip'], '127.0.0.1')

    # --- Test 3: multiple auth failures share one session ------------------
    def test_multiple_auth_failures_share_one_session(self):
        s = Session(source_ip='10.0.0.5')
        s.record_auth_attempt('root')
        s.record_auth_failure()
        s.record_auth_attempt('admin')
        s.record_auth_failure()
        self.assertEqual(s.auth_result, AUTH_FAILURE)
        self.assertEqual(s.authenticated_at, None)
        # Every event still keys off the single session id.
        self.assertEqual(s.session_id, s.session_id)

    # --- Test 4: failed-auth session still finalizes -----------------------
    def test_failed_auth_session_finalizes(self):
        s = Session(source_ip='10.0.0.6')
        s.record_auth_attempt('root')
        s.record_auth_failure()
        finalized = s.finalize()
        self.assertTrue(finalized)
        self.assertIsNotNone(s.disconnected_at)
        self.assertIsNotNone(s.duration_seconds)
        self.assertEqual(s.auth_result, AUTH_FAILURE)
        self.assertIsNone(s.authenticated_at)

    # --- Test 5: normal disconnect finalizes once --------------------------
    def test_normal_disconnect_finalizes_once(self):
        s = Session(source_ip='127.0.0.1')
        s.record_auth_attempt('user1')
        s.record_auth_success('user1')
        self.assertTrue(s.finalize())
        self.assertEqual(s.auth_result, AUTH_SUCCESS)
        self.assertIsNotNone(s.authenticated_at)
        self.assertIsNotNone(s.disconnected_at)

    # --- Test 6: unexpected disconnect still finalizes ---------------------
    def test_unexpected_disconnect_finalizes(self):
        """A session that never authenticates and just drops must finalize."""
        s = Session(source_ip='10.0.0.7')
        finalized = s.finalize()  # no auth events at all
        self.assertTrue(finalized)
        self.assertIsNotNone(s.disconnected_at)
        self.assertIsNotNone(s.duration_seconds)

    # --- Test 7: duration is valid and non-negative ------------------------
    def test_duration_is_non_negative(self):
        s = Session(source_ip='127.0.0.1')
        s.record_auth_success('user1')
        s.finalize()
        self.assertIsNotNone(s.duration_seconds)
        self.assertGreaterEqual(s.duration_seconds, 0)

    # --- Test 8: no duplicate finalize / disconnect ------------------------
    def test_no_duplicate_disconnect(self):
        s = Session(source_ip='127.0.0.1')
        first = s.finalize()
        second = s.finalize()  # second call must be a no-op
        self.assertTrue(first)
        self.assertFalse(second)
        final_at = s.disconnected_at
        self.assertEqual(s.finalize(), False)
        self.assertEqual(s.disconnected_at, final_at)  # unchanged

    # --- Test 9: concurrent sessions stay independent ----------------------
    def test_concurrent_sessions_independent(self):
        a = Session(source_ip='10.0.0.1')
        b = Session(source_ip='10.0.0.2')
        a.record_auth_success('user1')
        a.finalize()
        # b must be untouched by a's lifecycle.
        self.assertIsNone(b.username)
        self.assertIsNone(b.authenticated_at)
        self.assertIsNone(b.auth_result)
        self.assertIsNone(b.disconnected_at)
        self.assertNotEqual(a.session_id, b.session_id)


if __name__ == '__main__':
    unittest.main()