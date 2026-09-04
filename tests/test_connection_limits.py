"""Tests for connection limits and timeouts."""
import threading
import time

import pytest

from honeypot.limits import ConnectionLimiter


class TestConnectionLimiter:
    """Verify the connection limiter enforces maximum connections."""

    def test_initializes_with_max(self):
        limiter = ConnectionLimiter(5)
        assert limiter.max_connections == 5

    def test_acquire_succeeds_below_limit(self):
        limiter = ConnectionLimiter(5)
        assert limiter.try_acquire() is True

    def test_acquire_fails_at_limit(self):
        limiter = ConnectionLimiter(2)
        limiter.try_acquire()
        limiter.try_acquire()
        assert limiter.try_acquire() is False

    def test_release_allows_new_connection(self):
        limiter = ConnectionLimiter(2)
        limiter.try_acquire()
        limiter.try_acquire()
        limiter.release()
        assert limiter.try_acquire() is True

    def test_release_is_safe_when_empty(self):
        limiter = ConnectionLimiter(2)
        # Should not raise
        limiter.release()

    def test_release_is_idempotent_safe(self):
        limiter = ConnectionLimiter(2)
        limiter.try_acquire()
        limiter.release()
        limiter.release()  # Should not raise

    def test_zero_limit_rejects_all(self):
        limiter = ConnectionLimiter(0)
        assert limiter.try_acquire() is False

    def test_one_limit(self):
        limiter = ConnectionLimiter(1)
        assert limiter.try_acquire() is True
        assert limiter.try_acquire() is False
        limiter.release()
        assert limiter.try_acquire() is True


class TestConcurrentConnections:
    """Verify thread safety of connection limiter."""

    def test_concurrent_acquires_never_exceed_limit(self):
        """At no point should more than `max` connections be active."""
        max_conn = 10
        limiter = ConnectionLimiter(max_conn)
        max_active = [0]
        lock = threading.Lock()
        active = [0]

        def acquire():
            if limiter.try_acquire():
                with lock:
                    active[0] += 1
                    max_active[0] = max(max_active[0], active[0])
                time.sleep(0.01)
                with lock:
                    active[0] -= 1
                limiter.release()

        threads = [threading.Thread(target=acquire) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # The key invariant: the limit was never exceeded
        assert max_active[0] <= max_conn
        # Some connections were accepted
        assert max_active[0] > 0

    def test_concurrent_max_never_exceeded(self):
        limiter = ConnectionLimiter(5)
        max_active = [0]
        lock = threading.Lock()
        active = [0]

        def worker():
            if limiter.try_acquire():
                with lock:
                    active[0] += 1
                    max_active[0] = max(max_active[0], active[0])
                time.sleep(0.01)
                with lock:
                    active[0] -= 1
                limiter.release()

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert max_active[0] <= 5

    def test_stress_test(self):
        limiter = ConnectionLimiter(50)
        counter = [0]
        lock = threading.Lock()

        def worker():
            if limiter.try_acquire():
                with lock:
                    counter[0] += 1
                time.sleep(0.001)
                limiter.release()

        threads = [threading.Thread(target=worker) for _ in range(200)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert counter[0] == 200


class TestSlotRelease:
    """Verify connection slots are properly released."""

    def test_slot_released_after_use(self):
        limiter = ConnectionLimiter(3)
        for _ in range(3):
            limiter.try_acquire()
        assert limiter.try_acquire() is False
        limiter.release()
        assert limiter.try_acquire() is True

    def test_all_slots_released(self):
        limiter = ConnectionLimiter(3)
        for _ in range(3):
            limiter.try_acquire()
        for _ in range(3):
            limiter.release()
        for _ in range(3):
            assert limiter.try_acquire() is True
        assert limiter.try_acquire() is False

    def test_release_after_exception(self):
        limiter = ConnectionLimiter(2)
        limiter.try_acquire()
        try:
            raise ValueError("simulated error")
        except ValueError:
            limiter.release()
        assert limiter.try_acquire() is True
