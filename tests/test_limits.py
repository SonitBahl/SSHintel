"""Focused tests for the concurrent connection limiter (honeypot.limits).

These validate the thread-safe connection cap in isolation, without needing to
run a real SSH server. They cover: the hard limit, slot release after a session
ends, concurrency (the cap is never exceeded), and slot release after an
exception (no leaked slots).
"""

import threading
import unittest

from honeypot.limits import ConnectionLimiter


class TestConnectionLimiter(unittest.TestCase):
    # --- Test 1: connection limit ------------------------------------------
    def test_limit_is_enforced(self):
        limiter = ConnectionLimiter(2)
        self.assertTrue(limiter.try_acquire())
        self.assertTrue(limiter.try_acquire())
        self.assertFalse(limiter.try_acquire())  # third is rejected

    # --- Test 2: slot release ----------------------------------------------
    def test_slot_released_after_disconnect(self):
        limiter = ConnectionLimiter(2)
        limiter.try_acquire()
        limiter.try_acquire()
        self.assertFalse(limiter.try_acquire())
        limiter.release()  # one session ends
        self.assertTrue(limiter.try_acquire())  # a new connection is allowed

    # --- Test 3: concurrent acquires never exceed the cap ------------------
    def test_concurrent_acquires_never_exceed_cap(self):
        limiter = ConnectionLimiter(5)
        held = 0
        peak = 0
        lock = threading.Lock()
        errors = []

        def worker():
            nonlocal held, peak
            if not limiter.try_acquire():
                return
            with lock:
                held += 1
                peak = max(peak, held)
            try:
                import time
                time.sleep(0.02)
            finally:
                with lock:
                    held -= 1
                limiter.release()

        threads = [threading.Thread(target=worker) for _ in range(30)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertLessEqual(peak, 5, "concurrent connections exceeded the cap")
        # Every acquired slot was returned.
        for _ in range(5):
            self.assertTrue(limiter.try_acquire(), "a slot was leaked")
        # And now we are at the cap again.
        self.assertFalse(limiter.try_acquire())

    # --- Test 7: slot released after an exception --------------------------
    def test_slot_released_after_exception(self):
        limiter = ConnectionLimiter(1)

        def worker():
            if not limiter.try_acquire():
                return
            try:
                raise RuntimeError("boom")
            except RuntimeError:
                pass  # like client_handle, the exception is contained
            finally:
                limiter.release()

        worker()
        self.assertTrue(limiter.try_acquire(), "slot was leaked after exception")

    # --- Edge: over-release is safe ----------------------------------------
    def test_double_release_is_safe(self):
        limiter = ConnectionLimiter(2)
        limiter.try_acquire()
        self.assertTrue(limiter.try_acquire())
        # Over-releasing must not crash or push the counter past the bound.
        limiter.release()
        limiter.release()
        limiter.release()  # a third release exceeds a BoundedSemaphore
        # Pool must still only ever admit up to 'max' holders.
        self.assertTrue(limiter.try_acquire())
        self.assertTrue(limiter.try_acquire())
        self.assertFalse(limiter.try_acquire())

    # --- Edge: zero/negative max -> reject everything ----------------------
    def test_zero_limit_rejects_everything(self):
        limiter = ConnectionLimiter(0)
        self.assertFalse(limiter.try_acquire())


if __name__ == '__main__':
    unittest.main()