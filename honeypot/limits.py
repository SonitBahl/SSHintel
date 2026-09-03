"""Thread-safe connection limiting for SSHintel.

Prevents an attacker from opening unbounded simultaneous connections by capping
the number of active connection slots. A ``threading.BoundedSemaphore`` is
atomic and thread-safe, so concurrent accept/finish is never able to exceed the
configured maximum.
"""

import threading


class ConnectionLimiter:
    """A thread-safe cap on the number of simultaneously active connections.

    Usage
    -----
        limiter = ConnectionLimiter(50)
        if limiter.try_acquire():
            # start a worker that calls limiter.release() in its ``finally``
        else:
            # limit reached - reject the connection
    """

    def __init__(self, max_connections):
        self.max_connections = max(int(max_connections), 0)
        self._semaphore = threading.BoundedSemaphore(self.max_connections)

    def try_acquire(self):
        """Atomically claim a slot if one is available. Returns ``True`` if so."""
        return self._semaphore.acquire(blocking=False)

    def release(self):
        """Return a slot to the pool. Safe against over-release (double-free)."""
        try:
            self._semaphore.release()
        except ValueError:
            # Over-released - ignore, never allow the pool to go negative.
            pass
