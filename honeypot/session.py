"""Session model for SSHintel.

A Session represents one attacker/client connection, from connection
establishment until disconnect. It carries the state that every structured
security event for that connection shares (session_id, source_ip), plus
lifecycle timestamps and the authentication outcome that are finalized as the
connection proceeds.

Sessions are deliberately lightweight and per-connection: each connection gets
its own independent Session instance, so no global mutable state is shared
between concurrent clients.
"""

import time
from dataclasses import dataclass, field

from .fs import create_filesystem
from .logger import new_session_id, utc_now_iso

AUTH_SUCCESS = 'success'
AUTH_FAILURE = 'failure'


@dataclass
class Session:
    """Lifecycle state for one attacker connection.

    ``session_id`` and ``connected_at`` are generated once when the session is
    created and reused for every event emitted for that connection. Duration is
    measured with ``time.monotonic()`` (a reliable, monotonic time source) while
    the recorded timestamps remain UTC wall-clock ISO-8601 strings.
    """

    source_ip: str
    session_id: str = field(default_factory=new_session_id)
    connected_at: str = field(default_factory=utc_now_iso)
    username: str | None = None
    authenticated_at: str | None = None
    disconnected_at: str | None = None
    auth_result: str | None = None
    duration_seconds: float | None = None
    # Per-session isolated state: the fake filesystem and working directory.
    # Each Session gets its own independent copy created by ``create_filesystem``.
    fake_filesystem: dict = field(default_factory=create_filesystem)
    cwd: str = "/home/user1"
    _connected_mono: float = field(
        default_factory=time.monotonic, init=False, repr=False, compare=False
    )

    def record_auth_attempt(self, username):
        """Remember the username being attempted (last attempt wins)."""
        self.username = username

    def record_auth_success(self, username):
        """Mark the session as successfully authenticated."""
        self.username = username
        self.authenticated_at = utc_now_iso()
        self.auth_result = AUTH_SUCCESS

    def record_auth_failure(self):
        """Mark the most recent authentication attempt as failed."""
        self.auth_result = AUTH_FAILURE

    def finalize(self) -> bool:
        """Finalize the session as disconnected.

        Computes duration from the monotonic time source and stamps the
        disconnect time exactly once. Returns ``True`` if this call finalized
        the session, or ``False`` if it was already finalized (so callers can
        guarantee a session produces at most one disconnect event).
        """
        if self.disconnected_at is not None:
            return False
        self.disconnected_at = utc_now_iso()
        self.duration_seconds = round(time.monotonic() - self._connected_mono, 6)
        return True