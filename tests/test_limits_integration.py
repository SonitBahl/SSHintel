"""Focused integration tests for connection limits and timeouts.

These exercise the live TCP/SSH server, so they require ``paramiko`` and a
generated host key in ``static/server.key``. They are skipped gracefully when
either is unavailable so the stdlib-only unit suite still passes.

Because a real server is involved these tests use short, test-specific timeouts
and clean up every client connection to avoid hanging the suite.
"""

import json
import socket
import threading
import time
import unittest
from pathlib import Path

from honeypot import logger

try:
    import paramiko
    from honeypot.main import honeypot
    HAVE_SERVER = True
except Exception:
    HAVE_SERVER = False

EVENTS_PATH = Path(__file__).parent.parent / "log_files" / "events.jsonl"

HOST, USER, PASSWD = "127.0.0.1", "user1", "pass123"
# Short, test-only values so the suite is fast.
# IDLE_TIMEOUT must be long enough that connection-holder sessions survive the
# brief window used to open them, but short enough to test quickly.
MAX_CONNECTIONS, AUTH_TIMEOUT, IDLE_TIMEOUT = 3, 2, 5


def _free_port():
    s = socket.socket()
    s.bind((HOST, 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_for_port(port, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = socket.socket()
        try:
            if s.connect_ex((HOST, port)) == 0:
                s.close()
                return True
        finally:
            s.close()
        time.sleep(0.05)
    return False


def _events_since(mark):
    """Return parsed JSONL events logged at or after ``mark`` (ISO string)."""
    if not EVENTS_PATH.exists():
        return []
    out = []
    with open(EVENTS_PATH, "r", encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("timestamp", "") >= mark:
                out.append(ev)
    return out


def _drain(shell, rounds=3, wait=0.2):
    data = b""
    for _ in range(rounds):
        try:
            chunk = shell.recv(4096)
            if not chunk:
                break
            data += chunk
        except Exception:
            break
        time.sleep(wait)
    return data


def _connect(port, username=USER, password=PASSWD):
    """Connect to the honeypot, retrying briefly to absorb asynchronous
    server-side slot releases between tests."""
    last = None
    for _ in range(6):
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            c.connect(HOST, port=port, username=username, password=password, timeout=5)
            return c
        except Exception as e:  # noqa: BLE001 - absorb transient resets
            last = e
            try:
                c.close()
            except Exception:
                pass
            time.sleep(0.3)
    raise last


def _invoke_shell(c):
    """Open a shell channel with a client-side recv timeout so tests never block."""
    shell = c.invoke_shell()
    shell.settimeout(0.5)
    return shell


@unittest.skipUnless(HAVE_SERVER, "requires paramiko + generated host key")
class TestLimitsIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        cls.server = threading.Thread(
            target=honeypot,
            kwargs={
                "address": HOST,
                "port": cls.port,
                "username": USER,
                "password": PASSWD,
                "tarpit": False,
                "max_connections": MAX_CONNECTIONS,
                "auth_timeout": AUTH_TIMEOUT,
                "session_idle_timeout": IDLE_TIMEOUT,
            },
            daemon=True,
        )
        cls.server.start()
        cls.assertTrue(_wait_for_port(cls.port), "server did not start listening")

    # --- Test 4: idle session eventually terminates ------------------------
    def test_idle_session_times_out(self):
        mark = logger.utc_now_iso()
        c = _connect(self.port)
        shell = _invoke_shell(c)
        _drain(shell)
        time.sleep(IDLE_TIMEOUT + 1.5)
        c.close()
        reasons = [
            e.get("reason")
            for e in _events_since(mark)
            if e.get("event_type") == "disconnect"
        ]
        self.assertIn("idle_timeout", reasons)

    # --- Test 5: an active session keeps working ---------------------------
    def test_active_session_does_not_time_out(self):
        mark = logger.utc_now_iso()
        c = _connect(self.port)
        shell = _invoke_shell(c)
        time.sleep(0.4)
        _drain(shell)
        for _ in range(6):
            shell.send("pwd\r")
            time.sleep(0.4)
            _drain(shell)
        shell.send("whoami\r")
        time.sleep(0.3)
        out = _drain(shell)
        c.close()
        self.assertIn(b"user1", out, "active session was killed by idle timeout")
        reasons = [
            e.get("reason")
            for e in _events_since(mark)
            if e.get("event_type") == "disconnect"
        ]
        self.assertNotIn("idle_timeout", reasons)

    # --- Tests 1, 2, 8: limit, slot release, rejected telemetry ------------
    def test_connection_limit_rejects_and_telemetry_plus_slot_release(self):
        mark = logger.utc_now_iso()
        holders = []
        for _ in range(MAX_CONNECTIONS):
            c = _connect(self.port)
            shell = _invoke_shell(c)
            time.sleep(0.3)
            _drain(shell)
            holders.append((c, shell))
        time.sleep(0.2)

        raw = socket.create_connection((HOST, self.port), timeout=3)
        time.sleep(0.3)
        try:
            raw.settimeout(1)
            raw.recv(50)  # server closes it; may raise or return b''
        except Exception:
            pass
        raw.close()

        events = _events_since(mark)
        self.assertTrue(
            any(
                e.get("event_type") == "connection_rejected"
                and e.get("reason") == "connection_limit"
                for e in events
            ),
            "no connection_rejected event emitted",
        )

        # Release one slot; a new connection must now succeed.
        c0, _ = holders.pop()
        c0.close()
        time.sleep(0.4)
        new = _connect(self.port)  # should authenticate fine (slot released)
        new.close()
        for c, _ in holders:
            c.close()

    # --- Test 6: auth idle (no handshake) eventually terminates ------------
    def test_auth_timeout_ends_connection(self):
        mark = logger.utc_now_iso()
        raw = socket.create_connection((HOST, self.port), timeout=3)
        raw.settimeout(AUTH_TIMEOUT + 2)
        try:
            raw.recv(100)
        except socket.timeout:
            pass
        raw.close()
        time.sleep(0.3)
        reasons = [
            e.get("reason")
            for e in _events_since(mark)
            if e.get("event_type") == "disconnect"
        ]
        self.assertIn("auth_timeout", reasons)
        self.assertNotIn("idle_timeout", reasons)

    # --- Test 9: tarpit still works ----------------------------------------
    def test_tarpit_regression(self):
        mark = logger.utc_now_iso()
        port = _free_port()
        threading.Thread(
            target=honeypot,
            kwargs={
                "address": HOST,
                "port": port,
                "username": USER,
                "password": PASSWD,
                "tarpit": True,
                "max_connections": 5,
                "auth_timeout": 5,
                "session_idle_timeout": 5,
            },
            daemon=True,
        ).start()
        self.assertTrue(_wait_for_port(port), "tarpit server did not start")
        c = _connect(port)
        shell = _invoke_shell(c)
        time.sleep(0.6)
        first = _drain(shell)
        self.assertTrue(first, "tarpit sent no banner output")
        c.close()
        events = _events_since(mark)
        self.assertTrue(any(e.get("event_type") == "tarpit" for e in events))


if __name__ == "__main__":
    unittest.main()