"""Concurrency and graceful shutdown regressions against real SSH servers."""

import os
from pathlib import Path
import signal
import socket
import sqlite3
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

import paramiko
import pytest

from honeypot import main
from honeypot.limits import ConnectionLimiter

ROOT = Path(__file__).resolve().parents[1]


def wait_until(predicate, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    assert predicate(), "condition did not become true before deadline"


@pytest.fixture
def sensor(tmp_path):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    database = tmp_path / "sensor.db"
    output = (tmp_path / "server.log").open("w+")
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("HONEYPOT_") and key != "PORT"}
    driver = (
        "import run, threading\n"
        "try:\n    run.main()\n"
        "finally:\n"
        "    print('LIVE_THREADS=' + repr([t.name for t in threading.enumerate() "
        "if t is not threading.main_thread()]), flush=True)\n"
    )
    env["PYTHONPATH"] = str(ROOT)
    process = subprocess.Popen(
        [sys.executable, "-u", "-c", driver, "serve", "--host", "127.0.0.1",
         "--port", str(port), "--username", "user1", "--password", "pass123",
         "--max-connections", "4", "--auth-timeout", "1",
         "--session-idle-timeout", "30", "--db", str(database)],
        cwd=str(tmp_path), env=env, stdout=output, stderr=output,
    )

    def text():
        return (tmp_path / "server.log").read_text()

    def rows(query):
        with sqlite3.connect(str(database), timeout=2) as connection:
            return connection.execute(query).fetchall()

    try:
        wait_until(lambda: "SSH honeypot listening" in text())
        assert process.poll() is None
        yield process, port, rows, text
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        output.close()


def connect(port):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect("127.0.0.1", port=port, username="user1", password="pass123",
                       timeout=3, allow_agent=False, look_for_keys=False)
        channel = client.invoke_shell()
        channel.settimeout(3)
        data = b""
        while not data.endswith(b"$ "):
            chunk = channel.recv(4096)
            assert chunk, "shell closed before prompt"
            data += chunk
        return client, channel
    except BaseException:
        client.close()
        raise


def test_concurrent_sessions_abrupt_disconnect_and_slot_recovery(sensor):
    process, port, rows, text = sensor
    for wave in range(3):
        with ThreadPoolExecutor(max_workers=4) as pool:
            sessions = list(pool.map(connect, [port] * 4))
        try:
            assert rows("SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL")[0][0] == 4
            with socket.create_connection(("127.0.0.1", port), timeout=2) as extra:
                extra.settimeout(2)
                try:
                    assert extra.recv(4096) == b""
                except ConnectionResetError:
                    pass
            for client, channel in sessions:
                channel.send("pwd\r")
                data = b""
                while not data.endswith(b"$ "):
                    chunk = channel.recv(4096)
                    assert chunk
                    data += chunk
                assert b"/home/user1" in data
                channel.send("unfinished-command")
        finally:
            for client, channel in sessions:
                client.close()
        wait_until(lambda: rows("SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL")[0][0] == 0)
    assert rows("SELECT COUNT(*) FROM sessions")[0][0] == 12
    assert rows("SELECT COUNT(*) FROM events WHERE event_type='disconnect'")[0][0] == 12
    assert rows("SELECT COUNT(*) FROM events WHERE event_type='command'")[0][0] == 12
    process.send_signal(signal.SIGINT)
    assert process.wait(timeout=8) == 0
    assert "LIVE_THREADS=[]" in text()
    assert "SQLite telemetry error" not in text()


def test_sigint_drains_connections_before_closing_store(sensor):
    process, port, rows, text = sensor
    client, channel = connect(port)
    raw = socket.create_connection(("127.0.0.1", port), timeout=2)
    try:
        wait_until(lambda: rows("SELECT COUNT(*) FROM sessions")[0][0] == 2)
        process.send_signal(signal.SIGINT)
        assert process.wait(timeout=8) == 0
        assert "LIVE_THREADS=[]" in text()
        # Paramiko can log a diagnostic traceback for the half-open peer;
        # the CLI itself must not leak KeyboardInterrupt on normal shutdown.
        assert "KeyboardInterrupt" not in text()
        assert rows("SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL")[0][0] == 0
        assert rows("SELECT COUNT(*) FROM events WHERE event_type='disconnect'")[0][0] == 2
        assert rows("PRAGMA integrity_check") == [("ok",)]
        assert "SQLite telemetry error" not in text()
    finally:
        raw.close()
        client.close()


def test_stalled_handshake_releases_slot_within_auth_timeout(sensor):
    process, port, rows, text = sensor
    with socket.create_connection(("127.0.0.1", port), timeout=2):
        wait_until(lambda: rows("SELECT COUNT(*) FROM sessions")[0][0] == 1)
        wait_until(lambda: rows("SELECT COUNT(*) FROM sessions WHERE ended_at IS NOT NULL")[0][0] == 1,
                   timeout=3)


def test_worker_releases_slot_when_handler_raises(monkeypatch):
    limiter = ConnectionLimiter(1)
    assert limiter.try_acquire()
    monkeypatch.setattr(main, "client_handle", Mock(side_effect=RuntimeError("handler failed")))
    with pytest.raises(RuntimeError, match="handler failed"):
        main._client_worker(Mock(), ("127.0.0.1", 1234), None, None,
                            False, 1, 1, limiter)
    assert limiter.try_acquire()
    assert not limiter.try_acquire()


@pytest.mark.parametrize("failure", ["thread_start", "store_open", "accept"])
def test_startup_and_accept_failures_close_owned_resources(monkeypatch, failure):
    listener = Mock()
    client = Mock()
    listener.accept.side_effect = [(client, ("127.0.0.1", 1234))]
    monkeypatch.setattr(main.socket, "socket", Mock(return_value=listener))
    limiter = ConnectionLimiter(1)
    monkeypatch.setattr(main, "ConnectionLimiter", Mock(return_value=limiter))
    store = Mock()
    monkeypatch.setattr(main, "TelemetryStore", Mock(return_value=store))
    monkeypatch.setattr(main, "set_telemetry_store", Mock())
    thread = Mock()
    monkeypatch.setattr(main.threading, "Thread", Mock(return_value=thread))
    if failure == "thread_start":
        thread.start.side_effect = RuntimeError("thread startup failed")
    elif failure == "store_open":
        store.open.side_effect = RuntimeError("store startup failed")
    else:
        listener.accept.side_effect = OSError("accept failed")
    with pytest.raises((RuntimeError, OSError)):
        main.honeypot(telemetry_db="unused.db")
    listener.close.assert_called_once_with()
    store.close.assert_called_once_with()
    if failure == "thread_start":
        client.close.assert_called_once_with()
        assert limiter.try_acquire(), "failed thread startup leaked a slot"
        thread.join.assert_not_called()
