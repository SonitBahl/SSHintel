import socket
import threading
from .handlers import client_handle
from .limits import ConnectionLimiter
from .logger import log_event, set_telemetry_store
from .telemetry_store import TelemetryStore


def honeypot(address='0.0.0.0', port=2222, username=None, password=None, tarpit=False,
             max_connections=50, auth_timeout=60, session_idle_timeout=300,
             telemetry_db=None):
    """Start the SSH honeypot.

    Args:
        telemetry_db: Path to a SQLite database file for persistent telemetry.
            If None (default), SQLite storage is disabled and only JSONL
            logging is used. Pass a path string or Path to enable it.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, port))
    sock.listen(100)

    limiter = ConnectionLimiter(max_connections)

    # Initialize the SQLite telemetry store if requested.
    store = None
    if telemetry_db is not None:
        store = TelemetryStore(telemetry_db)
        store.open()
        set_telemetry_store(store)
        print(f"SQLite telemetry store: {store.db_path}")
    else:
        set_telemetry_store(None)

    print(f"SSH honeypot listening on {address}:{port} "
          f"(max {max_connections} connections, auth timeout {auth_timeout}s, "
          f"session idle timeout {session_idle_timeout}s)")

    try:
        while True:
            try:
                client, addr = sock.accept()
                if not limiter.try_acquire():
                    log_event('connection_rejected', source_ip=addr[0], reason='connection_limit')
                    try:
                        client.close()
                    except OSError:
                        pass
                    continue
                t = threading.Thread(
                    target=_client_worker,
                    args=(client, addr, username, password, tarpit,
                          auth_timeout, session_idle_timeout, limiter),
                    daemon=True,
                )
                t.start()
            except Exception as e:
                print("!!! Exception - Failed to accept connection !!!")
                print(e)
    finally:
        # Clean up the telemetry store on shutdown.
        if store is not None:
            store.close()
            set_telemetry_store(None)


def _client_worker(client, addr, username, password, tarpit,
                   auth_timeout, session_idle_timeout, limiter):
    """Run one connection's lifecycle, always returning its connection slot."""
    try:
        client_handle(
            client, addr, username, password, tarpit,
            auth_timeout=auth_timeout,
            session_idle_timeout=session_idle_timeout,
        )
    finally:
        limiter.release()
