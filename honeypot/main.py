import socket
import threading
from .handlers import client_handle
from .limits import ConnectionLimiter
from .logger import log_event, set_telemetry_store
from .telemetry_store import TelemetryStore


def _close_client(client):
    """Wake blocked SSH reads before closing the underlying socket."""
    try:
        client.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    client.close()


def honeypot(address='0.0.0.0', port=2222, username=None, password=None, tarpit=False,
             max_connections=50, auth_timeout=60, session_idle_timeout=300,
             tarpit_max_seconds=120, telemetry_db=None):
    """Start the SSH honeypot.

    Args:
        telemetry_db: Path to a SQLite database file for persistent telemetry.
            If None (default), SQLite storage is disabled and only JSONL
            logging is used. Pass a path string or Path to enable it.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    limiter = ConnectionLimiter(max_connections)
    workers = {}
    store = None
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((address, port))
        sock.listen(100)
        if telemetry_db is not None:
            store = TelemetryStore(telemetry_db)
            store.open()
            set_telemetry_store(store)
            print(f"SQLite telemetry store: {store.db_path}")
        else:
            set_telemetry_store(None)

        print(f"SSH honeypot listening on {address}:{port} "
              f"(max {max_connections} connections, auth timeout {auth_timeout}s, "
              f"session idle timeout {session_idle_timeout}s"
              + (f", tarpit max {tarpit_max_seconds}s" if tarpit else "") + ")")
        while True:
            client, addr = sock.accept()
            # The accept loop owns the registry; don't retain completed workers.
            workers = {t: conn for t, conn in workers.items() if t.is_alive()}
            if not limiter.try_acquire():
                try:
                    log_event('connection_rejected', source_ip=addr[0], source_port=addr[1], reason='connection_limit')
                finally:
                    _close_client(client)
                continue
            thread = None
            try:
                thread = threading.Thread(
                    target=_client_worker,
                    args=(client, addr, username, password, tarpit,
                          auth_timeout, session_idle_timeout, limiter,
                          tarpit_max_seconds, None),
                    name='sshintel-client', daemon=True,
                )
                workers[thread] = client
                thread.start()
            except BaseException:
                workers.pop(thread, None)
                _close_client(client)
                limiter.release()
                raise
    except KeyboardInterrupt:
        print("Stopping SSH honeypot...")
    finally:
        sock.close()
        for client in workers.values():
            _close_client(client)
        for thread in workers:
            thread.join()
        # All session finalization must finish before the store is closed.
        if store is not None:
            store.close()
        set_telemetry_store(None)


def _client_worker(client, addr, username, password, tarpit,
                   auth_timeout, session_idle_timeout, limiter,
                   tarpit_max_seconds=120, config=None):
    """Run one connection's lifecycle, always returning its connection slot."""
    try:
        client_handle(
            client, addr, username, password, tarpit,
            auth_timeout=auth_timeout,
            session_idle_timeout=session_idle_timeout,
            tarpit_max_seconds=tarpit_max_seconds,
            config=config,
        )
    finally:
        limiter.release()
