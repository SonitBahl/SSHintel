import socket
import threading
from .handlers import client_handle
from .limits import ConnectionLimiter
from .logger import log_event


def honeypot(address='0.0.0.0', port=2222, username=None, password=None, tarpit=False,
             max_connections=50, auth_timeout=60, session_idle_timeout=300):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, port))
    sock.listen(100)

    limiter = ConnectionLimiter(max_connections)
    print(f"SSH honeypot listening on {address}:{port} "
          f"(max {max_connections} connections, auth timeout {auth_timeout}s, "
          f"session idle timeout {session_idle_timeout}s)")

    while True:
        try:
            client, addr = sock.accept()
            if not limiter.try_acquire():
                # Limit reached: reject the connection without allocating a full
                # session/worker, and record the rejection as a security event.
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
