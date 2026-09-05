import paramiko
import time
import socket
from pathlib import Path

from .server import Server
from .session import Session
from .shell import FakeShell
from .logger import funnel_logger, log_event, record_session_connect, record_session_finalize

host_key_path = Path(__file__).parent.parent / 'static' / 'server.key'

def _load_or_generate_host_key(path: Path) -> paramiko.RSAKey:
    """Load existing host key, or generate a new one if missing/corrupt.
    
    Generating the key programmatically (instead of relying on ssh-keygen)
    ensures the honeypot starts without user interaction and without
    accidentally creating an encrypted key file.
    """
    if path.exists():
        try:
            return paramiko.RSAKey(filename=str(path))
        except paramiko.ssh_exception.PasswordRequiredException:
            # Key is encrypted; regenerate without passphrase
            pass
        except Exception:
            # Corrupt or unreadable key; regenerate
            pass
    
    # Generate a new 2048-bit RSA key without passphrase
    key = paramiko.RSAKey.generate(2048)
    path.parent.mkdir(parents=True, exist_ok=True)
    key.write_private_key_file(str(path))
    return key

host_key = _load_or_generate_host_key(host_key_path)

def emulated_shell(channel, session, idle_timeout=300):
    prompt_template = "user1@ubuntu:{}$ "
    shell = FakeShell(session)
    command = b""
    # An inactivity timeout: channel.recv() raises socket.timeout if no data
    # arrives within ``idle_timeout`` seconds. Because the countdown restarts on
    # every successful recv(), an actively-typing attacker is never killed.
    if idle_timeout and idle_timeout > 0:
        channel.settimeout(idle_timeout)
    channel.send(_prompt(prompt_template, session.cwd))

    while True:
        try:
            char = channel.recv(1)
        except socket.timeout:
            session.disconnect_reason = 'idle_timeout'
            break
        if not char:
            break

        if char == b"\r":
            channel.send(b"\r\n")
            cmd_line = command.decode(errors="replace")
            command = b""

            # Run through the fake shell. Any Python exception escaping a
            # handler must become a simulated shell error, never crash the
            # SSH session.
            try:
                output = shell.execute(cmd_line)
            except Exception:
                output = "bash: internal error while handling command"
                print(f"!!! Shell handler raised for {cmd_line!r}")

            if shell.exited:
                channel.send(b"logout\r\n")
                break

            funnel_logger.info(f'Command "{cmd_line}" executed by {session.source_ip}')
            log_event(
                'command',
                session_id=session.session_id,
                source_ip=session.source_ip,
                username=session.username,
                command=cmd_line,
                cwd=session.cwd,
            )
            if output:
                channel.send(output.encode() + b"\r\n" if not output.endswith("\n") else output.encode())
            channel.send(_prompt(prompt_template, session.cwd))

        elif char == b"\x7f":
            if len(command) > 0:
                command = command[:-1]
                channel.send(b"\b \b")
        else:
            channel.send(char)
            command += char

    channel.close()


def _prompt(template, cwd):
    cwd_display = cwd.replace("/home/user1", "~") if cwd.startswith("/home/user1") else cwd
    return template.format(cwd_display).encode()

def client_handle(client, addr, username, password, tarpit=False,
                  auth_timeout=60, session_idle_timeout=300):
    client_ip = addr[0]
    session = Session(source_ip=client_ip)
    print(f"{client_ip} connected to server.")
    log_event('connect', session_id=session.session_id, source_ip=session.source_ip)
    record_session_connect(session.session_id, session.source_ip, session.connected_at)
    in_auth_phase = True
    try:
        # Bound the SSH handshake + authentication phase so a client that
        # connects but never completes auth cannot hold a socket forever.
        client.settimeout(auth_timeout)
        transport = paramiko.Transport(client)
        transport.local_version = "SSH-2.0-MySSHServer_1.0"
        transport.add_server_key(host_key)

        server = Server(client_ip, username, password, session=session)
        transport.start_server(server=server)
        channel = transport.accept(auth_timeout)

        if channel is None:
            print("No channel was opened.")
            session.disconnect_reason = 'auth_timeout'
            return
        # Handshake is done; clear the socket-level timeout. The shell applies
        # its own per-recv inactivity timeout via the channel.
        client.settimeout(None)
        in_auth_phase = False

        banner = "Welcome to Ubuntu 22.04 LTS!\r\n\r\n"
        if tarpit:
            log_event('tarpit', session_id=session.session_id, source_ip=session.source_ip)
            for char in banner * 100:
                channel.send(char)
                time.sleep(8)
        else:
            channel.send(banner)

        emulated_shell(channel, session, idle_timeout=session_idle_timeout)

    except socket.timeout:
        if in_auth_phase:
            session.disconnect_reason = 'auth_timeout'
        print(f"{client_ip} disconnected during SSH handshake/auth (timeout).")
    except Exception as e:
        if in_auth_phase:
            session.disconnect_reason = 'auth_timeout'
        print("!!! Exception in client handler !!!")
        print(e)
    finally:
        try:
            transport.close()
        except Exception:
            pass
        client.close()
        # Finalize exactly once, then emit the disconnect event. ``finalize()``
        # is idempotent so we never emit more than one disconnect per session.
        session.finalize()
        log_event(
            'disconnect',
            session_id=session.session_id,
            source_ip=session.source_ip,
            username=session.username,
            auth_result=session.auth_result,
            duration_seconds=session.duration_seconds,
            reason=session.disconnect_reason,
        )
        record_session_finalize(
            session.session_id,
            session.username,
            session.disconnected_at,
            session.duration_seconds,
            session.auth_result,
            session.disconnect_reason,
        )
