import paramiko
import socket
import time
import threading
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

def emulated_shell(channel, session, idle_timeout=300, tarpit=False,
                  tarpit_max_seconds=120, config=None):
    prompt_template = "user1@ubuntu:{}$ "
    shell = FakeShell(session)
    command = b""
    keystroke_count = 0
    keystroke_start = time.monotonic()

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
            cmd_line = command.decode(errors="replace")
            command = b""
            keystroke_start = time.monotonic()

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

            if config and config.get("capture_keystrokes"):
                elapsed_ms = int((time.monotonic() - keystroke_start) * 1000)
                log_event(
                    'input.keystroke',
                    session_id=session.session_id,
                    source_ip=session.source_ip,
                    source_port=session.source_port,
                    username=session.username,
                    key="<enter>",
                    sequence_index=keystroke_count,
                    delta_ms=elapsed_ms,
                )
                channel.send(b"\r\n")

            funnel_logger.info(f'Command "{cmd_line}" executed by {session.source_ip}')
            preview_limit = config.get("output_preview_chars", 500) if config else 500
            log_event(
                'command',
                session_id=session.session_id,
                source_ip=session.source_ip,
                source_port=session.source_port,
                username=session.username,
                command=cmd_line,
                cwd=session.cwd,
                output_preview=_output_preview(output, preview_limit),
                output_bytes=len(output.encode()) if output else 0,
            )
            _send_output(channel, output, tarpit, tarpit_max_seconds)
            channel.send(_prompt(prompt_template, session.cwd))
        elif char == b"\x7f":
            if config and config.get("capture_keystrokes"):
                if len(command) > 0:
                    command = command[:-1]
                    channel.send(b"\b \b")
        else:
            if config and config.get("capture_keystrokes"):
                keystroke_count += 1
                if keystroke_count >= config.get("max_keystrokes", 5000):
                    channel.send(b"\a")
                    continue
                if len(char) > config.get("max_line_length", 4096):
                    continue
                elapsed_ms = int((time.monotonic() - keystroke_start) * 1000)
                log_event(
                    'input.keystroke',
                    session_id=session.session_id,
                    source_ip=session.source_ip,
                    source_port=session.source_port,
                    username=session.username,
                    key=char.decode(errors="replace"),
                    sequence_index=keystroke_count - 1,
                    delta_ms=elapsed_ms,
                )
                channel.send(char)
                command += char
            else:
                channel.send(char)
                command += char

    channel.close()


def _prompt(template, cwd):
    cwd_display = cwd.replace("/home/user1", "~") if cwd.startswith("/home/user1") else cwd
    return template.format(cwd_display).encode()


def _send_slow_lines(channel, payload, max_seconds):
    """Send payload line by line with a bounded delay between lines."""
    if max_seconds <= 0:
        channel.send(payload)
        return

    lines = payload.splitlines(keepends=True) or [payload]
    deadline = time.monotonic() + max_seconds
    for index, line in enumerate(lines):
        if not line:
            continue
        channel.send(line)
        if index == len(lines) - 1:
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            continue
        time.sleep(min(0.2, remaining))


def _output_preview(output, limit):
    """Return a capped preview of command output.

    Output longer than ``limit`` characters is truncated with an explicit
    marker so the telemetry store never holds unbounded output (e.g. ``tree /``
    is a cheap disk bomb). ``limit`` must be a positive integer.
    """
    if limit <= 0:
        return ""
    if output is None:
        return ""
    if len(output) <= limit:
        return output
    return output[:limit] + "\n... <output truncated>"


def _send_output(channel, output, tarpit, tarpit_max_seconds):
    """Send command output to the channel.

    In tarpit mode, output is sent line by line with a small delay to slow the
    attacker. In normal mode, output is sent immediately.
    """
    if output:
        data = output.encode()
        if not data.endswith(b"\n"):
            data += b"\r\n"
        if tarpit:
            _send_slow_lines(channel, data, tarpit_max_seconds)
        else:
            channel.send(data)

def client_handle(client, addr, username, password, tarpit=False,
                  auth_timeout=60, session_idle_timeout=300, max_connections=50,
                  tarpit_max_seconds=120, config=None):
    client_ip = addr[0]
    session = Session(source_ip=client_ip, source_port=addr[1])
    print(f"{client_ip} connected to server.")
    log_event('connect', session_id=session.session_id, source_ip=session.source_ip, source_port=addr[1])
    record_session_connect(session.session_id, session.source_ip, session.connected_at)
    in_auth_phase = True
    transport = None
    auth_timer = None
    try:
        # Bound the ENTIRE handshake/auth phase, including clients that never
        # send a banner. A socket timeout alone interferes with Paramiko reads.
        transport = paramiko.Transport(client)
        transport.local_version = "SSH-2.0-MySSHServer_1.0"
        transport.add_server_key(host_key)
        if auth_timeout and auth_timeout > 0:
            auth_timer = threading.Timer(auth_timeout, transport.close)
            auth_timer.daemon = True
            auth_timer.start()

        server = Server(client_ip, username, password, session=session)
        transport.start_server(server=server)
        channel = transport.accept(auth_timeout)

        if channel is None:
            print("No channel was opened.")
            session.disconnect_reason = 'auth_timeout'
            return
        # Handshake is done; the shell applies its own per-recv inactivity
        # timeout via the channel.
        in_auth_phase = False
        if auth_timer is not None:
            auth_timer.cancel()
            auth_timer.join()

        banner = "Welcome to Ubuntu 22.04 LTS!\r\n\r\n"
        if tarpit:
            log_event('tarpit', session_id=session.session_id, source_ip=session.source_ip, source_port=addr[1])
        channel.send(banner)
        emulated_shell(channel, session, idle_timeout=session_idle_timeout,
                       tarpit=tarpit, config=config)

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
        if auth_timer is not None:
            auth_timer.cancel()
            auth_timer.join()
        if transport is not None:
            transport.close()
            # Paramiko owns a separate thread. Don't close the telemetry store
            # while an auth callback can still be writing to it.
            if transport.ident is not None:
                transport.join()
        client.close()
        # Finalize exactly once, then emit the disconnect event. ``finalize()``
        # is idempotent so we never emit more than one disconnect per session.
        session.finalize()
        log_event(
            'disconnect',
            session_id=session.session_id,
            source_ip=session.source_ip,
            source_port=addr[1],
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
