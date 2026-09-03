from honeypot.main import honeypot
import argparse

parser = argparse.ArgumentParser(description="SSH Honeypot CLI")
parser.add_argument('--host', default='0.0.0.0')
parser.add_argument('--port', type=int, default=2222)
parser.add_argument('--username')
parser.add_argument('--password')
parser.add_argument('--tarpit', action='store_true')
parser.add_argument('--max-connections', type=int, default=50,
                    help='maximum simultaneous active connections (default: 50)')
parser.add_argument('--auth-timeout', type=int, default=60,
                    help='seconds allowed for SSH handshake/authentication (default: 60)')
parser.add_argument('--session-idle-timeout', type=int, default=300,
                    help='seconds of inactivity before an authenticated session ends (default: 300)')

args = parser.parse_args()

honeypot(
    args.host, args.port, args.username, args.password, args.tarpit,
    max_connections=args.max_connections,
    auth_timeout=args.auth_timeout,
    session_idle_timeout=args.session_idle_timeout,
)
