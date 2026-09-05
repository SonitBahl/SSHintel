from honeypot.main import honeypot
from honeypot.logger import set_telemetry_store
from honeypot.telemetry_store import TelemetryStore
import argparse
import sys


def cmd_stats(store):
    """Print summary statistics from the telemetry store."""
    print("=== SSHintel Telemetry Summary ===")
    print(f"  Sessions:          {store.count_sessions()}")
    print(f"  Unique IPs:        {store.unique_ips()}")
    print(f"  Total events:      {store.count_events()}")
    print(f"  Auth attempts:     {store.total_auth_attempts()}")
    print(f"  Auth successes:    {store.successful_auths()}")
    print(f"  Auth failures:     {store.failed_auth_attempts()}")
    print(f"  Commands executed: {store.total_commands()}")


def cmd_top_commands(store, limit=10):
    """Print the most frequently executed commands."""
    rows = store.top_commands(limit=limit)
    print(f"=== Top {len(rows)} Commands ===")
    if not rows:
        print("  (no commands recorded)")
        return
    for i, row in enumerate(rows, 1):
        print(f"  {i:3d}. {row['command']:<20s} ({row['count']}x)")


def cmd_top_usernames(store, limit=10):
    """Print the most frequently attempted usernames."""
    rows = store.top_usernames(limit=limit)
    print(f"=== Top {len(rows)} Usernames ===")
    if not rows:
        print("  (no usernames recorded)")
        return
    for i, row in enumerate(rows, 1):
        print(f"  {i:3d}. {row['username']:<20s} ({row['count']}x)")


def cmd_top_ips(store, limit=10):
    """Print the most active source IPs."""
    rows = store.top_source_ips(limit=limit)
    print(f"=== Top {len(rows)} Source IPs ===")
    if not rows:
        print("  (no IPs recorded)")
        return
    for i, row in enumerate(rows, 1):
        print(f"  {i:3d}. {row['source_ip']:<20s} ({row['count']} events)")


def cmd_dashboard(store, host="127.0.0.1", port=5000):
    """Launch the local web dashboard."""
    from dashboard.app import create_app
    app = create_app(store.db_path)
    print(f"SSHintel dashboard running at http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    app.run(host=host, port=port, debug=False)


def main():
    """Main CLI dispatcher for SSHintel."""
    parser = argparse.ArgumentParser(
        description="SSHintel — Lightweight SSH Honeypot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # --- Honeypot server ---
    hp = subparsers.add_parser("serve", help="Run the SSH honeypot server")
    hp.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    hp.add_argument("--port", type=int, default=2222, help="Bind port (default: 2222)")
    hp.add_argument("--username", default="user1", help="Expected username (default: user1)")
    hp.add_argument("--password", default="pass123", help="Expected password (default: pass123)")
    hp.add_argument("--tarpit", action="store_true", help="Enable tarpit mode")
    hp.add_argument("--max-connections", type=int, default=50, help="Max concurrent connections (default: 50)")
    hp.add_argument("--auth-timeout", type=int, default=60, help="Authentication timeout in seconds (default: 60)")
    hp.add_argument("--session-idle-timeout", type=int, default=300, help="Session idle timeout in seconds (default: 300)")
    hp.add_argument("--db", default=None, help="Path to SQLite telemetry database (default: data/sshintel.db)")
    hp.add_argument("--no-db", action="store_true", help="Disable SQLite telemetry storage")

    # --- Telemetry queries ---
    stats = subparsers.add_parser("stats", help="Show telemetry statistics")
    stats.add_argument("--db", default=None, help="Path to SQLite database (default: data/sshintel.db)")

    top_cmds = subparsers.add_parser("top-commands", help="Show most common commands")
    top_cmds.add_argument("--limit", type=int, default=10, help="Number of results (default: 10)")
    top_cmds.add_argument("--db", default=None, help="Path to SQLite database (default: data/sshintel.db)")

    top_users = subparsers.add_parser("top-usernames", help="Show most targeted usernames")
    top_users.add_argument("--limit", type=int, default=10, help="Number of results (default: 10)")
    top_users.add_argument("--db", default=None, help="Path to SQLite database (default: data/sshintel.db)")

    top_ips = subparsers.add_parser("top-ips", help="Show most active source IPs")
    top_ips.add_argument("--limit", type=int, default=10, help="Number of results (default: 10)")
    top_ips.add_argument("--db", default=None, help="Path to SQLite database (default: data/sshintel.db)")

    # --- Dashboard ---
    dash = subparsers.add_parser("dashboard", help="Launch the web dashboard")
    dash.add_argument("--host", default="127.0.0.1", help="Dashboard bind address (default: 127.0.0.1)")
    dash.add_argument("--port", type=int, default=5000, help="Dashboard port (default: 5000)")
    dash.add_argument("--db", default=None, help="Path to SQLite database (default: data/sshintel.db)")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    # --- Honeypot server ---
    if args.command == "serve":
        store = _get_store(args.db, args.no_db)
        set_telemetry_store(store)
        try:
            honeypot(
                host=args.host,
                port=args.port,
                username=args.username,
                password=args.password,
                tarpit=args.tarpit,
                max_connections=args.max_connections,
                auth_timeout=args.auth_timeout,
                session_idle_timeout=args.session_idle_timeout,
            )
        finally:
            store.close()
        return

    # --- Telemetry / dashboard (read-only) ---
    store = _get_store(args.db, no_db=False)
    store.open()

    if args.command == "stats":
        cmd_stats(store)
    elif args.command == "top-commands":
        cmd_top_commands(store, limit=args.limit)
    elif args.command == "top-usernames":
        cmd_top_usernames(store, limit=args.limit)
    elif args.command == "top-ips":
        cmd_top_ips(store, limit=args.limit)
    elif args.command == "dashboard":
        cmd_dashboard(store, host=args.host, port=args.port)
    else:
        parser.print_help()
        sys.exit(1)

    store.close()


def _get_store(db_path, no_db=False):
    """Create a TelemetryStore, or a no-op store if DB is disabled."""
    if no_db:
        return _NoOpStore()
    return TelemetryStore(db_path)


class _NoOpStore:
    """A no-op telemetry store used when --no-db is specified."""

    def __init__(self):
        self.db_path = None

    def open(self):
        pass

    def close(self):
        pass

    def log_event(self, event):
        pass

    def record_session_finalize(self, *args, **kwargs):
        pass


if __name__ == "__main__":
    main()
