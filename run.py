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
