"""Local web dashboard for SSHintel security telemetry."""
from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from honeypot.telemetry_store import TelemetryStore


DEFAULT_DB_PATH = Path(__file__).parent.parent / "data" / "sshintel.db"


def create_app(db_path: str | os.PathLike | None = None) -> Flask:
    """Create and configure the Flask dashboard application.

    Args:
        db_path: Path to the SQLite telemetry database. If None, uses
            the default location (data/sshintel.db).
    """
    app = Flask(__name__)

    store = TelemetryStore(db_path if db_path else DEFAULT_DB_PATH)
    if store.db_path.exists():
        store.open()

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/metrics")
    def api_metrics():
        return jsonify({
            "sessions": store.count_sessions(),
            "unique_ips": store.unique_ips(),
            "auth_attempts": store.total_auth_attempts(),
            "auth_successes": store.successful_auths(),
            "auth_failures": store.failed_auth_attempts(),
            "commands": store.total_commands(),
        })

    @app.route("/api/top-commands")
    def api_top_commands():
        limit = request.args.get("limit", 10, type=int)
        return jsonify(store.top_commands(limit=limit))

    @app.route("/api/top-usernames")
    def api_top_usernames():
        limit = request.args.get("limit", 10, type=int)
        return jsonify(store.top_usernames(limit=limit))

    @app.route("/api/top-ips")
    def api_top_ips():
        limit = request.args.get("limit", 10, type=int)
        return jsonify(store.top_source_ips(limit=limit))

    @app.route("/api/recent-events")
    def api_recent_events():
        limit = request.args.get("limit", 50, type=int)
        return jsonify(store.get_recent_events(limit=limit))

    @app.route("/api/recent-sessions")
    def api_recent_sessions():
        limit = request.args.get("limit", 20, type=int)
        return jsonify(store.get_recent_sessions(limit=limit))

    @app.route("/api/activity")
    def api_activity():
        """Return event counts grouped by hour for the activity chart."""
        limit = request.args.get("hours", 24, type=int)
        rows = store.activity_by_hour(hours=limit)
        return jsonify(rows)

    return app