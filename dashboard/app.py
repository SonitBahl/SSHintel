"""Local web dashboard for SSHintel security telemetry."""
from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, abort, jsonify, render_template, request

from honeypot.telemetry_store import TelemetryStore


DEFAULT_DB_PATH = Path(__file__).parent.parent / "data" / "sshintel.db"


def _synthesize_session(events):
    """Build a minimal session summary from events when no finalize record exists."""
    if not events:
        return None
    first = events[0]
    last = events[-1]
    # Find the most common non-empty username
    usernames = [e.get("username") for e in events if e.get("username")]
    username = max(set(usernames), key=usernames.count) if usernames else None
    # Find the most common non-empty source_ip
    ips = [e.get("source_ip") for e in events if e.get("source_ip")]
    source_ip = max(set(ips), key=ips.count) if ips else ""
    # Determine auth result from events
    auth_success = any(e.get("event_type") == "auth_success" for e in events)
    auth_failure = any(e.get("event_type") == "auth_failure" for e in events)
    if auth_success:
        status = "success"
    elif auth_failure:
        status = "failure"
    else:
        status = "unknown"
    return {
        "session_id": first.get("session_id"),
        "source_ip": source_ip,
        "username": username,
        "started_at": first.get("timestamp"),
        "ended_at": last.get("timestamp"),
        "duration": None,
        "status": status,
        "disconnect_reason": None,
    }


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

    @app.route("/session/<session_id>")
    def session_view(session_id):
        if not store.is_open:
            abort(404)
        session = store.get_session(session_id)
        if session is None:
            # Check if there are events for this session
            events = store.get_session_events(session_id, limit=1)
            if not events:
                abort(404)
        return render_template("session.html", session_id=session_id)

    @app.route("/api/session/<session_id>")
    def api_session(session_id):
        if not store.is_open:
            return jsonify({"error": "no_database"}), 404
        session = store.get_session(session_id)
        events = store.get_session_events(session_id)
        if session is None and not events:
            return jsonify({"error": "not_found"}), 404
        # Synthesize a minimal session summary from events if no finalize record
        if session is None:
            session = _synthesize_session(events)
        return jsonify({"session": session, "events": events})

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