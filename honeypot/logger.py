import json
import logging
import uuid
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

base_dir = Path(__file__).parent.parent
log_dir = base_dir / 'log_files'
log_dir.mkdir(exist_ok=True)

# Global SQLite telemetry store, set once at startup when SQLite is enabled.
# Remains None when telemetry is disabled, so all no-op checks short-circuit.
_telemetry_store = None

creds_log_path = log_dir / 'creds_audits.log'
cmd_log_path = log_dir / 'cmd_audits.log'
events_log_path = log_dir / 'events.jsonl'

logging_format = logging.Formatter('%(message)s')

# --- Application / debug loggers -------------------------------------------
# These are for operating the honeypot (human-oriented), not for attacker
# telemetry. Credential attempts and raw commands are kept here to preserve
# the original v1.0 logging behaviour.

funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler(cmd_log_path, maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler(creds_log_path, maxBytes=2000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)

# --- Structured security event logger (JSON Lines) -------------------------
# Each event is one valid JSON object on one line. This is the machine-
# readable source of truth for attacker activity (connect, auth_attempt,
# auth_success, auth_failure, command, disconnect, tarpit).

event_logger = logging.getLogger('EventLogger')
event_logger.setLevel(logging.INFO)
event_handler = RotatingFileHandler(
    events_log_path, maxBytes=100000, backupCount=2, encoding='utf-8'
)
event_handler.setFormatter(logging_format)
event_logger.addHandler(event_handler)


def new_session_id():
    """Return a unique identifier for a connection/session (UUID4, as a string)."""
    return str(uuid.uuid4())


def utc_now_iso():
    """Return the current UTC time as an ISO-8601 string (with microseconds)."""
    return datetime.now(timezone.utc).isoformat()


def build_event(event_type, session_id=None, source_ip=None, **extra):
    """Build a structured security event dict from the given fields.

    ``event_type`` is required; ``session_id`` and ``source_ip`` are the common
    base fields shared by every event. Extra event-specific fields are only
    included when they are not ``None`` so the output stays compact.
    """
    event = {"timestamp": utc_now_iso(), "event_type": event_type}
    if session_id is not None:
        event["session_id"] = session_id
    if source_ip is not None:
        event["source_ip"] = source_ip
    for key, value in extra.items():
        if value is not None:
            event[key] = value
    return event


def serialize_event(event):
    """Serialize an event dict into a single line of valid JSON (no newlines).

    Always produces real JSON (double-quoted), never a Python representation.
    """
    return json.dumps(event, ensure_ascii=False, separators=(",", ":"))


def log_event(event_type, session_id=None, source_ip=None, **extra):
    """Write one structured security event to the JSONL log.

    A logging failure is reported through the console but never raised, so a
    broken logger cannot terminate the honeypot or an attacker session.
    """
    try:
        event = build_event(
            event_type, session_id=session_id, source_ip=source_ip, **extra
        )
        event_logger.info(serialize_event(event))
        # Mirror the event into the SQLite telemetry store if one is configured.
        if _telemetry_store is not None and _telemetry_store.is_open:
            _telemetry_store.log_event(event)
    except Exception as exc:
        print(f"!!! Failed to write security event ({event_type}): {exc}")


def set_telemetry_store(store):
    """Set the global SQLite telemetry store used by all event logging.

    Pass ``None`` to disable SQLite persistence.
    """
    global _telemetry_store
    _telemetry_store = store


def record_session_connect(session_id, source_ip, connected_at):
    """Record the start of a new session in the telemetry store (no-op if disabled)."""
    if _telemetry_store is not None and _telemetry_store.is_open:
        _telemetry_store.record_session_connect(session_id, source_ip, connected_at)


def record_session_finalize(session_id, username, ended_at, duration,
                            status, disconnect_reason):
    """Record a session's final state in the telemetry store (no-op if disabled)."""
    if _telemetry_store is not None and _telemetry_store.is_open:
        _telemetry_store.record_session_finalize(
            session_id, username, ended_at, duration, status, disconnect_reason
        )
