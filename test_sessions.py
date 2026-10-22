import sqlite3
import tempfile
import os
from pathlib import Path

# Create fresh db
db_path = Path(tempfile.mktemp(suffix='.db'))
db_path.unlink(missing_ok=True)

conn = sqlite3.connect(str(db_path))
print('Connected')
conn.execute('PRAGMA journal_mode=WAL')
print('journal_mode set')

# Run CREATE TABLES SQL
CREATE_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    session_id      TEXT,
    source_ip       TEXT,
    source_port     INTEGER,
    username        TEXT,
    command         TEXT,
    cwd             TEXT,
    metadata        TEXT,
    event_id        TEXT,
    schema_version  TEXT,
    legacy_event_type TEXT,
    sensor_id       TEXT,
    country         TEXT,
    asn             TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id      TEXT PRIMARY KEY,
    source_ip       TEXT,
    username        TEXT,
    started_at      TEXT,
    ended_at        TEXT,
    duration        REAL,
    status          TEXT,
    disconnect_reason TEXT
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""
conn.executescript(CREATE_TABLES_SQL)
print('Tables created via executescript')

# Check tables
tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
print("Tables:", tables)

# Run migration
existing = {row[1] for row in conn.execute('PRAGMA table_info(events)')}
print('Existing events columns:', existing)

for col in ['event_id', 'schema_version', 'legacy_event_type', 'sensor_id', 'country', 'asn']:
    if col not in existing:
        conn.execute(f'ALTER TABLE events ADD COLUMN {col} TEXT')
        print(f'Added {col}')

# Check sessions columns
sessions_cols = [row[1] for row in conn.execute('PRAGMA table_info(sessions)')]
print('Sessions columns:', sessions_cols)

# Create indexes - but with debugging
indexes = [
    'CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);',
    'CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);',
    'CREATE INDEX IF NOT EXISTS idx_events_session_id ON events(session_id);',
    'CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);',
    'CREATE INDEX IF NOT EXISTS idx_events_username ON events(username);',
    'CREATE INDEX IF NOT EXISTS idx_events_legacy_event_type ON events(legacy_event_type);',
    'CREATE INDEX IF NOT EXISTS idx_events_sensor_id ON events(sensor_id);',
    'CREATE INDEX IF NOT EXISTS idx_events_country ON events(country);',
    'CREATE INDEX IF NOT EXISTS idx_events_asn ON events(asn);',
    'CREATE INDEX IF NOT EXISTS idx_events_source_port ON events(source_port);',
    'CREATE INDEX IF NOT EXISTS idx_sessions_source_ip ON sessions(source_ip);',
    'CREATE INDEX IF NOT EXISTS idx_sessions_started_at ON sessions(started_at);',
]

for stmt in indexes:
    try:
        conn.execute(stmt)
        print(f'OK: {stmt[:50]}...')
    except Exception as e:
        print(f'ERROR: {stmt[:60]}...')
        print(f'  Exception: {e}')
        import traceback
        traceback.print_exc()

conn.close()
db_path.unlink(missing_ok=True)
print('Done!')