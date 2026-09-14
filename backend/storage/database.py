"""
Async SQLite database layer.
Schema for: events, parsers, quarantine, ledger, metrics.
"""

import json
import aiosqlite
from pathlib import Path
from backend.config import settings

DB_PATH = str(settings.db_path)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS raw_events (
    event_id TEXT PRIMARY KEY,
    received_at TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'unknown',
    raw_message TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    evidence_path TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS processed_events (
    event_id TEXT PRIMARY KEY,
    raw_event_id TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    parser_id TEXT DEFAULT '',
    parser_name TEXT DEFAULT '',
    parser_version INTEGER DEFAULT 0,
    processing_mode TEXT NOT NULL,
    confidence REAL DEFAULT 0.0,
    ocsf_json TEXT DEFAULT '{}',
    validation_result TEXT DEFAULT '',
    tier_detail TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY (raw_event_id) REFERENCES raw_events(event_id)
);

CREATE TABLE IF NOT EXISTS parsers (
    parser_id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    format_signature TEXT NOT NULL DEFAULT '',
    parser_version INTEGER NOT NULL DEFAULT 1,
    schema_version TEXT NOT NULL DEFAULT '1.0',
    status TEXT NOT NULL DEFAULT 'CANDIDATE',
    confidence REAL DEFAULT 0.0,
    spec_json TEXT NOT NULL DEFAULT '{}',
    test_results_json TEXT DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS parser_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parser_id TEXT NOT NULL,
    parser_version INTEGER NOT NULL,
    status TEXT NOT NULL,
    spec_json TEXT NOT NULL,
    changed_at TEXT NOT NULL,
    FOREIGN KEY (parser_id) REFERENCES parsers(parser_id)
);

CREATE TABLE IF NOT EXISTS quarantine (
    quarantine_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    raw_message TEXT NOT NULL,
    raw_sha256 TEXT DEFAULT '',
    source TEXT DEFAULT 'unknown',
    detected_format TEXT DEFAULT 'unknown',
    reason TEXT NOT NULL,
    failed_check TEXT DEFAULT '',
    severity TEXT DEFAULT 'MEDIUM',
    detail TEXT DEFAULT '',
    validation_failures TEXT DEFAULT '[]',
    metadata TEXT DEFAULT '{}',
    timestamp TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'QUARANTINED'
);

CREATE TABLE IF NOT EXISTS ledger (
    batch_id TEXT PRIMARY KEY,
    merkle_root TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    previous_root TEXT DEFAULT '',
    event_count INTEGER DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'COMMITTED'
);

CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    metric_name TEXT NOT NULL,
    metric_value REAL NOT NULL,
    recorded_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_parsers_status ON parsers(status);
CREATE INDEX IF NOT EXISTS idx_parsers_signature ON parsers(format_signature);
CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine(status);
CREATE INDEX IF NOT EXISTS idx_processed_mode ON processed_events(processing_mode);
"""


async def get_db() -> aiosqlite.Connection:
    """Get a database connection."""
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA foreign_keys=ON")
    return db


async def init_db():
    """Initialize the database schema."""
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    db = await get_db()
    try:
        await db.executescript(SCHEMA_SQL)
        # Migrate quarantine table columns if missing in existing database
        cursor = await db.execute("PRAGMA table_info(quarantine)")
        cols = {row["name"] for row in await cursor.fetchall()}
        if "raw_sha256" not in cols:
            await db.execute("ALTER TABLE quarantine ADD COLUMN raw_sha256 TEXT DEFAULT ''")
        if "detected_format" not in cols:
            await db.execute("ALTER TABLE quarantine ADD COLUMN detected_format TEXT DEFAULT 'unknown'")
        if "failed_check" not in cols:
            await db.execute("ALTER TABLE quarantine ADD COLUMN failed_check TEXT DEFAULT ''")
        if "severity" not in cols:
            await db.execute("ALTER TABLE quarantine ADD COLUMN severity TEXT DEFAULT 'MEDIUM'")
        if "metadata" not in cols:
            await db.execute("ALTER TABLE quarantine ADD COLUMN metadata TEXT DEFAULT '{}'")
        await db.commit()
    finally:
        await db.close()


async def reset_db():
    """Reset the database (for demo/testing)."""
    db_path = Path(DB_PATH)
    if db_path.exists():
        db_path.unlink()
    await init_db()
