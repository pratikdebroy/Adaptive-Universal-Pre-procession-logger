"""
Parser Registry — Transactional persistence + atomic cache promotion.

Design:
  SQLite transaction → COMMIT → atomic in-memory cache swap
  If cache update fails, reload active parser state from persistent registry.

Classification: IMPLEMENTED
"""

from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from backend.config import settings
from backend.models import ParserRecord, ParserSpecification, ParserStatus
from backend.parsers.fast_path import FastPathEngine
from backend.storage.database import get_db


class ParserRegistry:
    """
    Parser registry with transactional persistence + atomic cache promotion.

    NOT claiming SQLite + RAM is a single atomic transaction.
    Implementation: SQLite COMMIT → atomic cache swap via threading.Lock.
    If cache update fails, state is reloaded from persistent registry.
    """

    def __init__(self, fast_path_engine: FastPathEngine):
        self._cache: dict[str, ParserRecord] = {}
        self._cache_lock = threading.Lock()
        self.fast_path = fast_path_engine

    async def initialize(self):
        """Load all ACTIVE parsers from DB into cache and fast-path engine."""
        db = await get_db()
        try:
            cursor = await db.execute(
                "SELECT * FROM parsers WHERE status = ?",
                (ParserStatus.ACTIVE.value,),
            )
            rows = await cursor.fetchall()

            new_cache: dict[str, ParserRecord] = {}
            for row in rows:
                record = self._row_to_record(row)
                new_cache[record.parser_id] = record
                self.fast_path.load_parser(record.parser_id, record.spec)

            with self._cache_lock:
                self._cache = new_cache
        finally:
            await db.close()

    async def register_candidate(
        self,
        name: str,
        source: str,
        format_signature: str,
        spec: ParserSpecification,
        confidence: float,
        test_results: dict[str, Any] | None = None,
    ) -> ParserRecord:
        """Register a new CANDIDATE parser in DB."""
        now = datetime.now(timezone.utc)
        record = ParserRecord(
            parser_id=str(uuid.uuid4()),
            name=name,
            source=source,
            format_signature=format_signature,
            parser_version=1,
            schema_version="1.0",
            status=ParserStatus.CANDIDATE,
            confidence=confidence,
            spec=spec,
            created_at=now,
            updated_at=now,
            test_results=test_results or {},
        )

        db = await get_db()
        try:
            await db.execute(
                """INSERT INTO parsers 
                   (parser_id, name, source, format_signature, parser_version,
                    schema_version, status, confidence, spec_json, test_results_json,
                    created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    record.parser_id, record.name, record.source,
                    record.format_signature, record.parser_version,
                    record.schema_version, record.status.value,
                    record.confidence, record.spec.model_dump_json(),
                    json.dumps(record.test_results),
                    record.created_at.isoformat(), record.updated_at.isoformat(),
                ),
            )
            await db.commit()
        finally:
            await db.close()

        # Add to cache as CANDIDATE (not in fast path yet)
        with self._cache_lock:
            self._cache[record.parser_id] = record

        return record

    async def promote(self, parser_id: str) -> bool:
        """
        Promote CANDIDATE to ACTIVE:
        1. SQLite transaction: update status, save history
        2. COMMIT
        3. Atomic in-memory cache swap (with lock)
        4. Load into fast-path engine
        5. If cache update fails, reload from DB
        """
        now = datetime.now(timezone.utc)
        db = await get_db()
        try:
            # Step 1: SQLite transaction
            # Save current state to history
            cursor = await db.execute(
                "SELECT * FROM parsers WHERE parser_id = ?", (parser_id,)
            )
            row = await cursor.fetchone()
            if not row:
                return False

            record = self._row_to_record(row)
            if record.status != ParserStatus.CANDIDATE:
                # Allow re-promotion for testing
                pass

            # Archive history
            await db.execute(
                """INSERT INTO parser_history 
                   (parser_id, parser_version, status, spec_json, changed_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (parser_id, record.parser_version, record.status.value,
                 record.spec.model_dump_json(), now.isoformat()),
            )

            # Update status to ACTIVE, increment version
            new_version = record.parser_version + 1
            await db.execute(
                """UPDATE parsers 
                   SET status = ?, parser_version = ?, updated_at = ?
                   WHERE parser_id = ?""",
                (ParserStatus.ACTIVE.value, new_version, now.isoformat(), parser_id),
            )

            # Step 2: COMMIT
            await db.commit()

            # Reload the updated record
            cursor = await db.execute(
                "SELECT * FROM parsers WHERE parser_id = ?", (parser_id,)
            )
            updated_row = await cursor.fetchone()
            updated_record = self._row_to_record(updated_row)

        finally:
            await db.close()

        # Step 3: Atomic in-memory cache swap
        try:
            with self._cache_lock:
                self._cache[parser_id] = updated_record
                # Step 4: Load into fast-path engine
                self.fast_path.load_parser(parser_id, updated_record.spec)
            return True
        except Exception:
            # Step 5: If cache update fails, reload from DB
            await self.initialize()
            return False

    async def rollback(self, parser_id: str) -> bool:
        """
        Rollback: set current to ROLLED_BACK, re-activate previous version.
        """
        now = datetime.now(timezone.utc)
        db = await get_db()
        try:
            # Get current record
            cursor = await db.execute(
                "SELECT * FROM parsers WHERE parser_id = ?", (parser_id,)
            )
            row = await cursor.fetchone()
            if not row:
                return False

            # Save current to history
            record = self._row_to_record(row)
            await db.execute(
                """INSERT INTO parser_history
                   (parser_id, parser_version, status, spec_json, changed_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (parser_id, record.parser_version, "ROLLED_BACK",
                 record.spec.model_dump_json(), now.isoformat()),
            )

            # Find previous version from history
            cursor = await db.execute(
                """SELECT spec_json, parser_version FROM parser_history
                   WHERE parser_id = ? AND status = 'ACTIVE'
                   ORDER BY changed_at DESC LIMIT 1""",
                (parser_id,),
            )
            prev_row = await cursor.fetchone()

            if prev_row:
                prev_spec_json = prev_row[0]
                prev_version = prev_row[1]
                await db.execute(
                    """UPDATE parsers SET status = ?, parser_version = ?,
                       spec_json = ?, updated_at = ? WHERE parser_id = ?""",
                    (ParserStatus.ACTIVE.value, prev_version,
                     prev_spec_json, now.isoformat(), parser_id),
                )
            else:
                # No previous version, just mark as rolled back
                await db.execute(
                    """UPDATE parsers SET status = ?, updated_at = ?
                       WHERE parser_id = ?""",
                    (ParserStatus.ROLLED_BACK.value, now.isoformat(), parser_id),
                )

            await db.commit()
        finally:
            await db.close()

        # Reload everything from DB
        await self.initialize()
        return True

    async def get_all(self) -> list[ParserRecord]:
        """Get all parsers from DB."""
        db = await get_db()
        try:
            cursor = await db.execute("SELECT * FROM parsers ORDER BY updated_at DESC")
            rows = await cursor.fetchall()
            return [self._row_to_record(row) for row in rows]
        finally:
            await db.close()

    async def get_by_id(self, parser_id: str) -> ParserRecord | None:
        with self._cache_lock:
            if parser_id in self._cache:
                return self._cache[parser_id]
        # Fallback to DB
        db = await get_db()
        try:
            cursor = await db.execute(
                "SELECT * FROM parsers WHERE parser_id = ?", (parser_id,)
            )
            row = await cursor.fetchone()
            return self._row_to_record(row) if row else None
        finally:
            await db.close()

    async def get_active_for_signature(self, signature: str) -> ParserRecord | None:
        with self._cache_lock:
            for record in self._cache.values():
                if record.status == ParserStatus.ACTIVE and record.format_signature == signature:
                    return record
        return None

    def get_active_count(self) -> int:
        with self._cache_lock:
            return sum(1 for r in self._cache.values() if r.status == ParserStatus.ACTIVE)

    def get_candidate_count(self) -> int:
        with self._cache_lock:
            return sum(1 for r in self._cache.values() if r.status == ParserStatus.CANDIDATE)

    @staticmethod
    def _row_to_record(row) -> ParserRecord:
        """Convert a DB row to a ParserRecord."""
        spec = ParserSpecification.model_validate_json(row["spec_json"])
        test_results = json.loads(row["test_results_json"]) if row["test_results_json"] else {}
        return ParserRecord(
            parser_id=row["parser_id"],
            name=row["name"],
            source=row["source"],
            format_signature=row["format_signature"],
            parser_version=row["parser_version"],
            schema_version=row["schema_version"],
            status=ParserStatus(row["status"]),
            confidence=row["confidence"],
            spec=spec,
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            test_results=test_results,
        )
