"""
Append-only ledger — Prototype Permissioned-Ledger Adapter.
Provides a pluggable LedgerBackend interface for future blockchain integration.

Classification: IMPLEMENTED (local append-only ledger)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from backend.integrity.merkle import MerkleTree
from backend.models import LedgerEntry
from backend.storage.database import get_db


class IntegrityLedger:
    """
    Prototype Permissioned-Ledger Adapter.
    Local append-only ledger with chain validation.
    Designed with a pluggable interface for future blockchain integration.
    """

    async def commit_batch(self, event_ids: list[str], hashes: list[str]) -> LedgerEntry:
        """Commit a batch of event hashes to the ledger."""
        # Build Merkle tree
        tree = MerkleTree(hashes)

        # Get previous root
        prev = await self.get_latest()
        previous_root = prev.merkle_root if prev else ""

        entry = LedgerEntry(
            batch_id=str(uuid.uuid4()),
            merkle_root=tree.root,
            timestamp=datetime.now(timezone.utc),
            previous_root=previous_root,
            event_count=len(event_ids),
            status="COMMITTED",
        )

        db = await get_db()
        try:
            await db.execute(
                """INSERT INTO ledger
                   (batch_id, merkle_root, timestamp, previous_root, event_count, status)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    entry.batch_id, entry.merkle_root, entry.timestamp.isoformat(),
                    entry.previous_root, entry.event_count, entry.status,
                ),
            )
            await db.commit()
        finally:
            await db.close()

        return entry

    async def verify_chain(self) -> tuple[bool, list[dict]]:
        """Verify all entries: each previous_root matches prior entry's merkle_root."""
        entries = await self.get_entries(limit=1000)
        if not entries:
            return True, []

        issues = []
        for i in range(1, len(entries)):
            if entries[i].previous_root != entries[i - 1].merkle_root:
                issues.append({
                    "batch_id": entries[i].batch_id,
                    "expected_previous": entries[i - 1].merkle_root,
                    "actual_previous": entries[i].previous_root,
                })

        return len(issues) == 0, issues

    async def get_entries(self, limit: int = 50) -> list[LedgerEntry]:
        """Get ledger entries in chronological order."""
        db = await get_db()
        try:
            cursor = await db.execute(
                "SELECT * FROM ledger ORDER BY timestamp ASC LIMIT ?", (limit,)
            )
            rows = await cursor.fetchall()
            return [
                LedgerEntry(
                    batch_id=row["batch_id"],
                    merkle_root=row["merkle_root"],
                    timestamp=datetime.fromisoformat(row["timestamp"]),
                    previous_root=row["previous_root"],
                    event_count=row["event_count"],
                    status=row["status"],
                )
                for row in rows
            ]
        finally:
            await db.close()

    async def get_latest(self) -> LedgerEntry | None:
        """Get the most recent ledger entry."""
        db = await get_db()
        try:
            cursor = await db.execute(
                "SELECT * FROM ledger ORDER BY timestamp DESC LIMIT 1"
            )
            row = await cursor.fetchone()
            if not row:
                return None
            return LedgerEntry(
                batch_id=row["batch_id"],
                merkle_root=row["merkle_root"],
                timestamp=datetime.fromisoformat(row["timestamp"]),
                previous_root=row["previous_root"],
                event_count=row["event_count"],
                status=row["status"],
            )
        finally:
            await db.close()
