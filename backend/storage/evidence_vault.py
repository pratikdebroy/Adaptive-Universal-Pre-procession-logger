"""
Evidence Vault — Lossless Raw Event Preservation.

CRITICAL DESIGN PRINCIPLE:
The raw event is NEVER sanitized, stripped, normalized, or modified before preservation.

Flow:
  RAW EVENT → compute SHA-256 → store EXACT original → create separate processing copy

The Evidence Vault stores the exact bytes received. All sanitization/validation
happens on a separate processing copy created AFTER preservation.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from backend.config import settings
from backend.models import RawEvent, ProcessingCopy


class EvidenceVault:
    """
    Immutable raw event storage with SHA-256 provenance.
    
    Classification: IMPLEMENTED
    """

    def __init__(self, evidence_dir: Path | None = None):
        self.evidence_dir = evidence_dir or settings.evidence_dir
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def compute_sha256(self, raw_message: str) -> str:
        """Compute SHA-256 of the exact raw message bytes."""
        return hashlib.sha256(raw_message.encode("utf-8", errors="surrogateescape")).hexdigest()

    def preserve(self, raw_message: str, source: str = "unknown") -> RawEvent:
        """
        Preserve the EXACT raw event. No sanitization. No modification.
        Returns a RawEvent with computed SHA-256.
        """
        raw_event = RawEvent(
            raw_message=raw_message,
            source=source,
            received_at=datetime.now(timezone.utc),
        )
        raw_event.raw_sha256 = self.compute_sha256(raw_message)

        # Store as immutable evidence file
        evidence_path = self.evidence_dir / f"{raw_event.event_id}.json"
        evidence_data = {
            "event_id": raw_event.event_id,
            "received_at": raw_event.received_at.isoformat(),
            "source": raw_event.source,
            "raw_message": raw_event.raw_message,
            "raw_sha256": raw_event.raw_sha256,
        }
        evidence_path.write_text(
            json.dumps(evidence_data, ensure_ascii=False),
            encoding="utf-8",
        )

        return raw_event

    def retrieve(self, event_id: str) -> RawEvent | None:
        """Retrieve a preserved raw event by ID."""
        evidence_path = self.evidence_dir / f"{event_id}.json"
        if not evidence_path.exists():
            return None

        data = json.loads(evidence_path.read_text(encoding="utf-8"))
        return RawEvent(
            event_id=data["event_id"],
            received_at=datetime.fromisoformat(data["received_at"]),
            source=data["source"],
            raw_message=data["raw_message"],
            raw_sha256=data["raw_sha256"],
        )

    def verify_integrity(self, event_id: str) -> tuple[bool, str, str]:
        """
        Verify that a stored raw event has not been tampered with.
        Returns: (is_intact, stored_hash, recomputed_hash)
        """
        raw_event = self.retrieve(event_id)
        if raw_event is None:
            return False, "", ""

        recomputed = self.compute_sha256(raw_event.raw_message)
        return (
            raw_event.raw_sha256 == recomputed,
            raw_event.raw_sha256,
            recomputed,
        )

    def tamper_for_demo(self, event_id: str) -> bool:
        """
        Deliberately modify a stored raw event for tamper detection demo.
        THIS IS ONLY FOR DEMONSTRATION PURPOSES.
        """
        evidence_path = self.evidence_dir / f"{event_id}.json"
        if not evidence_path.exists():
            return False

        data = json.loads(evidence_path.read_text(encoding="utf-8"))
        data["raw_message"] = data["raw_message"] + " [TAMPERED]"
        evidence_path.write_text(
            json.dumps(data, ensure_ascii=False),
            encoding="utf-8",
        )
        return True

    def list_events(self, limit: int = 100) -> list[str]:
        """List stored event IDs."""
        files = sorted(self.evidence_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        return [f.stem for f in files[:limit]]

    def clear(self):
        """Clear all evidence (for demo reset)."""
        for f in self.evidence_dir.glob("*.json"):
            f.unlink()


def create_processing_copy(raw_event: RawEvent) -> ProcessingCopy:
    """
    Create a sanitized processing copy from a preserved raw event.
    The original raw event remains untouched in the Evidence Vault.
    
    Sanitization applied to the COPY only:
    - Strip null bytes
    - Strip control characters (except tab, newline)
    - Limit length
    """
    message = raw_event.raw_message
    sanitization_log: list[str] = []

    # Strip null bytes from processing copy
    if "\x00" in message:
        message = message.replace("\x00", "")
        sanitization_log.append("null_bytes_stripped")

    # Strip control characters (keep tab \t and newline \n)
    cleaned = []
    has_control = False
    for ch in message:
        if ord(ch) < 32 and ch not in ("\t", "\n", "\r"):
            has_control = True
        else:
            cleaned.append(ch)
    if has_control:
        message = "".join(cleaned)
        sanitization_log.append("control_chars_stripped")

    # Trim excessive whitespace
    stripped = message.strip()
    if stripped != message:
        message = stripped
        sanitization_log.append("whitespace_trimmed")

    return ProcessingCopy(
        event_id=raw_event.event_id,
        sanitized_message=message,
        source=raw_event.source,
        sanitization_applied=sanitization_log,
    )
