"""
OCSF-compatible Network Activity normalization.
Maps parsed fields to OCSF Network Activity (class_uid: 4001).

Uses "OCSF-compatible Network Activity representation" terminology.
Based on OCSF v1.1.0 schema.

Classification: IMPLEMENTED
"""

from __future__ import annotations

import time
from typing import Any

from backend.config import settings
from backend.models import OCSFEvent, ProcessingMode, RawEvent


class OCSFNormalizer:
    """Maps parsed fields to OCSF-compatible Network Activity (class_uid: 4001)."""

    ACTION_MAP: dict[str, tuple[int, str, int, str]] = {
        "ALLOW": (1, "Allowed", 1, "Allowed"),
        "PERMIT": (1, "Allowed", 1, "Allowed"),
        "ACCEPT": (1, "Allowed", 1, "Allowed"),
        "DENY": (2, "Denied", 2, "Blocked"),
        "DROP": (2, "Denied", 3, "Dropped"),
        "BLOCK": (2, "Denied", 2, "Blocked"),
        "REJECT": (2, "Denied", 2, "Blocked"),
        "RESET": (2, "Denied", 10, "Reset"),
    }

    PROTOCOL_NUM: dict[str, int] = {
        "TCP": 6, "UDP": 17, "ICMP": 1, "GRE": 47, "ESP": 50, "AH": 51, "SCTP": 132,
    }

    SEVERITY_MAP: dict[int, str] = {
        0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium",
        4: "High", 5: "Critical", 6: "Fatal",
    }

    def normalize(
        self,
        parsed_fields: dict[str, Any],
        raw_event: RawEvent,
        parser_id: str,
        parser_version: int,
        processing_mode: ProcessingMode,
        confidence: float,
    ) -> OCSFEvent:
        """Normalize parsed fields into OCSF-compatible structure."""

        # Extract endpoint fields
        src_ip = parsed_fields.get("source.ip")
        src_port = self._safe_int(parsed_fields.get("source.port"))
        dst_ip = parsed_fields.get("destination.ip")
        dst_port = self._safe_int(parsed_fields.get("destination.port"))

        # Protocol
        proto_name = str(parsed_fields.get("network.transport", "UNKNOWN")).upper()
        proto_num = self.PROTOCOL_NUM.get(proto_name, 0)

        # Action mapping
        raw_action = str(parsed_fields.get("action", "UNKNOWN")).upper()
        action_id, action, disposition_id, disposition = self.ACTION_MAP.get(
            raw_action, (0, "Unknown", 0, "Unknown")
        )

        # Severity: allowed=1(Informational), denied=3(Medium)
        severity_id = 1 if action_id == 1 else (3 if action_id == 2 else 0)
        severity = self.SEVERITY_MAP.get(severity_id, "Unknown")

        # Message from parsed fields
        message = parsed_fields.get("message", "")

        # Build src/dst endpoint dicts
        src_endpoint: dict[str, Any] = {}
        if src_ip:
            src_endpoint["ip"] = src_ip
        if src_port is not None:
            src_endpoint["port"] = src_port

        dst_endpoint: dict[str, Any] = {}
        if dst_ip:
            dst_endpoint["ip"] = dst_ip
        if dst_port is not None:
            dst_endpoint["port"] = dst_port

        # Connection info
        connection_info: dict[str, Any] = {
            "protocol_name": proto_name.lower(),
            "protocol_num": proto_num,
            "direction_id": 0,
            "direction": "Unknown",
        }

        # Metadata
        metadata = {
            "version": settings.ocsf_version,
            "product": {
                "name": "Universal Log Pre-processing Framework",
                "vendor_name": "SIH 2026 — NTRO",
                "version": "1.0.0-prototype",
            },
            "profiles": [settings.ocsf_profile],
        }

        now_ms = int(time.time() * 1000)

        return OCSFEvent(
            category_uid=4,
            category_name="Network Activity",
            class_uid=4001,
            class_name="Network Activity",
            activity_id=6,
            activity_name="Traffic",
            type_uid=400106,
            type_name="Network Activity: Traffic",
            severity_id=severity_id,
            severity=severity,
            time=now_ms,
            action_id=action_id,
            action=action,
            disposition_id=disposition_id,
            disposition=disposition,
            src_endpoint=src_endpoint,
            dst_endpoint=dst_endpoint,
            connection_info=connection_info,
            metadata=metadata,
            message=message,
            raw_event_id=raw_event.event_id,
            raw_sha256=raw_event.raw_sha256,
            parser_id=parser_id,
            parser_version=parser_version,
            processing_mode=processing_mode.value,
            confidence=confidence,
            schema_version=settings.ocsf_version,
        )

    @staticmethod
    def _safe_int(val: Any) -> int | None:
        if val is None:
            return None
        try:
            return int(val)
        except (ValueError, TypeError):
            return None
