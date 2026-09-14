"""
Format router — decides fast path vs adaptive path.
Classification: IMPLEMENTED
"""

from backend.models import ParsedFields, ProcessingCopy
from backend.parsers.fast_path import FastPathEngine
from backend.config import settings


class FormatRouter:
    """Routes events to fast path or adaptive path based on format signature matching."""

    def __init__(self, fast_path_engine: FastPathEngine):
        self.fast_path = fast_path_engine

    def route(self, processing_copy: ProcessingCopy) -> tuple[str, ParsedFields | None, str]:
        """
        Route a processing copy to fast path or adaptive path.
        Returns: (route: 'FAST_PATH'|'ADAPTIVE', parsed_fields, parser_id)
        """
        parser_id, parsed, confidence = self.fast_path.parse(processing_copy.sanitized_message)

        if parsed and confidence >= settings.fast_path_confidence_threshold:
            return "FAST_PATH", parsed, parser_id or ""

        return "ADAPTIVE", None, ""
