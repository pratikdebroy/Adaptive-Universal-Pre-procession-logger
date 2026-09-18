"""
Deterministic fast-path parser engine.
Executes parser SPECIFICATIONS (JSON structures), never arbitrary code.

Classification: IMPLEMENTED
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from backend.models import ParserSpecification, ParsedFields, ProcessingMode


class FastPathEngine:
    """
    Deterministic parser engine that executes validated parser specifications.
    No eval(), no exec(), no code generation — only structured field extraction.
    """

    def __init__(self):
        self._parsers: dict[str, ParserSpecification] = {}

    def load_parser(self, parser_id: str, spec: ParserSpecification):
        """Load a parser specification into the in-memory cache."""
        self._parsers[parser_id] = spec

    def remove_parser(self, parser_id: str):
        """Remove a parser from the cache."""
        self._parsers.pop(parser_id, None)

    def atomic_swap(self, parser_id: str, new_spec: ParserSpecification):
        """Atomically replace a parser spec in cache."""
        self._parsers[parser_id] = new_spec

    def compute_format_signature(self, message: str) -> str:
        """
        Compute a format signature from the message structure.
        Uses sorted key names found in key=value patterns.
        """
        keys = []
        # Extract keys from key=value patterns
        for token in message.split():
            if "=" in token:
                key = token.split("=", 1)[0]
                keys.append(key.upper())
        if keys:
            signature_str = "|".join(sorted(keys))
        else:
            # For non-KV formats, use token structure
            tokens = message.split()
            signature_str = f"LEN:{len(tokens)}|" + "|".join(
                "NUM" if t.replace(".", "").isdigit() else "SYM" if not t.isalnum() else "WORD"
                for t in tokens[:5]
            )
        return hashlib.md5(signature_str.encode()).hexdigest()

    def parse(self, message: str) -> tuple[str | None, ParsedFields | None, float]:
        """
        Try all loaded parsers against the message.
        Returns: (parser_id, parsed_fields, confidence)
        """
        best_id: str | None = None
        best_fields: dict[str, Any] | None = None
        best_confidence = 0.0

        for parser_id, spec in self._parsers.items():
            fields, confidence = self._execute_spec(message, spec)
            if confidence > best_confidence:
                best_confidence = confidence
                best_id = parser_id
                best_fields = fields

        if best_id and best_fields and best_confidence > 0:
            parsed = ParsedFields(
                fields=best_fields,
                parser_id=best_id,
                processing_mode=ProcessingMode.FAST_PATH,
                confidence=best_confidence,
            )
            return best_id, parsed, best_confidence

        return None, None, 0.0

    def _execute_spec(self, message: str, spec: ParserSpecification) -> tuple[dict[str, Any], float]:
        """Execute a single parser specification against a message."""
        parsed_data: dict[str, Any] = {}

        # 1. Try JSON parsing first
        import json
        try:
            parsed_json = json.loads(message)
            if isinstance(parsed_json, dict):
                for source_key, target_field in spec.fields.items():
                    if source_key in parsed_json:
                        parsed_data[target_field] = parsed_json[source_key]
                
                if spec.fields:
                    matched = sum(1 for target in spec.fields.values() if target in parsed_data)
                    confidence = matched / len(spec.fields)
                else:
                    confidence = 0.0
                return parsed_data, confidence
        except json.JSONDecodeError:
            pass

        if spec.regex_pattern:
            # Regex-based parsing
            try:
                match = re.search(spec.regex_pattern, message)
                if match:
                    groups = match.groupdict()
                    for source_key, target_field in spec.fields.items():
                        if source_key in groups and groups[source_key] is not None:
                            parsed_data[target_field] = groups[source_key]
                else:
                    return {}, 0.0
            except re.error:
                return {}, 0.0
        else:
            # Key-value based parsing
            entry_sep = spec.entry_separator or " "
            field_sep = spec.field_separator or "="
            tokens = message.split(entry_sep)

            for token in tokens:
                token = token.strip()
                if field_sep in token:
                    key, value = token.split(field_sep, 1)
                    key = key.strip()
                    value = value.strip()
                    if key in spec.fields:
                        parsed_data[spec.fields[key]] = value

        # Calculate confidence
        if spec.fields:
            matched = sum(1 for target in spec.fields.values() if target in parsed_data)
            confidence = matched / len(spec.fields)
        else:
            confidence = 0.0

        return parsed_data, confidence

    def get_loaded_parsers(self) -> dict[str, dict]:
        """Return info about loaded parsers."""
        return {
            pid: {
                "template": spec.template,
                "fields": spec.fields,
                "source_hint": spec.source_hint,
            }
            for pid, spec in self._parsers.items()
        }

    def get_parser_count(self) -> int:
        return len(self._parsers)

    def get_known_keys(self, source_hint: str | None = None) -> set[str]:
        """Return all source field keys (lowercased) from loaded parser specifications.
        If source_hint is provided, filter by that source to avoid cross-source key pollution."""
        keys: set[str] = set()
        for spec in self._parsers.values():
            if source_hint and spec.source_hint and source_hint.lower() not in spec.source_hint.lower():
                continue
            keys.update(k.lower() for k in spec.fields.keys())
        return keys
