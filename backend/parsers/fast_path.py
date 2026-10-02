"""
Deterministic fast-path parser engine.
Executes parser SPECIFICATIONS (JSON structures), never arbitrary code.

Architecture (matching diagram):
  - BDPT tree is the primary routing mechanism
  - Each BDPT cluster can have multiple parser variants
  - execute_variant() runs a specific parser against a message
  - No sequential O(n) fallback in the main parse path

Classification: IMPLEMENTED
"""

from __future__ import annotations

import hashlib
import json
import re
import logging
from typing import Any

from backend.models import ParserSpecification, ParsedFields, ProcessingMode

logger = logging.getLogger(__name__)


class FastPathEngine:
    """
    Deterministic parser engine that executes validated parser specifications.
    
    Responsibilities (after architectural fix):
      - Store parser specs by parser_id
      - Execute a specific parser spec against a message (_execute_spec, execute_variant)
      - try_variants(): given a list of variant IDs from the BDPT leaf node, try each
        and return the first that succeeds with sufficient confidence
    
    BDPT routing is NOT done here. The unified DrainMiner in Tier1Matcher owns
    the tree. The pipeline asks Tier1Matcher for the matching cluster, gets back
    variant IDs, and calls try_variants() here to execute them.
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

    def get_spec(self, parser_id: str) -> ParserSpecification | None:
        """Get a parser spec by ID."""
        return self._parsers.get(parser_id)

    def compute_format_signature(self, message: str) -> str:
        """
        Compute a format signature from the message structure.
        Uses sorted key names found in key=value patterns.
        """
        keys = []
        for token in message.split():
            if "=" in token:
                key = token.split("=", 1)[0]
                keys.append(key.upper())
        if keys:
            signature_str = "|".join(sorted(keys))
        else:
            tokens = message.split()
            signature_str = f"LEN:{len(tokens)}|" + "|".join(
                "NUM" if t.replace(".", "").isdigit() else "SYM" if not t.isalnum() else "WORD"
                for t in tokens[:5]
            )
        return hashlib.md5(signature_str.encode()).hexdigest()

    def execute_variant(
        self, message: str, parser_id: str
    ) -> tuple[dict[str, Any], float]:
        """
        Execute a specific parser variant against a message.
        Returns: (parsed_fields_dict, confidence)
        """
        spec = self._parsers.get(parser_id)
        if not spec:
            return {}, 0.0
        return self._execute_spec(message, spec)

    def try_variants(
        self, message: str, variant_ids: list[str]
    ) -> tuple[str | None, ParsedFields | None, float]:
        """
        Try each variant in the list (in order) and return the first that succeeds.
        This is called by the pipeline after Tier1Matcher identifies a matching cluster.
        Returns: (parser_id, parsed_fields, confidence)
        """
        for variant_id in variant_ids:
            if variant_id not in self._parsers:
                continue
            fields, confidence = self._execute_spec(message, self._parsers[variant_id])
            if confidence > 0.0:
                parsed = ParsedFields(
                    fields=fields,
                    parser_id=variant_id,
                    processing_mode=ProcessingMode.FAST_PATH,
                    confidence=confidence,
                )
                return variant_id, parsed, confidence
        return None, None, 0.0

    def _execute_spec(
        self, message: str, spec: ParserSpecification
    ) -> tuple[dict[str, Any], float]:
        """Execute a single parser specification against a message."""
        parsed_data: dict[str, Any] = {}

        # 1. Try JSON parsing first
        try:
            parsed_json = json.loads(message)
            if isinstance(parsed_json, dict):
                for source_key, target_field in spec.fields.items():
                    if source_key in parsed_json:
                        parsed_data[target_field] = parsed_json[source_key]

                if spec.fields:
                    matched = sum(
                        1 for target in spec.fields.values() if target in parsed_data
                    )
                    confidence = matched / len(spec.fields)
                else:
                    confidence = 0.0
                return parsed_data, confidence
        except (json.JSONDecodeError, ValueError):
            pass

        # 2. Regex-based parsing
        if spec.regex_pattern:
            try:
                match = re.search(spec.regex_pattern, message)
                if match:
                    groups = {k.lower(): v for k, v in match.groupdict().items()}
                    for source_key, target_field in spec.fields.items():
                        source_key_lower = source_key.lower()
                        if source_key_lower in groups and groups[source_key_lower] is not None:
                            parsed_data[target_field] = groups[source_key_lower]
                else:
                    # Regex didn't match — fall back to KV parsing if spec has separators
                    if spec.field_separator:
                        pass  # Fall through to KV parsing below
                    else:
                        return {}, 0.0
            except re.error:
                if spec.field_separator:
                    pass  # Fall through to KV parsing below
                else:
                    return {}, 0.0

        # 3. Key-value based parsing (also used as fallback when regex fails)
        if not parsed_data and spec.field_separator:
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
            matched = sum(
                1 for target in spec.fields.values() if target in parsed_data
            )
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
        """Return all source field keys (lowercased) from loaded parser specifications."""
        keys: set[str] = set()
        for spec in self._parsers.values():
            if source_hint and spec.source_hint and source_hint.lower() not in spec.source_hint.lower():
                continue
            keys.update(k.lower() for k in spec.fields.keys())
        return keys
