"""
Structural token analysis — Tier 2 adaptive parsing.

Tokenizes log lines, identifies key-value patterns, classifies value types,
and produces candidate OCSF field mappings with EVIDENCE-BASED confidence.

Tier-2 identifies STRUCTURE. Semantic ambiguity is escalated to Tier-3.

Two independent confidence scores:
  - structural_confidence: How well we understand token structure (KV pairs, types)
  - semantic_confidence: How confidently we can map source fields to OCSF targets

Classification: IMPLEMENTED
"""

from __future__ import annotations

import enum
import re
from typing import Any

from pydantic import BaseModel

from backend.config import settings
from backend.models import ParserSpecification


class TokenType(str, enum.Enum):
    KEY = "KEY"
    VALUE = "VALUE"
    SEPARATOR = "SEPARATOR"
    OPERATOR = "OPERATOR"
    UNKNOWN = "UNKNOWN"


class ValueType(str, enum.Enum):
    IP = "IP"
    PORT = "PORT"
    PROTOCOL = "PROTOCOL"
    TIMESTAMP = "TIMESTAMP"
    ACTION = "ACTION"
    STRING = "STRING"
    NUMBER = "NUMBER"
    UNKNOWN = "UNKNOWN"


class EvidenceType(str, enum.Enum):
    """How a source field was mapped to an OCSF target."""
    EXACT_KNOWN_PARSER = "EXACT_KNOWN_PARSER"   # Key exists in an active parser
    ALIAS_MATCH = "ALIAS_MATCH"                 # Key found in FIELD_NAME_MAP only
    VALUE_TYPE_INFERENCE = "VALUE_TYPE_INFERENCE" # Inferred from value classification
    UNRESOLVED = "UNRESOLVED"                   # No mapping evidence


# Evidence weights for semantic confidence calculation
EVIDENCE_WEIGHTS: dict[EvidenceType, float] = {
    EvidenceType.EXACT_KNOWN_PARSER: 1.0,
    EvidenceType.ALIAS_MATCH: 0.5,
    EvidenceType.VALUE_TYPE_INFERENCE: 0.3,
    EvidenceType.UNRESOLVED: 0.0,
}


class FieldMapping(BaseModel):
    """A candidate field mapping with evidence."""
    source_field: str
    candidate_target: str
    evidence_type: EvidenceType
    evidence_weight: float
    value_type: ValueType
    value_sample: str


class StructuralToken(BaseModel):
    token: str
    token_type: TokenType
    value_type: ValueType
    position: int


# Maps known field name patterns to OCSF-compatible target fields
# These are used as EVIDENCE, not as certainty.
# Ambiguous names like "source", "destination", "client", "server" are intentionally excluded:
# they only map to source.ip/destination.ip if value-type inference confirms an IP address.
FIELD_NAME_MAP: dict[str, str] = {
    "src": "source.ip",
    "src_ip": "source.ip",
    "srcip": "source.ip",
    "source_ip": "source.ip",
    "saddr": "source.ip",
    "client_ip": "source.ip",
    "remote_ip": "source.ip",
    "dst": "destination.ip",
    "dst_ip": "destination.ip",
    "dest_ip": "destination.ip",
    "dstip": "destination.ip",
    "destination_ip": "destination.ip",
    "daddr": "destination.ip",
    "server_ip": "destination.ip",
    "proto": "network.transport",
    "protocol": "network.transport",
    "dpt": "destination.port",
    "dst_port": "destination.port",
    "port": "destination.port",
    "dport": "destination.port",
    "dest_port": "destination.port",
    "spt": "source.port",
    "src_port": "source.port",
    "sport": "source.port",
    "action": "action",
    "act": "action",
    "status": "action",
    "msg": "message",
    "message": "message",
    "time": "time",
    "timestamp": "time",
    "user": "source.hostname",
    "method": "message",
    "rule": "rule.uid",
    "uri": "message",
    "level": "severity",
    "service": "message",
    "component": "message",
    "event": "message",
    "task": "message",
    "path": "message",
}

# Maps OCSF targets to field types
TARGET_TYPE_MAP: dict[str, str] = {
    "source.ip": "ip",
    "destination.ip": "ip",
    "source.port": "port",
    "destination.port": "port",
    "network.transport": "protocol",
    "action": "action",
    "time": "timestamp",
    "message": "string",
    "severity": "number",
    "rule.uid": "string",
    "network.interface": "string",
    "source.hostname": "string",
}

IP_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}")

PROTOCOL_NAMES = {"tcp", "udp", "icmp", "gre", "esp", "ah", "sctp"}
ACTION_NAMES = {"allow", "deny", "drop", "accept", "block", "reject", "permit",
                "reset", "connected", "disconnected"}


class StructuralAnalyzer:
    """Analyzes log structure to identify key-value patterns and field types.

    Returns TWO confidence scores:
    - structural_confidence: token structure understanding
    - semantic_confidence: OCSF field mapping certainty (evidence-based)
    """

    def classify_value(self, val: str) -> ValueType:
        """Classify a value string into a semantic type."""
        if IP_PATTERN.match(val):
            return ValueType.IP
        if val.lower() in PROTOCOL_NAMES:
            return ValueType.PROTOCOL
        if val.lower() in ACTION_NAMES:
            return ValueType.ACTION
        if TIMESTAMP_PATTERN.match(val):
            return ValueType.TIMESTAMP
        if val.isdigit():
            num = int(val)
            if 0 <= num <= 65535:
                return ValueType.PORT
            return ValueType.NUMBER
        return ValueType.STRING

    def tokenize(self, message: str) -> list[StructuralToken]:
        """Tokenize a log message and identify structure."""
        tokens: list[StructuralToken] = []

        chunks = message.split()
        pos = 0
        for chunk in chunks:
            if "=" in chunk and not chunk.startswith("=") and not chunk.endswith("="):
                key, value = chunk.split("=", 1)
                tokens.append(StructuralToken(
                    token=key, token_type=TokenType.KEY,
                    value_type=ValueType.UNKNOWN, position=pos,
                ))
                pos += len(key)
                tokens.append(StructuralToken(
                    token="=", token_type=TokenType.OPERATOR,
                    value_type=ValueType.UNKNOWN, position=pos,
                ))
                pos += 1
                tokens.append(StructuralToken(
                    token=value, token_type=TokenType.VALUE,
                    value_type=self.classify_value(value), position=pos,
                ))
                pos += len(value) + 1
            else:
                tokens.append(StructuralToken(
                    token=chunk, token_type=TokenType.UNKNOWN,
                    value_type=self.classify_value(chunk), position=pos,
                ))
                pos += len(chunk) + 1

        return tokens

    def analyze(
        self, message: str, known_parser_keys: set[str] | None = None,
    ) -> tuple[bool, float, ParserSpecification | None, dict[str, Any]]:
        """
        Analyze a log message structurally.

        Args:
            message: The log line to analyze.
            known_parser_keys: Set of lowercased source field keys from active
                parsers in the fast path engine. Used to determine evidence level.

        Returns: (confident, semantic_confidence, candidate_spec, detail)
            - confident: True only if semantic_confidence >= threshold
            - semantic_confidence: Evidence-weighted mapping confidence
            - candidate_spec: Always produced if KV pairs found (even if not confident)
            - detail: Enriched dict with candidate mappings and evidence for Tier-3
        """
        if known_parser_keys is None:
            known_parser_keys = set()

        tokens = self.tokenize(message)

        # Extract key-value pairs and build evidence-based mappings
        fields: dict[str, str] = {}
        field_types: dict[str, str] = {}
        candidate_mappings: list[FieldMapping] = []
        variables: list[str] = []
        constants: list[str] = []
        evidence_weights: list[float] = []
        total_kv = 0

        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if (
                tok.token_type == TokenType.KEY
                and i + 2 < len(tokens)
                and tokens[i + 1].token_type == TokenType.OPERATOR
                and tokens[i + 2].token_type == TokenType.VALUE
            ):
                key = tok.token
                value_tok = tokens[i + 2]
                total_kv += 1

                key_lower = key.lower()
                alias_target = FIELD_NAME_MAP.get(key_lower, None)

                # Determine evidence type and mapping
                if key_lower in known_parser_keys and alias_target:
                    # Key exists in an active parser — high confidence
                    evidence_type = EvidenceType.EXACT_KNOWN_PARSER
                    target = alias_target
                    field_type = TARGET_TYPE_MAP.get(target, "string")
                elif alias_target:
                    # Key found in alias map but NOT in any active parser
                    # Guard: If alias target is IP or PORT, verify value type compatibility
                    if alias_target in ("source.ip", "destination.ip") and value_tok.value_type != ValueType.IP:
                        evidence_type = EvidenceType.UNRESOLVED
                        target = "message"
                        field_type = "string"
                    elif alias_target in ("source.port", "destination.port") and value_tok.value_type != ValueType.PORT:
                        evidence_type = EvidenceType.UNRESOLVED
                        target = "message"
                        field_type = "string"
                    elif key_lower == "status" and value_tok.value_type != ValueType.ACTION:
                        evidence_type = EvidenceType.ALIAS_MATCH
                        target = "message"
                        field_type = "string"
                    else:
                        evidence_type = EvidenceType.ALIAS_MATCH
                        target = alias_target
                        field_type = TARGET_TYPE_MAP.get(target, "string")
                elif value_tok.value_type == ValueType.IP:
                    evidence_type = EvidenceType.VALUE_TYPE_INFERENCE
                    target = "source.ip" if "src" in key_lower or "source" in key_lower else "destination.ip"
                    field_type = "ip"
                elif value_tok.value_type == ValueType.PORT:
                    evidence_type = EvidenceType.VALUE_TYPE_INFERENCE
                    target = "destination.port"
                    field_type = "port"
                elif value_tok.value_type == ValueType.PROTOCOL:
                    evidence_type = EvidenceType.VALUE_TYPE_INFERENCE
                    target = "network.transport"
                    field_type = "protocol"
                elif value_tok.value_type == ValueType.ACTION:
                    evidence_type = EvidenceType.VALUE_TYPE_INFERENCE
                    target = "action"
                    field_type = "action"
                else:
                    evidence_type = EvidenceType.UNRESOLVED
                    target = "message"
                    field_type = "string"

                weight = EVIDENCE_WEIGHTS[evidence_type]
                evidence_weights.append(weight)

                fields[key] = target
                field_types[key] = field_type

                mapping = FieldMapping(
                    source_field=key,
                    candidate_target=target,
                    evidence_type=evidence_type,
                    evidence_weight=weight,
                    value_type=value_tok.value_type,
                    value_sample=value_tok.token,
                )
                candidate_mappings.append(mapping)
                variables.append(
                    f"{key} → {target} ({evidence_type.value}, weight={weight})"
                )

                i += 3
            else:
                if tok.token_type == TokenType.UNKNOWN:
                    constants.append(tok.token)
                i += 1

        # --- Compute dual confidence scores ---

        # Structural confidence: Do we understand the token structure?
        # High if we found KV pairs with typed values
        structural_confidence = 1.0 if total_kv >= 2 else (total_kv / 2.0 if total_kv > 0 else 0.0)

        # Semantic confidence: How certain are our OCSF mappings?
        # Mean of evidence weights across all fields
        semantic_confidence = (
            sum(evidence_weights) / len(evidence_weights)
            if evidence_weights else 0.0
        )

        # Confident only if semantic confidence meets threshold
        confident = (
            semantic_confidence >= settings.semantic_confidence_threshold
            and total_kv >= 2
        )

        # Always produce a candidate spec if we found KV pairs
        # (Tier-3 can use this even when Tier-2 is not confident)
        spec = None
        if total_kv > 0:
            template_parts = [f"{key}=<*>" for key in fields]
            template = " ".join(template_parts)

            spec = ParserSpecification(
                template=template,
                field_separator="=",
                entry_separator=" ",
                fields=fields,
                field_types=field_types,
                source_hint="structural_analysis",
                confidence=semantic_confidence,
            )

        detail = {
            "tokens": [t.model_dump() for t in tokens],
            "variables_identified": variables,
            "constants_identified": constants,
            "total_kv_pairs": total_kv,
            "structural_confidence": structural_confidence,
            "semantic_confidence": semantic_confidence,
            "confident": confident,
            "candidate_mappings": [m.model_dump() for m in candidate_mappings],
            "unresolved_fields": [
                m.source_field for m in candidate_mappings
                if m.evidence_type in (EvidenceType.ALIAS_MATCH, EvidenceType.VALUE_TYPE_INFERENCE, EvidenceType.UNRESOLVED)
            ],
        }

        return confident, semantic_confidence, spec, detail
