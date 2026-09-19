"""
SLM abstraction layer — Ollama adapter + Demo Inference Fallback.

CRITICAL RULES:
- The DemoFallbackProvider is NOT an SLM. It is clearly labeled "DEMO INFERENCE FALLBACK".
- The SLM must NEVER generate executable code. Only structured parser specifications.
- Same interface so Ollama can replace the fallback transparently.
- Output is constrained JSON: field mappings with confidence and reason.

Classification: IMPLEMENTED (interface + fallback), PROTOTYPE ABSTRACTION (Ollama adapter)
"""

from __future__ import annotations

import ipaddress
import json
import logging
from abc import ABC, abstractmethod
from typing import Any

import httpx
from pydantic import BaseModel

from backend.config import settings
from backend.models import InferenceMode, ParserSpecification
from backend.adaptive.tier2_structural import FIELD_NAME_MAP, TARGET_TYPE_MAP

logger = logging.getLogger(__name__)

ALLOWLISTED_TARGET_FIELDS = {
    "source.ip", "source.port", "destination.ip", "destination.port",
    "network.transport", "action", "message", "time", "severity",
    "rule.uid", "network.interface", "source.hostname", "destination.hostname",
    "source.mac", "destination.mac", "network.direction", "network.bytes",
}


class FieldResolution(BaseModel):
    """A single field mapping resolved by Tier-3 inference."""
    source_field: str
    target_field: str
    confidence: float
    reason: str


class InferenceResult(BaseModel):
    """Result from inference provider."""
    spec: ParserSpecification
    confidence: float
    mode: InferenceMode
    detail: str
    resolved_mappings: list[FieldResolution] = []
    retrieved_templates_used: int = 0


class SLMProvider(ABC):
    """Abstract inference provider interface."""

    @abstractmethod
    async def infer(
        self, log_line: str,
        historical_templates: list[dict],
        structural_hints: dict,
    ) -> InferenceResult:
        ...

    @abstractmethod
    def get_mode(self) -> InferenceMode:
        ...

    @abstractmethod
    def get_mode_label(self) -> str:
        ...


class OllamaProvider(SLMProvider):
    """
    Local SLM via Ollama API.
    Sends a STRUCTURED prompt with candidate mappings, value types,
    and retrieved templates — asking only for semantic resolution.
    Never asks the model to generate code.
    """

    def get_mode(self) -> InferenceMode:
        return InferenceMode.LOCAL_SLM

    def get_mode_label(self) -> str:
        return "LOCAL SLM (Ollama)"

    async def infer(
        self, log_line: str,
        historical_templates: list[dict],
        structural_hints: dict,
    ) -> InferenceResult:
        prompt = self._build_prompt(log_line, historical_templates, structural_hints)

        try:
            async with httpx.AsyncClient(timeout=settings.ollama_timeout_seconds) as client:
                response = await client.post(
                    f"{settings.ollama_base_url}/api/generate",
                    json={
                        "model": settings.ollama_model,
                        "prompt": prompt,
                        "stream": False,
                        "format": "json",
                    },
                )
                response.raise_for_status()
                result = response.json()
                generated = result.get("response", "{}")

                spec_data = json.loads(generated)

                # Parse mappings from SLM output
                mappings_data = spec_data.get("mappings", [])
                resolved: list[FieldResolution] = []
                fields: dict[str, str] = {}
                field_types: dict[str, str] = {}

                for m in mappings_data:
                    src = m.get("source_field", "")
                    tgt = m.get("target_field", "")
                    conf = min(float(m.get("confidence", 0.5)), 0.95)
                    reason = m.get("reason", "SLM inference")

                    if src and tgt:
                        # Extract sample value for this field from structural hints
                        sample_val = None
                        for c in structural_hints.get("candidate_mappings", []):
                            if str(c.get("source_field", "")).lower() == src.lower():
                                sample_val = str(c.get("value_sample", ""))
                                break

                        # Semantic Guardrail: verify value matches expected type before mapping to IP or port
                        if tgt in ("source.ip", "destination.ip"):
                            is_ip = False
                            if sample_val:
                                try:
                                    ipaddress.ip_address(sample_val.strip())
                                    is_ip = True
                                except ValueError:
                                    is_ip = False
                            if not is_ip:
                                tgt = "message"
                                reason = f"Value '{sample_val}' is not a valid IP; mapped to message"

                        elif tgt in ("source.port", "destination.port"):
                            is_port = False
                            if sample_val and str(sample_val).strip().lstrip("-").isdigit():
                                try:
                                    p = int(str(sample_val).strip())
                                    if 0 <= p <= 65535:
                                        is_port = True
                                except ValueError:
                                    is_port = False
                            if not is_port:
                                tgt = "message"
                                reason = f"Value '{sample_val}' is not a valid port; mapped to message"

                        elif tgt not in ALLOWLISTED_TARGET_FIELDS:
                            tgt = "message"
                            reason = f"Target '{tgt}' not in allowlist; mapped to message"

                        resolved.append(FieldResolution(
                            source_field=src, target_field=tgt,
                            confidence=conf, reason=reason,
                        ))
                        fields[src] = tgt
                        field_types[src] = TARGET_TYPE_MAP.get(tgt, "string")

                # Fallback: if SLM didn't return mappings format, try fields directly
                if not fields and "fields" in spec_data:
                    fields = spec_data["fields"]
                    field_types = spec_data.get("field_types", {})

                regex_pattern = spec_data.get("regex_pattern", "")
                if regex_pattern:
                    template = regex_pattern
                else:
                    template_parts = [f"{k}=<*>" for k in fields]
                    template = " ".join(template_parts)

                overall_conf = (
                    sum(r.confidence for r in resolved) / len(resolved)
                    if resolved else 0.80
                )
                overall_conf = min(overall_conf, 0.90)

                spec = ParserSpecification(
                    template=template,
                    regex_pattern=regex_pattern,
                    fields=fields,
                    field_types=field_types,
                    field_separator="=",
                    entry_separator=" ",
                    source_hint="ollama_slm",
                    confidence=overall_conf,
                )
                return InferenceResult(
                    spec=spec,
                    confidence=overall_conf,
                    mode=InferenceMode.LOCAL_SLM,
                    detail="Local SLM resolved semantic field mappings",
                    resolved_mappings=resolved,
                    retrieved_templates_used=len(historical_templates),
                )
        except Exception as e:
            logger.warning(f"Ollama inference failed: {e}. Cannot generate spec.")
            raise

    def _build_prompt(self, log_line: str, templates: list[dict], hints: dict) -> str:
        # Build structured context from Tier-2 hints
        candidate_section = ""
        candidates = hints.get("candidate_mappings", [])
        if candidates:
            candidate_section = "\nCandidate field mappings from structural analysis:"
            for c in candidates:
                candidate_section += (
                    f"\n  {c.get('source_field', '?')} → {c.get('candidate_target', '?')} "
                    f"(evidence: {c.get('evidence_type', '?')}, "
                    f"value_type: {c.get('value_type', '?')}, "
                    f"sample: {c.get('value_sample', '?')})"
                )

        unresolved = hints.get("unresolved_fields", [])
        unresolved_section = f"\nFields needing semantic resolution: {unresolved}" if unresolved else ""

        template_section = ""
        for i, t in enumerate(templates[:3]):
            tmpl_spec = t.get("spec", {})
            template_section += f"\nHistorical Template {i+1} (similarity: {t.get('similarity', 0):.2f}):"
            template_section += f"\n  Fields: {tmpl_spec.get('fields', {})}"

        return f"""You are a log field mapping resolver. Given structural analysis of a log line,
resolve the semantic meaning of each source field to an OCSF target field.

DO NOT generate any executable code. Return ONLY a JSON object.

Log line: {log_line}
{candidate_section}
{unresolved_section}

Similar historical templates: {template_section}

Valid OCSF target fields: source.ip, destination.ip, source.port, destination.port, network.transport, action, message, time, severity, rule.uid, source.hostname

CRITICAL RULES:
1. ONLY map to 'source.ip' or 'destination.ip' if the field value is a valid IPv4 or IPv6 address.
2. ONLY map to 'source.port' or 'destination.port' if the field value is a numeric port (0-65535).
3. If the log is completely unstructured and free-text (no JSON, no key-value pairs), you MUST provide a 'regex_pattern' with named capture groups like '(?P<source_hostname>\w+)' to extract the values, and map those capture group names in the mappings.
4. Fields like 'level=info' or 'level=debug' represent log level. Map them to 'severity'.
5. General text fields map to 'message'.

Return a JSON object with this exact structure:
{{
  "regex_pattern": "(?P<user>\w+) (?P<time>\w+) logins on system (?P<host>\S+)", // ONLY provide this if the log is completely unstructured
  "mappings": [
    {{"source_field": "<key_or_regex_capture_group>", "target_field": "<ocsf_target>", "confidence": <0.0-1.0>, "reason": "<explanation>"}}
  ]
}}"""


class DemoFallbackProvider(SLMProvider):
    """
    Deterministic pattern-matching inference engine for semantic resolution.

    THIS IS NOT AN SLM. It uses Tier-2 candidate mappings, RAG-retrieved
    historical templates, and value type analysis to resolve semantic ambiguity.

    Clearly labeled as "DEMO INFERENCE FALLBACK" in all outputs.

    Classification: IMPLEMENTED (deterministic fallback)
    """

    def get_mode(self) -> InferenceMode:
        return InferenceMode.DEMO_FALLBACK

    def get_mode_label(self) -> str:
        return "DEMO INFERENCE FALLBACK"

    async def infer(
        self, log_line: str,
        historical_templates: list[dict],
        structural_hints: dict,
    ) -> InferenceResult:
        """
        Resolve semantic field mappings using:
        1. Tier-2 candidate mappings (with evidence levels)
        2. RAG-retrieved historical templates (field overlap)
        3. Value type classification
        """
        resolved: list[FieldResolution] = []
        fields: dict[str, str] = {}
        field_types: dict[str, str] = {}

        # Get candidate mappings from Tier-2 structural analysis
        candidates = structural_hints.get("candidate_mappings", [])

        # Build historical field mapping evidence from RAG
        historical_field_evidence: dict[str, list[str]] = {}
        for tmpl in historical_templates[:3]:
            tmpl_fields = tmpl.get("spec", {}).get("fields", {})
            for src_key, target in tmpl_fields.items():
                historical_field_evidence.setdefault(target, []).append(src_key.lower())

        for candidate in candidates:
            src_field = candidate.get("source_field", "")
            candidate_target = candidate.get("candidate_target", "")
            evidence_type = candidate.get("evidence_type", "UNRESOLVED")
            value_type = candidate.get("value_type", "UNKNOWN")
            value_sample = candidate.get("value_sample", "")

            # Start with the alias-based candidate
            target = candidate_target
            confidence = candidate.get("evidence_weight", 0.0)
            reasons: list[str] = []

            # Boost 1: Alias match evidence
            if evidence_type in ("EXACT_KNOWN_PARSER", "ALIAS_MATCH"):
                reasons.append(f"Deterministic alias: {src_field.lower()} → {target}")

            # Boost 2: Value type corroborates the mapping
            type_target_match = {
                "IP": {"source.ip", "destination.ip"},
                "PORT": {"source.port", "destination.port"},
                "PROTOCOL": {"network.transport"},
                "ACTION": {"action"},
                "TIMESTAMP": {"time"},
            }
            expected_targets = type_target_match.get(value_type, set())
            if target in expected_targets:
                confidence += 0.2
                reasons.append(f"Value type {value_type} corroborates {target}")

            # Boost 3: Historical template evidence from RAG
            historical_keys = historical_field_evidence.get(target, [])
            if historical_keys:
                # Check if similar keys mapped to the same target historically
                src_lower = src_field.lower()
                # Check for substring overlap with historical keys
                for hist_key in historical_keys:
                    # e.g., "src_ip" overlaps with "src" which mapped to source.ip
                    if hist_key in src_lower or src_lower in hist_key:
                        confidence += 0.15
                        reasons.append(f"Historical template: '{hist_key}' mapped to {target}")
                        break

            # Guard: ensure semantic suitability before assigning IP or Port targets
            if target in ("source.ip", "destination.ip"):
                is_ip = False
                if value_sample:
                    try:
                        ipaddress.ip_address(str(value_sample).strip())
                        is_ip = True
                    except ValueError:
                        is_ip = False
                if not is_ip:
                    target = "message"
                    reasons.append(f"Value '{value_sample}' is not a valid IP; mapped to message")

            elif target in ("source.port", "destination.port"):
                is_port = False
                if value_sample and str(value_sample).strip().lstrip("-").isdigit():
                    try:
                        p = int(str(value_sample).strip())
                        if 0 <= p <= 65535:
                            is_port = True
                    except ValueError:
                        is_port = False
                if not is_port:
                    target = "message"
                    reasons.append(f"Value '{value_sample}' is not a valid numeric port; mapped to message")

            elif target not in ALLOWLISTED_TARGET_FIELDS:
                target = "message"

            # Cap confidence
            confidence = min(confidence, 0.92)

            resolved.append(FieldResolution(
                source_field=src_field,
                target_field=target,
                confidence=round(confidence, 2),
                reason="; ".join(reasons) if reasons else "Inferred from structural analysis",
            ))
            fields[src_field] = target
            field_types[src_field] = TARGET_TYPE_MAP.get(target, "string")

        regex_pattern = structural_hints.get("regex_pattern", "")
        if regex_pattern:
            template = regex_pattern
        else:
            template_parts = [f"{k}=<*>" for k in fields]
            template = " ".join(template_parts)

        overall_confidence = (
            sum(r.confidence for r in resolved) / len(resolved)
            if resolved else 0.0
        )
        overall_confidence = min(overall_confidence, 0.85)  # Cap fallback confidence

        spec = ParserSpecification(
            template=template,
            regex_pattern=regex_pattern,
            fields=fields,
            field_types=field_types,
            field_separator="=",
            entry_separator=" ",
            source_hint="demo_fallback",
            confidence=overall_confidence,
        )

        return InferenceResult(
            spec=spec,
            confidence=overall_confidence,
            mode=InferenceMode.DEMO_FALLBACK,
            detail="DEMO INFERENCE FALLBACK — semantic resolution using structural evidence + RAG (NOT an SLM)",
            resolved_mappings=resolved,
            retrieved_templates_used=len(historical_templates),
        )


_cached_provider: SLMProvider | None = None
_ollama_checked: bool = False
_ollama_available: bool = False


async def check_ollama_availability(force_refresh: bool = False) -> bool:
    """Check if Ollama is running and accessible. Auto-detects available model if needed."""
    global _ollama_checked, _ollama_available
    if _ollama_checked and not force_refresh and _ollama_available:
        return _ollama_available
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            resp = await client.get(f"{settings.ollama_base_url}/api/tags")
            if resp.status_code == 200:
                _ollama_available = True
                data = resp.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                # If specific model not pulled, auto-adopt the first available model
                if models and not any(settings.ollama_model in m for m in models):
                    settings.ollama_model = models[0]
                    logger.info(f"Ollama connected. Adopted installed model: '{settings.ollama_model}'")
                elif models:
                    logger.info(f"Ollama connected with model: '{settings.ollama_model}'")
            else:
                _ollama_available = False
    except Exception:
        _ollama_available = False
    _ollama_checked = True
    return _ollama_available


async def get_inference_provider(force_refresh: bool = False) -> SLMProvider:
    """Factory: returns the appropriate inference provider."""
    global _cached_provider

    mode = settings.inference_mode

    if mode == "demo_fallback":
        _cached_provider = DemoFallbackProvider()
        return _cached_provider

    # Check if Ollama is accessible
    ollama_ok = await check_ollama_availability(force_refresh=force_refresh)

    if mode == "ollama":
        if ollama_ok:
            _cached_provider = OllamaProvider()
        else:
            logger.warning("Ollama requested but unavailable. Using Demo Fallback.")
            _cached_provider = DemoFallbackProvider()
    else:  # auto
        if ollama_ok:
            _cached_provider = OllamaProvider()
            logger.info("Ollama detected. Using Local SLM.")
        else:
            _cached_provider = DemoFallbackProvider()
            logger.info("Ollama not available. Using Demo Inference Fallback.")

    return _cached_provider


def get_current_inference_mode() -> str:
    """Return current inference mode label for display."""
    if _cached_provider:
        return _cached_provider.get_mode_label()
    return "NOT INITIALIZED"


def is_ollama_available() -> bool:
    """Return cached Ollama availability status."""
    return _ollama_available
