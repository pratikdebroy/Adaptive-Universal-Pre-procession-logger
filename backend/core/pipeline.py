"""
Pipeline Orchestrator — the central engine.

Implements the EXACT architecture from the SIH diagram:

  1. RECEIVE LOG → SHA-256 preserve, processing copy
  2. STRUCTURE MATCHING USING BDPT → front+back matching, get leaf node
  3A. If matched → CHECK PARSER VARIANTS WITH TRUST GATE → Fast Path
  3B. If no match OR no variant → AI-ASSISTED PATH (RAG + LLM)
      → Trust Gate validates proposed parser
  4A. Approved → UPDATE PARSER REGISTRY (link variant or new BDPT node)
  4B. Rejected → QUARANTINE
  5. NORMALISATION AND SIEM DELIVERY → OCSF, PII masking, Merkle tree

Classification: IMPLEMENTED
"""

from __future__ import annotations

import time
import json
import logging
from datetime import datetime, timezone
from typing import Any

from backend.config import settings
from backend.models import (
    ProcessingMode, ValidationResult, QuarantineReason, QuarantineSeverity,
    ProcessedEventResponse, PipelineStageInfo, RawEvent,
    ParsedFields, ParserSpecification, QuarantineEntry,
    TrustGateResult, ValidationCheck,
)
from backend.storage.evidence_vault import EvidenceVault, create_processing_copy
from backend.ingestion.defensive import (
    run_ingestion_safety_checks, SourceRateLimiter, global_rate_limiter,
)
from backend.parsers.fast_path import FastPathEngine
from backend.adaptive.tier1_template import Tier1Matcher
from backend.adaptive.tier2_structural import StructuralAnalyzer
from backend.adaptive.tier3_slm_rag import Tier3Adaptive
from backend.adaptive.rag_index import ParserRAG
from backend.adaptive.slm_interface import get_current_inference_mode, get_inference_provider
from backend.validation.trust_gate import ParserSafetyValidator, HybridTrustGate
from backend.normalization.ocsf_normalizer import OCSFNormalizer
from backend.registry.parser_registry import ParserRegistry
from backend.storage.database import get_db

logger = logging.getLogger(__name__)


class PipelineOrchestrator:
    """
    The central processing pipeline.
    Coordinates all stages from raw ingestion to OCSF output.
    Follows the exact architecture from the SIH diagram.
    """

    def __init__(self):
        # Core components
        self.vault = EvidenceVault()
        self.rate_limiter = global_rate_limiter
        self.fast_path = FastPathEngine()
        self.tier1 = Tier1Matcher()
        self.structural = StructuralAnalyzer()
        self.rag = ParserRAG()
        self.tier3 = Tier3Adaptive(self.rag)
        self.parser_safety = ParserSafetyValidator()
        self.trust_gate = HybridTrustGate()
        self.normalizer = OCSFNormalizer()
        self.registry: ParserRegistry | None = None

        # Metrics (from actual execution)
        self.metrics = {
            "total_events": 0,
            "fast_path_count": 0,
            "structural_count": 0,
            "tier3_count": 0,
            "quarantine_count": 0,
            "fast_path_latencies": [],
            "adaptive_latencies": [],
        }

    async def initialize(self):
        """Initialize all components. Called on startup."""
        from backend.parsers.templates import KNOWN_PARSERS

        # Initialize registry — pass tier1 so it can re-link adaptive parsers to tree on startup
        self.registry = ParserRegistry(self.fast_path, tier1_matcher=self.tier1)

        # Ensure only known baseline parsers exist from start
        try:
            db = await get_db()
            try:
                placeholders = ",".join("?" * len(KNOWN_PARSERS))
                await db.execute(
                    f"DELETE FROM parsers WHERE parser_id NOT IN ({placeholders})",
                    tuple(KNOWN_PARSERS.keys()),
                )
                await db.commit()
            finally:
                await db.close()
        except Exception as e:
            logger.warning(f"Error cleaning leftover adaptive parsers on startup: {e}")

        # Seed known parsers — load spec into FastPathEngine AND structural template into Tier1Matcher tree
        for parser_id, (name, spec) in KNOWN_PARSERS.items():
            self.fast_path.load_parser(parser_id, spec)
            # Inject the clean structural template into the unified BDPT tree
            if spec.template and "JSON_PAYLOAD" not in spec.template:
                self.tier1.miner.add_explicit_template(spec.template, parser_id)
            try:
                existing = await self.registry.get_by_id(parser_id)
                if not existing:
                    record = await self.registry.register_candidate(
                        name=name,
                        source=spec.source_hint,
                        format_signature=self.fast_path.compute_format_signature(spec.template),
                        spec=spec,
                        confidence=1.0,
                        parser_id=parser_id,
                    )
                    await self.registry.promote(record.parser_id)
            except Exception as e:
                logger.warning(f"Error seeding parser {parser_id}: {e}")

        # Seed RAG
        self.rag.seed_known_templates()

        # Load active parsers from registry
        try:
            await self.registry.initialize()
        except Exception:
            pass  # Fresh DB

        # Probe and initialize inference provider
        await get_inference_provider()

        logger.info(
            f"Pipeline initialized. Active parsers: {self.fast_path.get_parser_count()}. Mode: {get_current_inference_mode()}"
        )

    async def process_event(
        self, raw_message: str, source: str = "unknown", auto_promote: bool = True
    ) -> ProcessedEventResponse:
        """
        Process a single raw event through the complete pipeline.
        Follows the exact diagram architecture:
          1 → 2 → 3A/3B → 4A/4B → 5
        """
        stages: list[PipelineStageInfo] = []
        start_time = time.perf_counter()

        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # STEP 1: RECEIVE LOG — Preserve + Ingestion Safety
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        stage_start = time.perf_counter()
        raw_event = self.vault.preserve(raw_message, source)
        stages.append(PipelineStageInfo(
            name="PRESERVE",
            status="COMPLETE",
            event_count=1,
            latency_ms=_ms(stage_start),
        ))

        # Ingestion safety checks (rate limit, size, injection detection)
        stage_start = time.perf_counter()
        safety_res = run_ingestion_safety_checks(raw_event, self.rate_limiter)
        if not safety_res.safe:
            return await self._quarantine(
                raw_event=raw_event,
                reason=safety_res.reason or QuarantineReason.MALFORMED_INPUT,
                detail=safety_res.detail,
                stages=stages,
                detected_format=safety_res.detected_format,
                failed_check=safety_res.failed_check,
                severity=safety_res.severity,
                metadata=safety_res.metadata,
            )

        # Create processing copy (sanitization on copy only)
        proc_copy = create_processing_copy(raw_event)
        message = proc_copy.sanitized_message

        if not message.strip():
            return await self._quarantine(
                raw_event=raw_event,
                reason=QuarantineReason.EMPTY_EVENT,
                detail="Empty message after sanitization",
                stages=stages,
                detected_format=safety_res.detected_format,
                failed_check="transport.empty_sanitized",
                severity=QuarantineSeverity.LOW,
            )

        stages.append(PipelineStageInfo(
            name="INGEST",
            status="COMPLETE",
            event_count=1,
            latency_ms=_ms(stage_start),
            processing_mode=f"format:{safety_res.detected_format}, sanitization:{proc_copy.sanitization_applied if proc_copy.sanitization_applied else 'clean'}",
        ))

        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # STEP 2: STRUCTURE MATCHING USING BDPT
        # Single unified Tier1Matcher tree does routing + variant lookup.
        # Returns the leaf cluster so the pipeline can try its parser variants.
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        bdpt_start = time.perf_counter()

        # Use unified Tier1Matcher tree:
        #   1. Bidirectional structural match (front+back scan)
        #   2. Returns the matching leaf cluster with variant IDs attached
        t1_confident, t1_score, bdpt_cluster, t1_detail = self.tier1.match_with_cluster(message)

        fp_parser_id, fp_parsed, fp_confidence = None, None, 0.0

        if bdpt_cluster and bdpt_cluster.has_variants():
            # Try each variant stored at this leaf node (diagram step 3A)
            fp_parser_id, fp_parsed, fp_confidence = self.fast_path.try_variants(
                message, bdpt_cluster.get_variant_ids()
            )

        structure_matched = fp_parsed is not None and fp_confidence >= settings.fast_path_confidence_threshold

        stages.append(PipelineStageInfo(
            name="ROUTE",
            status="BDPT_MATCHED" if structure_matched else "BDPT_MISS",
            latency_ms=_ms(bdpt_start),
            processing_mode=f"BDPT: t1_sim={t1_score:.2f}, fp_conf={fp_confidence:.2f}, matched={structure_matched}",
        ))

        tier_detail = f"BDPT: {t1_detail.get('status', '')} (sim={t1_score:.2f})"
        processing_mode = ProcessingMode.FAST_PATH
        confidence = 0.0
        parser_id = ""
        parsed: ParsedFields | None = None
        self_healing = False
        best_variant_validation: TrustGateResult | None = None

        if structure_matched and fp_parsed and fp_parser_id:
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # STEP 3A: CHECK PARSER VARIANTS WITH TRUST GATE
            # BDPT (or regex) matched a parser → validate output with Trust Gate
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

            variant_start = time.perf_counter()

            # Trust Gate validates the variant's output
            validation = self.trust_gate.validate(fp_parsed.fields, fp_confidence, source_hint=source)

            if validation.result == ValidationResult.APPROVED:
                # ✅ FAST PATH — variant matched and passed Trust Gate
                processing_mode = ProcessingMode.FAST_PATH
                parser_id = fp_parser_id
                confidence = fp_confidence
                parsed = fp_parsed
                best_variant_validation = validation
                tier_detail += f" → FAST PATH (parser={fp_parser_id}, conf={fp_confidence:.2f})"

                latency = _ms(variant_start)
                self.metrics["fast_path_count"] += 1
                self.metrics["fast_path_latencies"].append(latency)

                stages.append(PipelineStageInfo(
                    name="PARSE",
                    status="FAST_PATH",
                    latency_ms=latency,
                    processing_mode=f"Variant matched: {fp_parser_id}",
                ))
            else:
                # BDPT matched but Trust Gate rejected → SELF-HEALING
                self_healing = True
                tier_detail += f" → SELF-HEALING (Trust Gate rejected: {'; '.join(validation.failure_reasons)})"
                stages.append(PipelineStageInfo(
                    name="PARSE",
                    status="SELF_HEALING",
                    latency_ms=_ms(variant_start),
                    processing_mode="Trust Gate rejected variant, escalating to AI path",
                ))
        else:
            # BDPT and regex both missed — totally new format
            tier_detail += " → NEW FORMAT (no parser matched)"

        if not parsed:
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # STEP 3B: AI-ASSISTED PATH
            # For new/unknown structures OR self-healing cases
            # RAG retrieval + LLM inference → propose parser
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

            adaptive_start = time.perf_counter()
            processing_mode = ProcessingMode.TIER3_ADAPTIVE
            self.metrics["tier3_count"] += 1

            # Build minimal hints for Tier-3 (tokenization only, NO field guessing)
            tokens = self.structural.tokenize(message)
            # bdpt_cluster is already available from Step 2 (may be None for totally new formats)
            hints = {
                "tokens": [t.model_dump() for t in tokens],
                "total_kv_pairs": sum(1 for t in tokens if t.token_type.value == "KEY"),
                "message": message,
                "self_healing": self_healing,
                "bdpt_template": bdpt_cluster.get_template_str() if bdpt_cluster else "",
                "candidate_mappings": [],  # Empty: let the LLM decide, don't poison with guesses
                "unresolved_fields": [],
            }

            # Tier 3: RAG + LLM
            t3_start = time.perf_counter()
            t3_spec, t3_conf, t3_detail = await self.tier3.adapt(message, hints)
            tier_detail += f" → AI Path: {t3_detail.get('inference_mode', '')}"

            stages.append(PipelineStageInfo(
                name="TIER-3 ADAPTIVE",
                status="COMPLETE" if t3_spec else "FAILED",
                latency_ms=_ms(t3_start),
                processing_mode=t3_detail.get("inference_mode", ""),
            ))

            if not t3_spec:
                return await self._quarantine(
                    raw_event, QuarantineReason.UNSUPPORTED_FORMAT,
                    "All parsing tiers failed", stages
                )

            # ── Parser Safety Validation ──
            safety = self.parser_safety.validate_spec(t3_spec)
            stages.append(PipelineStageInfo(
                name="PARSER SAFETY",
                status="SAFE" if safety.safe else "UNSAFE",
            ))
            if not safety.safe:
                return await self._quarantine(
                    raw_event=raw_event,
                    reason=safety.primary_reason,
                    detail=f"Parser safety check failed: {'; '.join(safety.failure_reasons)}",
                    stages=stages,
                    failed_check=safety.failed_check_name or "parser_safety",
                    severity=safety.primary_severity,
                )

            # Execute the proposed spec to get parsed fields
            fields, confidence = self.fast_path._execute_spec(message, t3_spec)
            parsed = ParsedFields(
                fields=fields,
                processing_mode=ProcessingMode.TIER3_ADAPTIVE,
                confidence=confidence,
            )

            # ── Trust Gate validates the proposed parser output ──
            if parsed.fields:
                tg_result = self.trust_gate.validate(parsed.fields, confidence, source_hint=source)
                stages.append(PipelineStageInfo(
                    name="VALIDATE",
                    status=tg_result.result.value,
                ))
                if tg_result.result == ValidationResult.QUARANTINED:
                    return await self._quarantine(
                        raw_event=raw_event,
                        reason=tg_result.primary_reason,
                        detail="; ".join(tg_result.failure_reasons),
                        stages=stages,
                        validation=tg_result,
                        failed_check=tg_result.failed_check_name,
                        severity=tg_result.primary_severity,
                        metadata={"failed_value": tg_result.failed_value} if tg_result.failed_value is not None else {},
                    )

            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # STEP 4A: UPDATE PARSER REGISTRY
            # Approved parser → register spec + link as variant at BDPT leaf node
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

            if self.registry and parsed and parsed.fields:
                try:
                    sig = self.fast_path.compute_format_signature(message)
                    record = await self.registry.register_candidate(
                        name=f"adaptive_{sig[:8]}",
                        source=source,
                        format_signature=sig,
                        spec=t3_spec,
                        confidence=confidence,
                    )
                    parser_id = record.parser_id

                    # Store spec in FastPathEngine (execution only, no tree involvement)
                    self.fast_path.load_parser(parser_id, t3_spec)

                    if self_healing and bdpt_cluster:
                        # SELF-HEALING: Link new variant to the existing leaf cluster
                        bdpt_cluster.add_variant(parser_id)
                        tier_detail += f" → SELF-HEAL: linked variant {parser_id[:8]} to cluster #{bdpt_cluster.cluster_id}"
                    else:
                        # NEW STRUCTURE: Feed raw log into Tier1Matcher tree.
                        # Tree naturally tokenizes it into real words → creates structural leaf cluster.
                        # Attach new parser ID as a variant at that leaf. NO regex strings in the tree.
                        new_cluster = self.tier1.add_template(message)
                        if new_cluster:
                            new_cluster.add_variant(parser_id)
                            tier_detail += f" → NEW TEMPLATE: registered {parser_id[:8]} at cluster #{new_cluster.cluster_id}"
                        else:
                            tier_detail += f" → NEW TEMPLATE: registered {parser_id}"

                    # Also add to RAG for future retrieval
                    self.rag.add_template(parser_id, t3_spec)

                    if auto_promote:
                        await self.registry.promote(parser_id)
                        stages.append(PipelineStageInfo(
                            name="REGISTRY",
                            status="PROMOTED",
                            processing_mode="CANDIDATE → ACTIVE" + (" (self-healing)" if self_healing else " (new template)"),
                        ))

                except Exception as e:
                    logger.warning(f"Failed to register/promote candidate: {e}")

            adaptive_latency = _ms(adaptive_start)
            self.metrics["adaptive_latencies"].append(adaptive_latency)

        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # STEP 5: NORMALISATION AND SIEM DELIVERY
        # Extract fields, PII masking, OCSF, Merkle tree
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        if parsed and parsed.fields:
            # If we came from fast path, still need to validate through Trust Gate
            if processing_mode == ProcessingMode.FAST_PATH:
                stage_start = time.perf_counter()
                validation = best_variant_validation or self.trust_gate.validate(
                    parsed.fields, confidence, source_hint=source
                )
                stages.append(PipelineStageInfo(
                    name="VALIDATE",
                    status=validation.result.value,
                    latency_ms=_ms(stage_start),
                ))
                if validation.result == ValidationResult.QUARANTINED:
                    return await self._quarantine(
                        raw_event=raw_event,
                        reason=validation.primary_reason,
                        detail="; ".join(validation.failure_reasons),
                        stages=stages,
                        validation=validation,
                        failed_check=validation.failed_check_name,
                        severity=validation.primary_severity,
                        metadata={"failed_value": validation.failed_value} if validation.failed_value is not None else {},
                    )
            else:
                # Adaptive path already validated above; reuse
                validation = TrustGateResult(
                    result=ValidationResult.APPROVED,
                    passed=True,
                    checks=[],
                    failure_reasons=[],
                )

            # ── PII MASKING ──
            stage_start = time.perf_counter()
            from backend.validation.pii_masking import pii_masker
            masked_fields = pii_masker.mask(parsed.fields)
            stages.append(PipelineStageInfo(
                name="PII MASKING",
                status="COMPLETE",
                latency_ms=_ms(stage_start),
            ))

            # ── NORMALIZE (OCSF) ──
            stage_start = time.perf_counter()
            ocsf_event = self.normalizer.normalize(
                parsed_fields=masked_fields,
                raw_event=raw_event,
                parser_id=parser_id or "",
                parser_version=parsed.parser_version,
                processing_mode=processing_mode,
                confidence=confidence,
            )
            stages.append(PipelineStageInfo(
                name="NORMALIZE",
                status="COMPLETE",
                latency_ms=_ms(stage_start),
                processing_mode="OCSF",
            ))

            # ── Save to DB ──
            await self._save_processed(raw_event, parsed, ocsf_event, processing_mode, parser_id, confidence, tier_detail)

            self.metrics["total_events"] += 1
            total_latency = _ms(start_time)

            # Look up parser name
            parser_name = ""
            if parser_id:
                if self.registry:
                    rec = await self.registry.get_by_id(parser_id)
                    if rec:
                        parser_name = rec.name
                        parsed.parser_version = rec.parser_version

            return ProcessedEventResponse(
                event_id=raw_event.event_id,
                raw_sha256=raw_event.raw_sha256,
                processing_mode=processing_mode,
                parser_id=parser_id or "",
                parser_name=parser_name,
                parser_version=parsed.parser_version,
                confidence=confidence,
                validation=validation,
                ocsf_event=ocsf_event,
                tier_detail=tier_detail,
                stages=stages,
                inference_mode=get_current_inference_mode(),
                tier3_invocations=1 if processing_mode == ProcessingMode.TIER3_ADAPTIVE else 0,
            )

        # Should not reach here normally
        return await self._quarantine(
            raw_event, QuarantineReason.MALFORMED_INPUT,
            "No parsed fields produced", stages
        )

    def _execute_spec(
        self, message: str, spec: ParserSpecification, mode: ProcessingMode
    ) -> ParsedFields:
        """Execute a parser spec against a message to extract fields."""
        fields, confidence = self.fast_path._execute_spec(message, spec)
        return ParsedFields(
            fields=fields,
            processing_mode=mode,
            confidence=confidence,
        )

    async def _quarantine(
        self,
        raw_event: RawEvent,
        reason: QuarantineReason,
        detail: str,
        stages: list[PipelineStageInfo],
        validation=None,
        detected_format: str = "unknown",
        failed_check: str = "",
        severity: QuarantineSeverity = QuarantineSeverity.MEDIUM,
        metadata: dict[str, Any] | None = None,
        processing_mode: ProcessingMode | None = None,
    ) -> ProcessedEventResponse:
        """Send event to quarantine (Step 4B)."""
        self.metrics["quarantine_count"] += 1
        self.metrics["total_events"] += 1

        resolved_failures = validation.failure_reasons if validation and validation.failure_reasons else [detail]
        resolved_failed_check = failed_check or (validation.failed_check_name if validation and validation.failed_check_name else reason.value)

        if validation is None:
            validation = TrustGateResult(
                result=ValidationResult.QUARANTINED,
                passed=False,
                checks=[ValidationCheck(check_name=resolved_failed_check, passed=False, detail=detail)],
                failure_reasons=resolved_failures,
                primary_reason=reason,
                primary_severity=severity,
                failed_check_name=resolved_failed_check,
            )

        entry = QuarantineEntry(
            event_id=raw_event.event_id,
            raw_message=raw_event.raw_message,
            raw_sha256=raw_event.raw_sha256,
            source=raw_event.source,
            detected_format=detected_format,
            reason=reason,
            failed_check=resolved_failed_check,
            severity=severity,
            detail=detail,
            validation_failures=resolved_failures,
            metadata=metadata or {},
        )

        # Save to DB
        try:
            db = await get_db()
            try:
                await db.execute(
                    """INSERT OR IGNORE INTO raw_events
                       (event_id, received_at, source, raw_message, raw_sha256, evidence_path)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        raw_event.event_id, raw_event.received_at.isoformat(),
                        raw_event.source, raw_event.raw_message, raw_event.raw_sha256,
                        str(self.vault.evidence_dir / f"{raw_event.event_id}.json"),
                    ),
                )
                await db.execute(
                    """INSERT INTO quarantine
                       (quarantine_id, event_id, raw_message, raw_sha256, source, detected_format,
                        reason, failed_check, severity, detail, validation_failures, metadata, timestamp, status)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        entry.quarantine_id, entry.event_id, entry.raw_message,
                        entry.raw_sha256, entry.source, entry.detected_format,
                        entry.reason.value, entry.failed_check, entry.severity.value,
                        entry.detail, json.dumps(entry.validation_failures),
                        json.dumps(entry.metadata), entry.timestamp.isoformat(),
                        entry.status,
                    ),
                )
                await db.commit()
            finally:
                await db.close()
        except Exception as e:
            logger.warning(f"Failed to save quarantine: {e}")

        stages.append(PipelineStageInfo(
            name="QUARANTINE",
            status=reason.value,
            processing_mode=f"[{severity.value}] {resolved_failed_check}: {detail}",
        ))

        if not processing_mode:
            processing_mode = ProcessingMode.TIER3_ADAPTIVE

        return ProcessedEventResponse(
            event_id=raw_event.event_id,
            raw_sha256=raw_event.raw_sha256,
            processing_mode=processing_mode,
            quarantine=entry,
            tier_detail=f"QUARANTINED: [{severity.value}] {reason.value} ({resolved_failed_check}) — {detail}",
            stages=stages,
            inference_mode=get_current_inference_mode(),
            validation=validation,
            tier3_invocations=0,
        )

    async def _save_processed(
        self, raw_event, parsed, ocsf_event, mode, parser_id, confidence, tier_detail
    ):
        """Save processed event to DB."""
        try:
            db = await get_db()
            try:
                await db.execute(
                    """INSERT OR IGNORE INTO raw_events
                       (event_id, received_at, source, raw_message, raw_sha256, evidence_path)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        raw_event.event_id, raw_event.received_at.isoformat(),
                        raw_event.source, raw_event.raw_message, raw_event.raw_sha256,
                        str(self.vault.evidence_dir / f"{raw_event.event_id}.json"),
                    ),
                )
                await db.execute(
                    """INSERT OR REPLACE INTO processed_events
                       (event_id, raw_event_id, raw_sha256, parser_id, parser_name,
                        parser_version, processing_mode, confidence, ocsf_json,
                        validation_result, tier_detail, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        raw_event.event_id, raw_event.event_id, raw_event.raw_sha256,
                        parser_id or "", "", parsed.parser_version if parsed else 0,
                        mode.value, confidence,
                        ocsf_event.model_dump_json() if ocsf_event else "{}",
                        "APPROVED", tier_detail,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                await db.commit()
            finally:
                await db.close()
        except Exception as e:
            logger.warning(f"Failed to save processed event: {e}")

    def get_metrics(self) -> dict[str, Any]:
        """Return actual pipeline metrics."""
        total = self.metrics["total_events"]
        fp = self.metrics["fast_path_count"]
        sc = self.metrics["structural_count"]
        t3 = self.metrics["tier3_count"]
        qr = self.metrics["quarantine_count"]

        fp_lats = self.metrics["fast_path_latencies"]
        ad_lats = self.metrics["adaptive_latencies"]

        return {
            "total_events": total,
            "fast_path_count": fp,
            "structural_count": sc,
            "tier3_count": t3,
            "quarantine_count": qr,
            "tier3_invocation_rate": (t3 / total * 100) if total > 0 else 0.0,
            "avg_fast_path_latency_ms": sum(fp_lats) / len(fp_lats) if fp_lats else 0.0,
            "avg_adaptive_latency_ms": sum(ad_lats) / len(ad_lats) if ad_lats else 0.0,
            "inference_mode": get_current_inference_mode(),
            "parsers_active": self.fast_path.get_parser_count(),
        }

    async def reset(self):
        """Reset pipeline state for demo."""
        from backend.storage.database import reset_db
        self.vault.clear()
        await reset_db()
        self.metrics = {
            "total_events": 0,
            "fast_path_count": 0,
            "structural_count": 0,
            "tier3_count": 0,
            "quarantine_count": 0,
            "fast_path_latencies": [],
            "adaptive_latencies": [],
        }
        self.fast_path = FastPathEngine()
        self.tier1 = Tier1Matcher()
        self.rag = ParserRAG()
        self.tier3 = Tier3Adaptive(self.rag)
        await self.initialize()


# Singleton
pipeline = PipelineOrchestrator()


def _ms(start: float) -> float:
    """Convert perf_counter delta to milliseconds."""
    return (time.perf_counter() - start) * 1000
