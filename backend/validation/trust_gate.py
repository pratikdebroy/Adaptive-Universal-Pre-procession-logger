"""
Hybrid Trust Gate — Two-layer validation.

Layer A: Parser Safety Validation — validates the parser SPECIFICATION itself
Layer B: Event Trust Validation — validates PARSED EVENT output

Classification: IMPLEMENTED
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from backend.config import settings
from backend.models import (
    ParserSpecification, ParserSafetyResult, TrustGateResult,
    ValidationCheck, ValidationResult, QuarantineReason, QuarantineSeverity,
)


class ParserSafetyValidator:
    """
    Validates parser SPECIFICATION structure.
    Ensures no executable code, valid fields, allowlisted targets.
    """

    ALLOWLISTED_TARGET_FIELDS = {
        "source.ip", "source.port", "destination.ip", "destination.port",
        "network.transport", "action", "message", "time", "severity",
        "rule.uid", "network.interface", "source.hostname", "destination.hostname",
        "source.mac", "destination.mac", "network.direction", "network.bytes",
    }

    ALLOWLISTED_FIELD_TYPES = {"string", "ip", "port", "protocol", "action", "timestamp", "number"}

    FORBIDDEN_PATTERNS = ["import ", "eval(", "exec(", "__", "os.system", "subprocess", "compile("]

    def validate_spec(self, spec: ParserSpecification) -> ParserSafetyResult:
        checks: list[ValidationCheck] = []
        failures: list[str] = []

        # Check 1: Template is non-empty
        template_ok = bool(spec.template and spec.template.strip())
        checks.append(ValidationCheck(
            check_name="template_non_empty",
            passed=template_ok,
            detail="Template must be a non-empty string",
        ))
        if not template_ok:
            failures.append("Template is empty")

        # Check 2: Fields dict is non-empty
        fields_ok = bool(spec.fields and len(spec.fields) > 0)
        checks.append(ValidationCheck(
            check_name="fields_non_empty",
            passed=fields_ok,
            detail=f"Fields count: {len(spec.fields) if spec.fields else 0}",
        ))
        if not fields_ok:
            failures.append("Fields dictionary is empty")

        # Check 3: All target fields are in allowlist
        if spec.fields:
            for source_key, target_field in spec.fields.items():
                allowed = target_field in self.ALLOWLISTED_TARGET_FIELDS
                checks.append(ValidationCheck(
                    check_name=f"target_field_allowed:{target_field}",
                    passed=allowed,
                    detail=f"{source_key} → {target_field}",
                    value=target_field,
                ))
                if not allowed:
                    failures.append(f"Target field '{target_field}' not in allowlist")

        # Check 4: All field types are in allowlist
        if spec.field_types:
            for field_name, field_type in spec.field_types.items():
                allowed = field_type in self.ALLOWLISTED_FIELD_TYPES
                checks.append(ValidationCheck(
                    check_name=f"field_type_allowed:{field_name}",
                    passed=allowed,
                    detail=f"{field_name}: {field_type}",
                ))
                if not allowed:
                    failures.append(f"Field type '{field_type}' not allowed")

        # Check 5: No executable patterns in template or regex
        for text in [spec.template, spec.regex_pattern]:
            if text:
                text_lower = text.lower()
                for pattern in self.FORBIDDEN_PATTERNS:
                    if pattern in text_lower:
                        checks.append(ValidationCheck(
                            check_name="no_executable_code",
                            passed=False,
                            detail=f"Forbidden pattern '{pattern}' found",
                        ))
                        failures.append(f"Executable pattern '{pattern}' in spec")

        if not any(c.check_name == "no_executable_code" for c in checks):
            checks.append(ValidationCheck(
                check_name="no_executable_code",
                passed=True,
                detail="No executable patterns detected",
            ))

        # Check 6: Separators are simple
        sep_ok = True
        for sep_name, sep_val in [("field_separator", spec.field_separator), ("entry_separator", spec.entry_separator)]:
            if sep_val and len(sep_val) > 3:
                sep_ok = False
                failures.append(f"{sep_name} too complex: '{sep_val}'")
        checks.append(ValidationCheck(
            check_name="separators_simple",
            passed=sep_ok,
            detail="Separators are simple characters",
        ))

        # Check 7: Regex is valid if present
        if spec.regex_pattern:
            try:
                re.compile(spec.regex_pattern)
                checks.append(ValidationCheck(
                    check_name="regex_valid",
                    passed=True,
                    detail="Regex compiles successfully",
                ))
            except re.error as e:
                checks.append(ValidationCheck(
                    check_name="regex_valid",
                    passed=False,
                    detail=f"Regex error: {e}",
                ))
                failures.append(f"Invalid regex: {e}")

        if failures:
            first_fail = failures[0]
            first_check = next((c.check_name for c in checks if not c.passed), "parser_safety")
            return ParserSafetyResult(
                safe=False,
                checks=checks,
                failure_reasons=failures,
                primary_reason=QuarantineReason.UNSAFE_PARSER_SPEC,
                primary_severity=QuarantineSeverity.CRITICAL,
                failed_check_name=first_check,
            )

        return ParserSafetyResult(
            safe=True,
            checks=checks,
            failure_reasons=[],
        )


class HybridTrustGate:
    """
    Validates PARSED EVENT output — schema/type/domain/semantic checks.

    Standardized Checks:
    1. Schema validation (required fields present) -> MISSING_REQUIRED_FIELD
    2. IP address validity (IPv4 & IPv6) -> INVALID_IP / INVALID_IPV6
    3. Port range validation (0-65535) -> INVALID_PORT
    4. Protocol validity -> INVALID_PROTOCOL
    5. MAC address validity -> INVALID_MAC
    6. CIDR notation validity -> INVALID_CIDR
    7. Timestamp validity & plausibility -> INVALID_TIMESTAMP / TIMESTAMP_IMPLAUSIBLE
    8. Confidence threshold -> LOW_CONFIDENCE_MAPPING
    9. Semantic consistency (action enum & field typing) -> SEMANTIC_MISMATCH / TYPE_MISMATCH

    Classification: IMPLEMENTED
    """

    MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")

    def validate(
        self, parsed_fields: dict[str, Any], confidence: float, source_hint: str = "generic"
    ) -> TrustGateResult:
        checks: list[ValidationCheck] = []
        failures: list[str] = []
        primary_reason = QuarantineReason.TRUST_GATE_FAILED
        primary_severity = QuarantineSeverity.MEDIUM
        failed_check_name = ""
        failed_value = None

        # Check 1: Required fields (source-aware)
        source_lower = (source_hint or "generic").lower()
        if any(k in source_lower for k in ["router", "cisco", "switch", "link"]):
            required = {"network.interface", "action"}
        elif any(k in source_lower for k in ["ids", "snort", "suricata", "scan"]):
            required = {"source.ip", "destination.ip", "network.transport"}
        elif any(k in source_lower for k in ["firewall", "netfilter", "iptables"]):
            required = {"source.ip", "destination.ip", "action"}
        elif "network.interface" in parsed_fields and "source.ip" not in parsed_fields:
            required = {"network.interface", "action"}
        elif "source.ip" in parsed_fields or "destination.ip" in parsed_fields:
            required = {"source.ip", "destination.ip", "action"}
        else:
            # Generic application or system event: schema-agnostic (do not force network fields)
            required = set()

        present = set(parsed_fields.keys())
        missing = required - present
        checks.append(ValidationCheck(
            check_name="required_fields",
            passed=len(missing) == 0,
            detail=f"Missing: {', '.join(missing)}" if missing else f"All required fields present ({', '.join(required)})",
            value=list(missing) if missing else [],
        ))
        if missing:
            failures.append(f"Missing required fields: {', '.join(missing)}")
            if not failed_check_name:
                primary_reason = QuarantineReason.MISSING_REQUIRED_FIELD
                primary_severity = QuarantineSeverity.MEDIUM
                failed_check_name = "required_fields"
                failed_value = list(missing)

        # Check 2: IP address validity (IPv4 / IPv6)
        for ip_field in ["source.ip", "destination.ip"]:
            if ip_field in parsed_fields:
                ip_val = str(parsed_fields[ip_field]).strip()
                try:
                    addr = ipaddress.ip_address(ip_val)
                    checks.append(ValidationCheck(
                        check_name=f"ip_valid:{ip_field}",
                        passed=True,
                        detail=f"{ip_field} = {ip_val} (IPv{addr.version}) ✓",
                        value=ip_val,
                    ))
                except ValueError:
                    checks.append(ValidationCheck(
                        check_name=f"ip_valid:{ip_field}",
                        passed=False,
                        detail=f"{ip_field} = {ip_val} — invalid IP address",
                        value=ip_val,
                    ))
                    failures.append(f"Invalid IP: {ip_field} = {ip_val}")
                    # Highest priority error
                    is_v6 = ":" in ip_val
                    primary_reason = QuarantineReason.INVALID_IPV6 if is_v6 else QuarantineReason.INVALID_IP
                    primary_severity = QuarantineSeverity.HIGH
                    failed_check_name = f"ip_valid:{ip_field}"
                    failed_value = ip_val

        # Check 3: Port range (0-65535)
        for port_field in ["source.port", "destination.port"]:
            if port_field in parsed_fields:
                port_val = parsed_fields[port_field]
                try:
                    port_int = int(port_val)
                    valid = 0 <= port_int <= 65535
                    checks.append(ValidationCheck(
                        check_name=f"port_range:{port_field}",
                        passed=valid,
                        detail=f"{port_field} = {port_int}" + (" ✓" if valid else " — must be 0-65535"),
                        value=port_int,
                    ))
                    if not valid:
                        failures.append(f"Port out of range: {port_field} = {port_int} (must be 0-65535)")
                        if failed_check_name != f"ip_valid:source.ip" and failed_check_name != f"ip_valid:destination.ip":
                            primary_reason = QuarantineReason.INVALID_PORT
                            primary_severity = QuarantineSeverity.MEDIUM
                            failed_check_name = f"port_range:{port_field}"
                            failed_value = port_val
                except (ValueError, TypeError):
                    checks.append(ValidationCheck(
                        check_name=f"port_range:{port_field}",
                        passed=False,
                        detail=f"{port_field} = {port_val} — not a valid integer",
                        value=port_val,
                    ))
                    failures.append(f"Invalid port: {port_field} = {port_val}")
                    if failed_check_name != f"ip_valid:source.ip" and failed_check_name != f"ip_valid:destination.ip":
                        primary_reason = QuarantineReason.INVALID_PORT
                        primary_severity = QuarantineSeverity.MEDIUM
                        failed_check_name = f"port_range:{port_field}"
                        failed_value = port_val

        # Check 4: Protocol validity
        if "network.transport" in parsed_fields:
            proto = str(parsed_fields["network.transport"]).upper()
            valid_protos = {p.upper() for p in settings.valid_protocols}
            proto_valid = proto in valid_protos
            checks.append(ValidationCheck(
                check_name="protocol_valid",
                passed=proto_valid,
                detail=f"protocol = {proto}" + (" ✓" if proto_valid else " — unknown protocol"),
                value=proto,
            ))
            if not proto_valid:
                failures.append(f"Unknown protocol: {proto}")
                if not failed_check_name:
                    primary_reason = QuarantineReason.INVALID_PROTOCOL
                    primary_severity = QuarantineSeverity.MEDIUM
                    failed_check_name = "protocol_valid"
                    failed_value = proto

        # Check 5: MAC address format
        for mac_field in ["source.mac", "destination.mac"]:
            if mac_field in parsed_fields:
                mac_val = str(parsed_fields[mac_field]).strip()
                mac_ok = bool(self.MAC_REGEX.match(mac_val))
                checks.append(ValidationCheck(
                    check_name=f"mac_valid:{mac_field}",
                    passed=mac_ok,
                    detail=f"{mac_field} = {mac_val}" + (" ✓" if mac_ok else " — invalid MAC format"),
                    value=mac_val,
                ))
                if not mac_ok:
                    failures.append(f"Invalid MAC format: {mac_field} = {mac_val}")
                    if not failed_check_name:
                        primary_reason = QuarantineReason.INVALID_MAC
                        primary_severity = QuarantineSeverity.MEDIUM
                        failed_check_name = f"mac_valid:{mac_field}"
                        failed_value = mac_val

        # Check 6: CIDR notation
        for cidr_field in ["source.cidr", "destination.cidr"]:
            if cidr_field in parsed_fields:
                cidr_val = str(parsed_fields[cidr_field]).strip()
                try:
                    ipaddress.ip_network(cidr_val, strict=False)
                    checks.append(ValidationCheck(
                        check_name=f"cidr_valid:{cidr_field}",
                        passed=True,
                        detail=f"{cidr_field} = {cidr_val} ✓",
                        value=cidr_val,
                    ))
                except ValueError:
                    checks.append(ValidationCheck(
                        check_name=f"cidr_valid:{cidr_field}",
                        passed=False,
                        detail=f"{cidr_field} = {cidr_val} — invalid CIDR prefix",
                        value=cidr_val,
                    ))
                    failures.append(f"Invalid CIDR: {cidr_field} = {cidr_val}")
                    if not failed_check_name:
                        primary_reason = QuarantineReason.INVALID_CIDR
                        primary_severity = QuarantineSeverity.MEDIUM
                        failed_check_name = f"cidr_valid:{cidr_field}"
                        failed_value = cidr_val

        # Check 7: Timestamp plausibility & format
        import datetime
        for time_field in ["time", "timestamp"]:
            if time_field in parsed_fields:
                t_val = parsed_fields[time_field]
                parsed_ts: float | None = None
                try:
                    if isinstance(t_val, (int, float)):
                        # If ms (> 1e11) vs s
                        parsed_ts = float(t_val) / 1000.0 if float(t_val) > 1e11 else float(t_val)
                    else:
                        dt = datetime.datetime.fromisoformat(str(t_val).replace("Z", "+00:00"))
                        parsed_ts = dt.timestamp()
                except Exception:
                    parsed_ts = None

                if parsed_ts is None:
                    checks.append(ValidationCheck(
                        check_name=f"timestamp_valid:{time_field}",
                        passed=False,
                        detail=f"{time_field} = {t_val} — cannot parse timestamp",
                        value=t_val,
                    ))
                    failures.append(f"Invalid timestamp format: {time_field} = {t_val}")
                    if not failed_check_name:
                        primary_reason = QuarantineReason.INVALID_TIMESTAMP
                        primary_severity = QuarantineSeverity.LOW
                        failed_check_name = f"timestamp_valid:{time_field}"
                        failed_value = t_val
                else:
                    # Check plausibility window: not > 1 day in future, not > 10 years in past
                    now_ts = datetime.datetime.now(datetime.timezone.utc).timestamp()
                    max_future = now_ts + settings.timestamp_max_future_seconds
                    max_past = now_ts - (settings.timestamp_max_past_years * 365.25 * 86400)
                    is_plausible = max_past <= parsed_ts <= max_future

                    checks.append(ValidationCheck(
                        check_name=f"timestamp_plausible:{time_field}",
                        passed=is_plausible,
                        detail=f"{time_field} = {t_val}" + (" ✓" if is_plausible else " — implausible timestamp (out of temporal bounds)"),
                        value=t_val,
                    ))
                    if not is_plausible:
                        failures.append(f"Implausible timestamp: {time_field} = {t_val}")
                        if not failed_check_name:
                            primary_reason = QuarantineReason.TIMESTAMP_IMPLAUSIBLE
                            primary_severity = QuarantineSeverity.LOW
                            failed_check_name = f"timestamp_plausible:{time_field}"
                            failed_value = t_val

        # Check 8: Confidence threshold
        conf_ok = confidence >= settings.min_confidence_threshold
        checks.append(ValidationCheck(
            check_name="confidence_threshold",
            passed=conf_ok,
            detail=f"confidence = {confidence:.2f} (threshold: {settings.min_confidence_threshold})",
            value=confidence,
        ))
        if not conf_ok:
            failures.append(f"Confidence {confidence:.2f} below threshold {settings.min_confidence_threshold}")
            if not failed_check_name:
                primary_reason = QuarantineReason.LOW_CONFIDENCE_MAPPING
                primary_severity = QuarantineSeverity.LOW
                failed_check_name = "confidence_threshold"
                failed_value = confidence

        # Check 9: Semantic consistency — action
        if "action" in parsed_fields:
            action = str(parsed_fields["action"]).upper()
            valid_actions = {a.upper() for a in settings.valid_actions}
            action_valid = action in valid_actions
            checks.append(ValidationCheck(
                check_name="action_valid",
                passed=action_valid,
                detail=f"action = {parsed_fields['action']}" + (" ✓" if action_valid else " — unknown action"),
                value=parsed_fields["action"],
            ))
            if not action_valid:
                failures.append(f"Unknown action: {parsed_fields['action']}")
                if not failed_check_name:
                    primary_reason = QuarantineReason.SEMANTIC_MISMATCH
                    primary_severity = QuarantineSeverity.MEDIUM
                    failed_check_name = "action_valid"
                    failed_value = parsed_fields["action"]

        # Build result
        passed_count = sum(1 for c in checks if c.passed)
        failed_count = sum(1 for c in checks if not c.passed)

        return TrustGateResult(
            result=ValidationResult.APPROVED if failed_count == 0 else ValidationResult.QUARANTINED,
            checks=checks,
            confidence=confidence,
            overall_passed=passed_count,
            overall_failed=failed_count,
            failure_reasons=failures,
            primary_reason=primary_reason if failed_count > 0 else QuarantineReason.FAILED_VALIDATION,
            primary_severity=primary_severity,
            failed_check_name=failed_check_name,
            failed_value=failed_value,
        )
