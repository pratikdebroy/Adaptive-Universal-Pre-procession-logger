"""
Tests for drift detection:
When format changes, fast path must NOT confidently match, triggering escalation.
"""

import pytest
from backend.parsers.fast_path import FastPathEngine
from backend.parsers.templates import FIREWALL_V1
from backend.parsers.format_router import FormatRouter
from backend.models import ProcessingCopy


def test_drift_causes_fast_path_miss():
    engine = FastPathEngine()
    engine.load_parser("firewall_v1", FIREWALL_V1)
    router = FormatRouter(engine)

    # Drifted log format: SRC_IP instead of SRC, DST_IP instead of DST, PORT instead of DPT, ACT instead of ACTION
    drifted_log = "SRC_IP=10.10.1.25 DST_IP=172.16.2.10 PROTO=TCP PORT=443 ACT=ALLOW"
    proc_copy = ProcessingCopy(event_id="test-1", sanitized_message=drifted_log)

    route, parsed, parser_id = router.route(proc_copy)

    # Must route to ADAPTIVE, not FAST_PATH
    assert route == "ADAPTIVE"
    assert parsed is None
    assert parser_id == ""


def test_format_signature_changes_on_drift():
    engine = FastPathEngine()

    orig_log = "SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW"
    drifted_log = "SRC_IP=10.10.1.25 DST_IP=172.16.2.10 PROTO=TCP PORT=443 ACT=ALLOW"

    sig_orig = engine.compute_format_signature(orig_log)
    sig_drifted = engine.compute_format_signature(drifted_log)

    assert sig_orig != sig_drifted
