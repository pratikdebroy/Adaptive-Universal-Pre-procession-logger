"""
Tests for OCSF-compatible Network Activity normalization (class_uid: 4001).
"""

from backend.normalization.ocsf_normalizer import OCSFNormalizer
from backend.models import RawEvent, ProcessingMode


def test_ocsf_normalization_structure():
    normalizer = OCSFNormalizer()
    raw = RawEvent(raw_message="SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW", raw_sha256="abc123hash")

    fields = {
        "source.ip": "10.10.1.25",
        "source.port": 54321,
        "destination.ip": "172.16.2.10",
        "destination.port": 443,
        "network.transport": "TCP",
        "action": "ALLOW",
    }

    ocsf = normalizer.normalize(
        parsed_fields=fields,
        raw_event=raw,
        parser_id="test_parser",
        parser_version=1,
        processing_mode=ProcessingMode.FAST_PATH,
        confidence=1.0,
    )

    # Assert OCSF Network Activity (4001) required invariants
    assert ocsf.category_uid == 4
    assert ocsf.category_name == "Network Activity"
    assert ocsf.class_uid == 4001
    assert ocsf.class_name == "Network Activity"
    assert ocsf.activity_id == 6
    assert ocsf.type_uid == 400106

    # Endpoint schemas
    assert ocsf.src_endpoint["ip"] == "10.10.1.25"
    assert ocsf.src_endpoint["port"] == 54321
    assert ocsf.dst_endpoint["ip"] == "172.16.2.10"
    assert ocsf.dst_endpoint["port"] == 443

    # Protocol & Action mappings
    assert ocsf.connection_info["protocol_name"] == "tcp"
    assert ocsf.connection_info["protocol_num"] == 6
    assert ocsf.action == "Allowed"
    assert ocsf.action_id == 1

    # Provenance retainment
    assert ocsf.raw_event_id == raw.event_id
    assert ocsf.raw_sha256 == "abc123hash"
    assert ocsf.parser_id == "test_parser"
    assert ocsf.parser_version == 1
    assert ocsf.confidence == 1.0
