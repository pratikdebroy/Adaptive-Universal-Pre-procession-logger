"""
Tests for Tier-2 structural token classification and analysis.
"""

from backend.adaptive.tier2_structural import StructuralAnalyzer, TokenType, ValueType


def test_structural_token_classification():
    analyzer = StructuralAnalyzer()
    log = "SRC_IP=10.10.1.25 DST_IP=172.16.2.10 PROTO=TCP PORT=443 ACT=ALLOW"

    tokens = analyzer.tokenize(log)
    assert len(tokens) > 0

    key_tokens = [t.token for t in tokens if t.token_type == TokenType.KEY]
    assert "SRC_IP" in key_tokens
    assert "DST_IP" in key_tokens
    assert "PORT" in key_tokens

    # Verify type classification
    val_map = {}
    for i in range(len(tokens) - 2):
        if tokens[i].token_type == TokenType.KEY and tokens[i+1].token_type == TokenType.OPERATOR:
            val_map[tokens[i].token] = tokens[i+2].value_type

    assert val_map.get("SRC_IP") == ValueType.IP
    assert val_map.get("DST_IP") == ValueType.IP
    assert val_map.get("PORT") == ValueType.PORT
    assert val_map.get("PROTO") == ValueType.PROTOCOL
    assert val_map.get("ACT") == ValueType.ACTION


def test_structural_analysis_mapping():
    analyzer = StructuralAnalyzer()
    log = "SRC_IP=10.10.1.25 DST_IP=172.16.2.10 PROTO=TCP PORT=443 ACT=ALLOW"

    confident, score, spec, detail = analyzer.analyze(log)

    assert spec is not None
    # Structural confidence: token/type structure is fully understood
    assert detail["structural_confidence"] >= 0.70
    # Semantic mapping is uncertain for drifted keys without Tier-3 resolution
    assert not confident
    assert "SRC_IP" in spec.fields
    assert spec.fields["SRC_IP"] == "source.ip"
    assert spec.fields["DST_IP"] == "destination.ip"
    assert spec.fields["PORT"] == "destination.port"
    assert spec.fields["PROTO"] == "network.transport"
    assert spec.fields["ACT"] == "action"
