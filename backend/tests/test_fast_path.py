"""
Tests for Fast Path parser engine and known template matching.
"""

import pytest
from backend.parsers.fast_path import FastPathEngine
from backend.parsers.templates import FIREWALL_V1, ROUTER_V1, IDS_V1


def test_known_firewall_fast_path():
    engine = FastPathEngine()
    engine.load_parser("firewall_v1", FIREWALL_V1)

    log = "SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW"
    parser_id, parsed, confidence = engine.parse(log)

    assert parser_id == "firewall_v1"
    assert parsed is not None
    assert confidence == 1.0
    assert parsed.fields["source.ip"] == "10.10.1.25"
    assert parsed.fields["destination.ip"] == "172.16.2.10"
    assert parsed.fields["network.transport"] == "TCP"
    assert parsed.fields["destination.port"] == "443"
    assert parsed.fields["action"] == "ALLOW"


def test_known_router_fast_path():
    engine = FastPathEngine()
    engine.load_parser("router_v1", ROUTER_V1)

    log = "%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down"
    parser_id, parsed, confidence = engine.parse(log)

    assert parser_id == "router_v1"
    assert parsed is not None
    assert confidence > 0.8
    assert parsed.fields["network.interface"] == "GigabitEthernet0/1"
    assert parsed.fields["action"] == "down"


def test_known_ids_fast_path():
    engine = FastPathEngine()
    engine.load_parser("ids_v1", IDS_V1)

    log = "[**] [1:2001:3] ET SCAN Potential SSH Scan [**] {TCP} 192.168.1.100:45123 -> 10.0.0.1:22"
    parser_id, parsed, confidence = engine.parse(log)

    assert parser_id == "ids_v1"
    assert parsed is not None
    assert parsed.fields["source.ip"] == "192.168.1.100"
    assert parsed.fields["destination.ip"] == "10.0.0.1"
    assert parsed.fields["source.port"] == "45123"
    assert parsed.fields["destination.port"] == "22"
