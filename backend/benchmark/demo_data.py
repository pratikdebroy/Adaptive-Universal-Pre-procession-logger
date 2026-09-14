"""
Demo dataset with 8 log types and ground truth for benchmarking.
All sample events used throughout the prototype.
"""

from __future__ import annotations

# ──────────────────────────────────────────────
# Known Formats
# ──────────────────────────────────────────────

KNOWN_FIREWALL_LOGS = [
    "SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW",
    "SRC=192.168.1.100 DST=10.0.0.1 PROTO=UDP DPT=53 ACTION=ALLOW",
    "SRC=172.16.0.5 DST=192.168.1.1 PROTO=TCP DPT=22 ACTION=DENY",
    "SRC=10.0.0.50 DST=203.0.113.10 PROTO=TCP DPT=80 ACTION=ALLOW",
    "SRC=192.168.10.25 DST=10.10.10.1 PROTO=ICMP DPT=0 ACTION=DROP",
    "SRC=10.20.30.40 DST=172.16.5.100 PROTO=TCP DPT=8080 ACTION=ALLOW",
    "SRC=192.168.0.1 DST=10.0.0.254 PROTO=UDP DPT=161 ACTION=ALLOW",
    "SRC=172.16.1.50 DST=192.168.2.100 PROTO=TCP DPT=3389 ACTION=DENY",
]

KNOWN_ROUTER_LOGS = [
    "%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down",
    "%LINK-3-UPDOWN: Interface GigabitEthernet0/2, changed state to up",
    "%LINK-5-CHANGED: Interface Serial0/0, changed state to administratively down",
    "%SYS-5-CONFIG_I: Configured from console by admin on vty0",
    "%LINEPROTO-5-UPDOWN: Line protocol on Interface FastEthernet0/0, changed state to up",
]

KNOWN_IDS_LOGS = [
    '[**] [1:2001:3] ET SCAN Potential SSH Scan [**] {TCP} 192.168.1.100:45123 -> 10.0.0.1:22',
    '[**] [1:2002:4] ET SCAN Nmap SYN Scan [**] {TCP} 10.10.1.50:55432 -> 172.16.0.1:80',
    '[**] [1:2003:2] ET POLICY DNS Query for Suspicious Domain [**] {UDP} 192.168.5.10:51234 -> 8.8.8.8:53',
    '[**] [1:2100:5] GPL EXPLOIT CVE-2021-44228 Log4j RCE [**] {TCP} 203.0.113.50:12345 -> 10.0.0.5:8080',
]

# ──────────────────────────────────────────────
# Drifted / Mutated Formats
# ──────────────────────────────────────────────

DRIFTED_FIREWALL_LOGS = [
    "SRC_IP=10.10.1.25 DST_IP=172.16.2.10 PROTO=TCP PORT=443 ACT=ALLOW",
    "SRC_IP=192.168.1.100 DST_IP=10.0.0.1 PROTO=UDP PORT=53 ACT=ALLOW",
    "SRC_IP=172.16.0.5 DST_IP=192.168.1.1 PROTO=TCP PORT=22 ACT=DENY",
    "SRC_IP=10.0.0.50 DST_IP=203.0.113.10 PROTO=TCP PORT=80 ACT=ALLOW",
    "SRC_IP=192.168.10.25 DST_IP=10.10.10.1 PROTO=ICMP PORT=0 ACT=DROP",
]

# Ground truth for drifted format
DRIFTED_FIREWALL_GROUND_TRUTH = {
    "fields": {
        "SRC_IP": "source.ip",
        "DST_IP": "destination.ip",
        "PROTO": "network.transport",
        "PORT": "destination.port",
        "ACT": "action",
    },
    "field_types": {
        "SRC_IP": "ip",
        "DST_IP": "ip",
        "PROTO": "protocol",
        "PORT": "port",
        "ACT": "action",
    },
}

# ──────────────────────────────────────────────
# Malformed / Invalid Logs
# ──────────────────────────────────────────────

MALFORMED_LOGS = [
    "",  # empty
    "   ",  # whitespace only
    "\x00\x01\x02\x03binary garbage\xff\xfe",  # binary
    "just a random string with no structure whatsoever and no key value pairs at all",
    '{"unclosed_json": "value',  # broken JSON
]

INVALID_IP_LOGS = [
    "SRC=999.999.999.999 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW",
    "SRC=10.10.1.25 DST=256.0.0.1 PROTO=TCP DPT=80 ACTION=ALLOW",
    "SRC=not_an_ip DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW",
]

INVALID_PORT_LOGS = [
    "SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=99999 ACTION=ALLOW",
    "SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=-1 ACTION=ALLOW",
    "SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=port ACTION=ALLOW",
]

OVERSIZED_PAYLOAD = "SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW PAYLOAD=" + "A" * 100000

SUSPICIOUS_PAYLOAD_LOGS = [
    "SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW; DROP TABLE events;--",
    "SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW<script>alert(1)</script>",
    "SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW\nimport os; os.system('rm -rf /')",
]

# ──────────────────────────────────────────────
# New Source Onboarding Samples
# ──────────────────────────────────────────────

ONBOARDING_SAMPLES = {
    "waf_logs": [
        "CLIENT=203.0.113.50 SERVER=10.0.0.5 METHOD=GET URI=/admin PATH=/admin STATUS=403 RULE=SQL_INJECTION",
        "CLIENT=198.51.100.20 SERVER=10.0.0.5 METHOD=POST URI=/login PATH=/login STATUS=200 RULE=NONE",
        "CLIENT=203.0.113.75 SERVER=10.0.0.10 METHOD=GET URI=/api/users PATH=/api/users STATUS=401 RULE=AUTH_BYPASS",
    ],
    "vpn_logs": [
        "USER=jsmith REMOTE_IP=203.0.113.100 VPN_IP=10.8.0.25 PROTO=UDP PORT=1194 STATUS=CONNECTED",
        "USER=admin REMOTE_IP=198.51.100.50 VPN_IP=10.8.0.26 PROTO=UDP PORT=1194 STATUS=DISCONNECTED",
    ],
}

# ──────────────────────────────────────────────
# Complete Benchmark Dataset with Ground Truth
# ──────────────────────────────────────────────

BENCHMARK_DATASET = []

# Add known firewall events with ground truth
for log in KNOWN_FIREWALL_LOGS:
    parts = dict(item.split("=", 1) for item in log.split() if "=" in item)
    BENCHMARK_DATASET.append({
        "raw": log,
        "category": "known_firewall",
        "expected_parser": "firewall_v1",
        "expected_mode": "FAST_PATH",
        "expected_fields": {
            "source.ip": parts.get("SRC", ""),
            "destination.ip": parts.get("DST", ""),
            "network.transport": parts.get("PROTO", ""),
            "destination.port": parts.get("DPT", ""),
            "action": parts.get("ACTION", ""),
        },
        "should_quarantine": False,
    })

# Add drifted firewall events
for log in DRIFTED_FIREWALL_LOGS:
    parts = dict(item.split("=", 1) for item in log.split() if "=" in item)
    BENCHMARK_DATASET.append({
        "raw": log,
        "category": "drifted_firewall",
        "expected_parser": "firewall_v2",
        "expected_mode": "TIER3_ADAPTIVE",
        "expected_fields": {
            "source.ip": parts.get("SRC_IP", ""),
            "destination.ip": parts.get("DST_IP", ""),
            "network.transport": parts.get("PROTO", ""),
            "destination.port": parts.get("PORT", ""),
            "action": parts.get("ACT", ""),
        },
        "should_quarantine": False,
    })

# Add malformed events
for log in MALFORMED_LOGS:
    BENCHMARK_DATASET.append({
        "raw": log,
        "category": "malformed",
        "expected_parser": None,
        "expected_mode": None,
        "expected_fields": {},
        "should_quarantine": True,
    })

# Add invalid IP events
for log in INVALID_IP_LOGS:
    BENCHMARK_DATASET.append({
        "raw": log,
        "category": "invalid_ip",
        "expected_parser": "firewall_v1",
        "expected_mode": "FAST_PATH",
        "expected_fields": {},
        "should_quarantine": True,
    })

# Add invalid port events
for log in INVALID_PORT_LOGS:
    BENCHMARK_DATASET.append({
        "raw": log,
        "category": "invalid_port",
        "expected_parser": "firewall_v1",
        "expected_mode": "FAST_PATH",
        "expected_fields": {},
        "should_quarantine": True,
    })

# Add router/IDS for variety
for log in KNOWN_ROUTER_LOGS:
    BENCHMARK_DATASET.append({
        "raw": log,
        "category": "known_router",
        "expected_parser": "router_v1",
        "expected_mode": "FAST_PATH",
        "expected_fields": {},
        "should_quarantine": False,
    })

for log in KNOWN_IDS_LOGS:
    BENCHMARK_DATASET.append({
        "raw": log,
        "category": "known_ids",
        "expected_parser": "ids_v1",
        "expected_mode": "FAST_PATH",
        "expected_fields": {},
        "should_quarantine": False,
    })


def get_demo_step_events() -> dict[int, dict]:
    """Events for the 10-step judge demo sequence."""
    return {
        1: {
            "raw": "",
            "description": "RESET: Reset demo state, registry to initial seed, metrics, and evidence vault.",
        },
        2: {
            "raw": "SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW",
            "description": "SEND KNOWN V1: Fast Path hit, zero Tier-3 AI invocations.",
        },
        3: {
            "raw": "SRC_IP=10.10.1.25 DST_IP=172.16.2.10 PROTO=TCP PORT=443 ACT=ALLOW",
            "description": "INTRODUCE V2 FORMAT DRIFT: Old parser misses, format signature mismatch → FAST PATH MISS.",
        },
        4: {
            "raw": "SRC_IP=10.10.1.25 DST_IP=172.16.2.10 PROTO=TCP PORT=443 ACT=ALLOW",
            "description": "RUN SELF-HEALING / ADAPTIVE PIPELINE: BDPT → Structural Analysis → Semantic Uncertainty → Tier-3 → Parser Safety → Trust Gate APPROVED.",
        },
        5: {
            "raw": "",
            "description": "PROMOTE: Transition Candidate → ACTIVE in SQLite + atomic cache swap.",
        },
        6: {
            "raw": "SRC_IP=10.10.1.25 DST_IP=172.16.2.10 PROTO=TCP PORT=443 ACT=ALLOW",
            "description": "REPLAY SAME V2: Handled by Fast Path with zero AI invocations.",
        },
        7: {
            "raw": "",
            "description": "SHOW PROVENANCE: Full lineage trace (Raw Event → SHA-256 → Parser Version → OCSF).",
        },
        8: {
            "raw": "",
            "description": "TAMPER CHECK: Modify raw evidence byte → Merkle root mismatch → INTEGRITY FAILURE.",
        },
        9: {
            "raw_invalid_ip": "SRC_IP=999.999.999.999 DST_IP=172.16.2.10 PROTO=TCP PORT=443 ACT=ALLOW",
            "raw_invalid_port": "SRC_IP=10.10.1.25 DST_IP=172.16.2.10 PROTO=TCP PORT=99999 ACT=ALLOW",
            "description": "QUARANTINE VERIFICATION (BOTH TESTS): Test Invalid IP (999.999.999.999) and Invalid Port (99999) separately.",
        },
        10: {
            "raw": "",
            "description": "ROLLBACK: Deactivates the promoted parser and restores the previously ACTIVE compatible parser.",
        },
    }



def generate_benchmark_batch(count: int = 100) -> list[str]:
    """Generate a batch of events for benchmarking. Mix of known, drifted, malformed."""
    import random
    events = []
    for _ in range(count):
        r = random.random()
        if r < 0.70:
            events.append(random.choice(KNOWN_FIREWALL_LOGS))
        elif r < 0.80:
            events.append(random.choice(KNOWN_ROUTER_LOGS))
        elif r < 0.85:
            events.append(random.choice(KNOWN_IDS_LOGS))
        elif r < 0.92:
            events.append(random.choice(DRIFTED_FIREWALL_LOGS))
        elif r < 0.96:
            events.append(random.choice(MALFORMED_LOGS))
        elif r < 0.98:
            events.append(random.choice(INVALID_IP_LOGS))
        else:
            events.append(random.choice(INVALID_PORT_LOGS))
    return events
