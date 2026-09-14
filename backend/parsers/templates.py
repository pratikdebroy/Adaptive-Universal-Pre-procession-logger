"""
Pre-defined parser specifications for known log formats.
These seed the parser registry on first startup.
"""

from backend.models import ParserSpecification


FIREWALL_V1 = ParserSpecification(
    template="SRC=<*> DST=<*> PROTO=<*> DPT=<*> ACTION=<*>",
    field_separator="=",
    entry_separator=" ",
    fields={
        "SRC": "source.ip",
        "DST": "destination.ip",
        "PROTO": "network.transport",
        "DPT": "destination.port",
        "ACTION": "action",
    },
    field_types={
        "SRC": "ip",
        "DST": "ip",
        "DPT": "port",
        "PROTO": "protocol",
        "ACTION": "action",
    },
    constants={},
    source_hint="firewall",
    confidence=1.0,
)

ROUTER_V1 = ParserSpecification(
    template="%LINK-<*>-<*>: Interface <*>, changed state to <*>",
    field_separator="",
    entry_separator="",
    fields={
        "severity": "severity",
        "state": "action",
        "interface": "network.interface",
        "action": "action",
    },
    field_types={
        "severity": "number",
        "interface": "string",
        "action": "action",
    },
    regex_pattern=r"%([\w]+)-(?P<severity>\d+)-(?P<state>[A-Z]+):\s*Interface\s*(?P<interface>\S+),\s*changed state to\s*(?P<action>.+)",
    source_hint="router",
    confidence=1.0,
)

IDS_V1 = ParserSpecification(
    template="[**] [<*>:<*>:<*>] <*> [**] {<*>} <*>:<*> -> <*>:<*>",
    field_separator="",
    entry_separator="",
    fields={
        "rule_id": "rule.uid",
        "msg": "message",
        "proto": "network.transport",
        "src_ip": "source.ip",
        "src_port": "source.port",
        "dst_ip": "destination.ip",
        "dst_port": "destination.port",
    },
    field_types={
        "src_ip": "ip",
        "dst_ip": "ip",
        "src_port": "port",
        "dst_port": "port",
        "proto": "protocol",
        "rule_id": "string",
        "msg": "string",
    },
    regex_pattern=r"\[\*\*\]\s*\[\d+:(?P<rule_id>\d+):\d+\]\s*(?P<msg>[^\[]+?)\s*\[\*\*\]\s*\{(?P<proto>\w+)\}\s*(?P<src_ip>[\d.]+):(?P<src_port>\d+)\s*->\s*(?P<dst_ip>[\d.]+):(?P<dst_port>\d+)",
    source_hint="ids",
    confidence=1.0,
)


# Map of parser_id -> (display_name, spec)
KNOWN_PARSERS: dict[str, tuple[str, ParserSpecification]] = {
    "firewall_v1": ("Firewall V1", FIREWALL_V1),
    "router_v1": ("Router V1", ROUTER_V1),
    "ids_v1": ("IDS V1", IDS_V1),
}


# The drifted format that should be DISCOVERED by the adaptive engine
DRIFTED_FIREWALL_SPEC = ParserSpecification(
    template="SRC_IP=<*> DST_IP=<*> PROTO=<*> PORT=<*> ACT=<*>",
    field_separator="=",
    entry_separator=" ",
    fields={
        "SRC_IP": "source.ip",
        "DST_IP": "destination.ip",
        "PROTO": "network.transport",
        "PORT": "destination.port",
        "ACT": "action",
    },
    field_types={
        "SRC_IP": "ip",
        "DST_IP": "ip",
        "PROTO": "protocol",
        "PORT": "port",
        "ACT": "action",
    },
    source_hint="firewall",
    confidence=0.85,
)
