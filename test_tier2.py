import sys
sys.path.append(".")
from backend.adaptive.tier2_structural import StructuralAnalyzer

analyzer = StructuralAnalyzer()
msg = "John tuesday logins from device 9788"
confident, semantic_confidence, spec, detail = analyzer.analyze(msg)

print("CONFIDENT:", confident)
print("SPEC:", spec)
print("REGEX PATTERN:", detail["regex_pattern"])
print("TOTAL KV:", detail["total_kv_pairs"])
print("FIELDS:", detail["variables_identified"])
