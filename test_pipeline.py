"""
End-to-end pipeline test for all log types.
Tests the restructured architecture matches the diagram.
"""
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["PYTHONIOENCODING"] = "utf-8"


async def main():
    from backend.core.pipeline import pipeline

    print("=" * 70)
    print("INITIALIZING PIPELINE...")
    print("=" * 70)
    await pipeline.initialize()
    print(f"Active parsers: {pipeline.fast_path.get_parser_count()}")
    print(f"BDPT clusters: {len(pipeline.tier1.miner.clusters)}")
    print()

    test_cases = [
        {
            "name": "Firewall V1 (KV format)",
            "log": "SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW",
            "expect_mode": "FAST_PATH",
        },
        {
            "name": "Router V1 (Cisco syslog)",
            "log": "%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down",
            "expect_mode": "FAST_PATH",
        },
        {
            "name": "IDS V1 (Snort format)",
            "log": "[**] [1:2001:3] ET SCAN Potential SSH Scan [**] {TCP} 192.168.1.100:45123 -> 10.0.0.1:22",
            "expect_mode": "FAST_PATH",
        },
        {
            "name": "Drifted Firewall (new keys)",
            "log": "SRC_IP=10.10.1.25 DST_IP=172.16.2.10 PROTO=TCP PORT=443 ACT=ALLOW",
            "expect_mode": "TIER3_ADAPTIVE",
        },
        {
            "name": "Unstructured text",
            "log": "john tuesday logins from device 5678",
            "expect_mode": "TIER3_ADAPTIVE",
        },
    ]

    results = []
    for i, tc in enumerate(test_cases):
        print("-" * 70)
        print(f"TEST {i+1}: {tc['name']}")
        print(f"LOG: {tc['log']}")
        print("-" * 70)

        try:
            response = await pipeline.process_event(tc["log"], source="test")

            mode = response.processing_mode.value if response.processing_mode else "UNKNOWN"
            quarantined = response.quarantine is not None

            status = "PASS" if not quarantined else "QUARANTINED"
            mode_match = mode == tc["expect_mode"]

            print(f"  Mode: {mode} {'[OK]' if mode_match else '[EXPECTED ' + tc['expect_mode'] + ']'}")
            print(f"  Status: {status}")
            print(f"  Confidence: {response.confidence:.2f}")
            print(f"  Parser ID: {response.parser_id}")
            td = response.tier_detail or ""
            print(f"  Tier Detail: {td[:120]}...")

            if quarantined:
                print(f"  QUARANTINE Reason: {response.quarantine.reason.value}")
                print(f"  QUARANTINE Detail: {response.quarantine.detail}")

            print(f"  Stages: {' -> '.join(s.name + '(' + s.status + ')' for s in response.stages)}")

            results.append({
                "name": tc["name"],
                "passed": not quarantined,
                "mode": mode,
                "mode_match": mode_match,
            })

        except Exception as e:
            import traceback
            print(f"  EXCEPTION: {e}")
            traceback.print_exc()
            results.append({"name": tc["name"], "passed": False, "mode": "ERROR", "mode_match": False})

        print()

    # Summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    for r in results:
        icon = "[PASS]" if r["passed"] else "[FAIL]"
        mode_icon = "[OK]" if r["mode_match"] else "[WRONG_MODE]"
        print(f"  {icon} {r['name']} [{r['mode']}] {mode_icon}")
    print(f"\n  {passed}/{total} tests passed")

    metrics = pipeline.get_metrics()
    print(f"\n  Metrics: FP={metrics['fast_path_count']}, T3={metrics['tier3_count']}, Q={metrics['quarantine_count']}")


if __name__ == "__main__":
    asyncio.run(main())
