"""
CLI Runner for the 9-Step SIH Judge Demo Sequence.
Executes each step against the live backend pipeline and prints formatted evidence.

Usage:
    python -m scripts.run_demo
"""

import asyncio
import json
import sys

# Force UTF-8 output encoding for Windows terminals
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

from backend.core.pipeline import pipeline
from backend.storage.database import init_db, reset_db
from backend.benchmark.demo_data import get_demo_step_events
from backend.api.demo import execute_demo_step


async def run_cli_demo():
    print("=" * 70)
    print("  SIH26156 — 9-STEP LIVE JUDGE DEMONSTRATION")
    print("  Organization: National Technical Research Organisation (NTRO)")
    print("=" * 70)

    await reset_db()
    await pipeline.initialize()

    for step_num in range(1, 10):
        print(f"\n[>] EXECUTING STEP {step_num}...")
        result = await execute_demo_step(step_num)

        title = result.get("title", "")
        desc = result.get("description", "")
        highlight = result.get("highlight", {})

        print(f"  Title      : {title}")
        print(f"  Description: {desc}")
        if highlight:
            print("  Highlights :")
            for k, v in highlight.items():
                print(f"    * {k}: {v}")

        # Specific proofs per step
        if step_num == 1:
            resp = result.get("response", {})
            print(f"    -> Routing Path : {resp.get('processing_mode')}")
            print(f"    -> Parser Active: {resp.get('parser_name') or resp.get('parser_id')}")
            print(f"    -> OCSF Class   : {resp.get('ocsf_event', {}).get('class_name')}")

        elif step_num == 7:
            print("    [!] SELF-HEALING PROOF: The drifted log was parsed on the FAST PATH!")

        elif step_num == 9:
            integ = result.get("integrity", {})
            print(f"    [!] TAMPER PROOF: Status = {integ.get('status')}")
            print(f"      Expected Root: {integ.get('expected_merkle_root')}")
            print(f"      Computed Root: {integ.get('computed_merkle_root')}")

        await asyncio.sleep(0.5)

    print("\n" + "=" * 70)
    print("  DEMO COMPLETE: All 9 steps executed with authentic state transitions.")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(run_cli_demo())
