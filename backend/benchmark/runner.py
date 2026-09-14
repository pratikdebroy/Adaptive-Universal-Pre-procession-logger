"""
Standalone Benchmark Runner for SIH26156.
Executes real batches of 100, 1,000, or 10,000 events against the pipeline.
Measures real EPS, average latency, P95 latency, AI (Tier-3) invocation rate,
quarantine rate, and schema validity.

DO NOT FABRICATE METRICS.
All output numbers reflect actual execution on the local machine.

Usage:
    python -m backend.benchmark.runner --count 100
    python -m backend.benchmark.runner --count 1000
"""

from __future__ import annotations

import argparse
import asyncio
import statistics
import time
import sys

from backend.core.pipeline import pipeline
from backend.benchmark.demo_data import generate_benchmark_batch
from backend.storage.database import init_db


async def run_cli_benchmark(count: int = 100):
    print("=" * 60)
    print("  SIH26156 UNIVERSAL LOG PRE-PROCESSING FRAMEWORK")
    print(f"  Benchmark Suite — Event Count: {count}")
    print("  Mode: Real Local Execution (No fabricated metrics)")
    print("=" * 60)

    await init_db()
    await pipeline.initialize()

    print(f"\n[1/3] Generating synthetic workload batch of {count} events...")
    events = generate_benchmark_batch(count)
    print(f"      Batch generated successfully.")

    print(f"[2/3] Executing pipeline across {count} events...")
    latencies: list[float] = []
    fast_path_count = 0
    structural_count = 0
    tier3_count = 0
    quarantine_count = 0
    valid_ocsf_count = 0

    total_start = time.perf_counter()

    for idx, raw_log in enumerate(events, 1):
        t0 = time.perf_counter()
        resp = await pipeline.process_event(raw_log, source="benchmark_cli")
        t1 = time.perf_counter()

        elapsed_ms = (t1 - t0) * 1000.0
        latencies.append(elapsed_ms)

        mode = resp.processing_mode.value
        if mode == "FAST_PATH":
            fast_path_count += 1
        elif mode == "STRUCTURAL":
            structural_count += 1
        elif mode == "TIER3_ADAPTIVE":
            tier3_count += 1

        if resp.quarantine:
            quarantine_count += 1
        if resp.ocsf_event:
            valid_ocsf_count += 1

        if idx % max(1, count // 10) == 0:
            print(f"      Processed {idx}/{count} events ({idx/count*100:.0f}%)...")

    total_elapsed = time.perf_counter() - total_start
    eps = count / total_elapsed if total_elapsed > 0 else 0.0

    sorted_lats = sorted(latencies)
    p50 = statistics.median(sorted_lats) if sorted_lats else 0.0
    p95_idx = int(len(sorted_lats) * 0.95)
    p95 = sorted_lats[p95_idx] if sorted_lats else 0.0
    avg_lat = statistics.mean(sorted_lats) if sorted_lats else 0.0
    min_lat = min(sorted_lats) if sorted_lats else 0.0
    max_lat = max(sorted_lats) if sorted_lats else 0.0

    print("\n[3/3] Results Calculation:")
    print("-" * 60)
    print(f"  Benchmark Environment   : Prototype benchmark — local environment")
    print(f"  Total Processed Events  : {count}")
    print(f"  Total Execution Time    : {total_elapsed:.3f} s")
    print(f"  Throughput (EPS)        : {eps:.2f} events/sec")
    print(f"  Average Latency         : {avg_lat:.2f} ms")
    print(f"  P50 Latency             : {p50:.2f} ms")
    print(f"  P95 Latency             : {p95:.2f} ms")
    print(f"  Latency Min / Max       : {min_lat:.2f} ms / {max_lat:.2f} ms")
    print("-" * 60)
    print(f"  ROUTING BREAKDOWN:")
    print(f"    • FAST PATH           : {fast_path_count} ({fast_path_count/count*100:.1f}%)")
    print(f"    • STRUCTURAL          : {structural_count} ({structural_count/count*100:.1f}%)")
    print(f"    • TIER-3 ADAPTIVE     : {tier3_count} ({tier3_count/count*100:.1f}%)")
    print(f"    • QUARANTINED (DLQ)   : {quarantine_count} ({quarantine_count/count*100:.1f}%)")
    print("-" * 60)
    print(f"  KEY ENGINEERING METRICS:")
    print(f"    • Tier-3 Inference Rate : {tier3_count/count*100:.2f}% (Proof: AI is not in hot path)")
    print(f"    • OCSF Schema Validity  : {valid_ocsf_count/count*100:.2f}%")
    print(f"    • Quarantine Rate       : {quarantine_count/count*100:.2f}%")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SIH26156 Log Preprocessing Benchmark")
    parser.add_argument("--count", type=int, default=100, choices=[100, 1000, 10000], help="Number of events to benchmark")
    args = parser.parse_args()

    asyncio.run(run_cli_benchmark(args.count))
