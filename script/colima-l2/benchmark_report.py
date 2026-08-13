#!/usr/bin/env python3
"""Convert one Colima data-plane run into stable TSV and JSON results."""

from __future__ import annotations

import csv
import json
import math
import statistics
import sys
from pathlib import Path
from typing import Any


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as source:
        return list(csv.DictReader(source, delimiter="\t"))


def rate_to_bps(value: str) -> float:
    """Parse the iperf rate format used by the benchmark environment."""

    if not value:
        return 0.0
    text = value.strip()
    suffixes = {
        "K": 1_000.0,
        "M": 1_000_000.0,
        "G": 1_000_000_000.0,
        "T": 1_000_000_000_000.0,
    }
    suffix = text[-1:].upper()
    if suffix in suffixes:
        return float(text[:-1]) * suffixes[suffix]
    return float(text)


def iperf_throughput(path: Path) -> float:
    """Read the most stable throughput field from an iperf3 JSON result."""

    data = json.loads(path.read_text(encoding="utf-8"))
    end = data.get("end", {})
    candidates: list[Any] = [
        end.get("sum_received", {}).get("bits_per_second"),
        end.get("sum", {}).get("bits_per_second"),
        end.get("sum_sent", {}).get("bits_per_second"),
    ]
    for value in candidates:
        if value is not None:
            return float(value)
    raise ValueError(f"iperf3 result has no throughput field: {path}")


def resource_metrics(path: Path) -> dict[str, float | int]:
    rows = read_tsv(path)
    if not rows:
        return {
            "cpu_pct": 0.0,
            "peak_rss_kib": 0,
            "peak_threads": 0,
            "packets": 0,
            "bytes": 0,
        }

    def values(name: str, cast: type[float] | type[int]) -> list[float | int]:
        result: list[float | int] = []
        for row in rows:
            try:
                result.append(cast(row[name]))
            except (KeyError, TypeError, ValueError):
                continue
        return result

    cpu_values = [float(value) for value in values("cpu_pct", float)]
    rss_values = [int(value) for value in values("rss_kib", int)]
    thread_values = [int(value) for value in values("threads", int)]
    packet_values = [
        int(row.get("rx_packets", "0")) + int(row.get("tx_packets", "0"))
        for row in rows
    ]
    byte_values = [
        int(row.get("rx_bytes", "0")) + int(row.get("tx_bytes", "0"))
        for row in rows
    ]

    def delta(values_for_delta: list[int]) -> int:
        if len(values_for_delta) < 2:
            return 0
        return max(0, values_for_delta[-1] - values_for_delta[0])

    return {
        "cpu_pct": statistics.mean(cpu_values) if cpu_values else 0.0,
        "peak_rss_kib": max(rss_values, default=0),
        "peak_threads": max(thread_values, default=0),
        "packets": delta(packet_values),
        "bytes": delta(byte_values),
    }


def finite(value: float | int) -> float | int:
    if isinstance(value, float) and not math.isfinite(value):
        return 0.0
    return value


def build_result(result_dir: Path, case: dict[str, str]) -> dict[str, Any]:
    endpoint_a = resource_metrics(result_dir / case["resource_a"])
    endpoint_b = resource_metrics(result_dir / case["resource_b"])
    throughput = iperf_throughput(result_dir / case["iperf_json"])
    return {
        "case_id": case["case_id"],
        "scenario": case["scenario"],
        "mode": case["mode"],
        "queue_count": int(case["queue_count"]),
        "protocol": case["protocol"],
        "direction": case["direction"],
        "streams": int(case["streams"]),
        "offered_bps": finite(rate_to_bps(case["offered_rate"])),
        "wall_time_ms": int(case["wall_time_ms"]),
        "throughput_bps": finite(throughput),
        "endpoint_a_cpu_pct": finite(float(endpoint_a["cpu_pct"])),
        "endpoint_b_cpu_pct": finite(float(endpoint_b["cpu_pct"])),
        "endpoint_a_peak_rss_kib": int(endpoint_a["peak_rss_kib"]),
        "endpoint_b_peak_rss_kib": int(endpoint_b["peak_rss_kib"]),
        "endpoint_a_peak_threads": int(endpoint_a["peak_threads"]),
        "endpoint_b_peak_threads": int(endpoint_b["peak_threads"]),
        "endpoint_a_packets": int(endpoint_a["packets"]),
        "endpoint_b_packets": int(endpoint_b["packets"]),
        "endpoint_a_bytes": int(endpoint_a["bytes"]),
        "endpoint_b_bytes": int(endpoint_b["bytes"]),
        "iperf_json": case["iperf_json"],
        "resource_a": case["resource_a"],
        "resource_b": case["resource_b"],
    }


FIELDS = [
    "case_id",
    "scenario",
    "mode",
    "queue_count",
    "protocol",
    "direction",
    "streams",
    "offered_bps",
    "wall_time_ms",
    "throughput_bps",
    "endpoint_a_cpu_pct",
    "endpoint_b_cpu_pct",
    "endpoint_a_peak_rss_kib",
    "endpoint_b_peak_rss_kib",
    "endpoint_a_peak_threads",
    "endpoint_b_peak_threads",
    "endpoint_a_packets",
    "endpoint_b_packets",
    "endpoint_a_bytes",
    "endpoint_b_bytes",
]


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} RESULT_DIR", file=sys.stderr)
        return 2

    result_dir = Path(sys.argv[1])
    cases = read_tsv(result_dir / "cases.tsv")
    results = [build_result(result_dir, case) for case in cases]

    with (result_dir / "results.tsv").open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=FIELDS, delimiter="\t", extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)

    (result_dir / "results.json").write_text(
        json.dumps({"cases": results}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    # Keep summary.tsv as a simple source-compatible alias for operators.
    (result_dir / "summary.tsv").write_text(
        (result_dir / "results.tsv").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    print(f"Parsed {len(results)} benchmark cases")
    print(f"Results: {result_dir / 'results.tsv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
