#!/usr/bin/env python3
"""Convert one Colima data-plane run into stable TSV and JSON results."""

from __future__ import annotations

import csv
import collections
import json
import math
import re
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
            throughput = float(value)
            if not math.isfinite(throughput) or throughput <= 0:
                raise ValueError(f"iperf3 throughput is not positive and finite: {path}")
            return throughput
    raise ValueError(f"iperf3 result has no throughput field: {path}")


def iperf_udp_metrics(path: Path) -> dict[str, float | int | None]:
    data = json.loads(path.read_text(encoding="utf-8"))
    summary = data.get("end", {}).get("sum", {})
    required = ("packets", "lost_packets", "lost_percent", "jitter_ms")
    if any(summary.get(name) is None for name in required):
        return {
            "sent_packets": None,
            "received_packets": None,
            "lost_packets": None,
            "loss_percent": None,
            "jitter_ms": None,
        }
    sent = int(summary["packets"])
    lost = int(summary["lost_packets"])
    received = sent - lost
    loss = float(summary["lost_percent"])
    jitter = float(summary["jitter_ms"])
    if (
        sent <= 0
        or lost < 0
        or received < 0
        or not math.isfinite(loss)
        or loss < 0
        or not math.isfinite(jitter)
        or jitter < 0
    ):
        raise ValueError(f"iperf3 UDP metrics are invalid: {path}")
    return {
        "sent_packets": sent,
        "received_packets": received,
        "lost_packets": lost,
        "loss_percent": loss,
        "jitter_ms": jitter,
    }


def prometheus_metric(path: Path, metric_name: str) -> int:
    pattern = re.compile(
        rf"^{re.escape(metric_name)}(?:\{{[^}}]*\}})?\s+(?P<value>[0-9]+(?:\.[0-9]+)?)$"
    )
    total = 0.0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = pattern.match(line.strip())
        if match is not None:
            total += float(match.group("value"))
    return int(total)


def resource_metrics(
    path: Path, window_start_ms: int, window_end_ms: int
) -> dict[str, Any]:
    rows = read_tsv(path)
    rows = [
        row
        for row in rows
        if window_start_ms <= int(row.get("epoch_ms", "0")) <= window_end_ms
    ]
    if not rows:
        return {
            "sampled": False,
            "complete": False,
            "samples": 0,
            "cpu_pct": 0.0,
            "peak_rss_kib": 0,
            "process_lifetime_hwm_kib": 0,
            "peak_rss_anon_kib": 0,
            "peak_rss_file_kib": 0,
            "peak_rss_shmem_kib": 0,
            "peak_pss_kib": 0,
            "peak_private_clean_kib": 0,
            "peak_private_dirty_kib": 0,
            "peak_threads": 0,
            "rx_packets": 0,
            "tx_packets": 0,
            "rx_bytes": 0,
            "tx_bytes": 0,
            "rows": [],
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
    hwm_values = [int(value) for value in values("hwm_kib", int)]
    rss_anon_values = [int(value) for value in values("rss_anon_kib", int)]
    rss_file_values = [int(value) for value in values("rss_file_kib", int)]
    rss_shmem_values = [int(value) for value in values("rss_shmem_kib", int)]
    pss_values = [int(value) for value in values("pss_kib", int)]
    private_clean_values = [int(value) for value in values("private_clean_kib", int)]
    private_dirty_values = [int(value) for value in values("private_dirty_kib", int)]
    thread_values = [int(value) for value in values("threads", int)]

    def delta(values_for_delta: list[int]) -> int:
        if len(values_for_delta) < 2:
            return 0
        return max(0, values_for_delta[-1] - values_for_delta[0])

    required_sample_fields = (
        "process_pid",
        "process_start_ticks",
        "rss_kib",
        "hwm_kib",
        "pss_kib",
        "threads",
    )
    first_pid = rows[0].get("process_pid", "")
    first_start_ticks = rows[0].get("process_start_ticks", "")
    def positive_integer(row: dict[str, str], name: str) -> bool:
        try:
            return int(row.get(name, "0")) > 0
        except (TypeError, ValueError):
            return False

    complete = bool(first_pid and first_start_ticks) and all(
        all(positive_integer(row, name) for name in required_sample_fields)
        and row.get("process_pid") == first_pid
        and row.get("process_start_ticks") == first_start_ticks
        for row in rows
    )

    return {
        "sampled": True,
        "complete": complete,
        "samples": len(rows),
        "cpu_pct": statistics.mean(cpu_values) if cpu_values else 0.0,
        "peak_rss_kib": max(rss_values, default=0),
        "process_lifetime_hwm_kib": max(hwm_values, default=0),
        "peak_rss_anon_kib": max(rss_anon_values, default=0),
        "peak_rss_file_kib": max(rss_file_values, default=0),
        "peak_rss_shmem_kib": max(rss_shmem_values, default=0),
        "peak_pss_kib": max(pss_values, default=0),
        "peak_private_clean_kib": max(private_clean_values, default=0),
        "peak_private_dirty_kib": max(private_dirty_values, default=0),
        "peak_threads": max(thread_values, default=0),
        "rx_packets": delta([int(row.get("rx_packets", "0")) for row in rows]),
        "tx_packets": delta([int(row.get("tx_packets", "0")) for row in rows]),
        "rx_bytes": delta([int(row.get("rx_bytes", "0")) for row in rows]),
        "tx_bytes": delta([int(row.get("tx_bytes", "0")) for row in rows]),
        "rows": rows,
    }


def combined_resource_metrics(resources: list[dict[str, Any]]) -> dict[str, int]:
    """Compute time-aligned process totals and conservative HWM totals."""

    if not resources or any(not resource["rows"] for resource in resources):
        return {
            "peak_rss_kib": 0,
            "hwm_sum_kib": 0,
            "peak_rss_anon_kib": 0,
            "peak_rss_file_kib": 0,
            "peak_rss_shmem_kib": 0,
            "peak_pss_kib": 0,
            "peak_private_clean_kib": 0,
            "peak_private_dirty_kib": 0,
            "peak_private_total_kib": 0,
            "aligned_samples": 0,
        }

    fields = (
        "rss_kib",
        "rss_anon_kib",
        "rss_file_kib",
        "rss_shmem_kib",
        "pss_kib",
        "private_clean_kib",
        "private_dirty_kib",
    )
    peaks = {field: 0 for field in fields}
    private_total_peak = 0
    aligned_samples = 0
    for base in resources[0]["rows"]:
        epoch = int(base["epoch_ms"])
        aligned = [base]
        for resource in resources[1:]:
            nearest = min(
                resource["rows"],
                key=lambda row: abs(int(row["epoch_ms"]) - epoch),
            )
            if abs(int(nearest["epoch_ms"]) - epoch) > 250:
                break
            aligned.append(nearest)
        if len(aligned) != len(resources):
            continue
        aligned_samples += 1
        totals = {
            field: sum(int(row.get(field, "0")) for row in aligned)
            for field in fields
        }
        for field, total in totals.items():
            peaks[field] = max(peaks[field], total)
        private_total_peak = max(
            private_total_peak,
            totals["private_clean_kib"] + totals["private_dirty_kib"],
        )

    return {
        "peak_rss_kib": peaks["rss_kib"],
        "hwm_sum_kib": sum(
            int(resource["process_lifetime_hwm_kib"]) for resource in resources
        ),
        "peak_rss_anon_kib": peaks["rss_anon_kib"],
        "peak_rss_file_kib": peaks["rss_file_kib"],
        "peak_rss_shmem_kib": peaks["rss_shmem_kib"],
        "peak_pss_kib": peaks["pss_kib"],
        "peak_private_clean_kib": peaks["private_clean_kib"],
        "peak_private_dirty_kib": peaks["private_dirty_kib"],
        "peak_private_total_kib": private_total_peak,
        "aligned_samples": aligned_samples,
    }


def route_proof_valid(path: Path, scenario: str) -> bool:
    try:
        proof = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(proof, dict) or proof.get("scenario") != scenario:
        return False
    if scenario == "direct-underlay":
        return bool(proof.get("forward_target") and proof.get("reverse_target"))
    expected_path_len = 2 if scenario == "relay-compact-l3" else 1
    expected_targets = {"forward": "10.88.0.2", "reverse": "10.88.0.1"}
    for direction in ("forward", "reverse"):
        route = proof.get(direction)
        if not isinstance(route, dict) or int(route.get("path_len", 0)) != expected_path_len:
            return False
        if str(route.get("ipv4", "")).split("/", 1)[0] != expected_targets[direction]:
            return False
        if (
            scenario == "relay-compact-l3"
            and route.get("next_hop_hostname") != "lowertier-l2-benchmark-relay"
        ):
            return False
    return True


PING_SAMPLE = re.compile(r"^\[(?P<epoch>[0-9.]+)\].* time[=<](?P<ms>[0-9.]+) ms$")
PING_SUMMARY = re.compile(
    r"(?P<sent>[0-9]+) packets transmitted, (?P<received>[0-9]+) (?:packets )?received"
)


def latency_metrics(
    path: Path, window_start_ms: int | None = None, window_end_ms: int | None = None
) -> dict[str, float | int | None]:
    samples: list[float] = []
    transmitted = 0
    received = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        summary = PING_SUMMARY.search(line)
        if summary is not None:
            transmitted = int(summary.group("sent"))
            received = int(summary.group("received"))
        match = PING_SAMPLE.search(line)
        if match is None:
            continue
        epoch_ms = int(float(match.group("epoch")) * 1000)
        if window_start_ms is not None and epoch_ms < window_start_ms:
            continue
        if window_end_ms is not None and epoch_ms > window_end_ms:
            continue
        samples.append(float(match.group("ms")))
    if not samples:
        return {"samples": 0, "transmitted": transmitted, "received": received, "min_ms": None, "mean_ms": None, "p95_ms": None, "max_ms": None}
    ordered = sorted(samples)
    p95_index = max(0, math.ceil(len(ordered) * 0.95) - 1)
    return {
        "samples": len(samples),
        "transmitted": transmitted,
        "received": received,
        "min_ms": ordered[0],
        "mean_ms": statistics.mean(samples),
        "p95_ms": ordered[p95_index],
        "max_ms": ordered[-1],
    }


def finite(value: float | int | None) -> float | int | None:
    if value is None:
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return 0.0
    return value


def build_result(
    result_dir: Path, case: dict[str, str], memory_ceiling_kib: int
) -> dict[str, Any]:
    window_start_ms = int(case["window_start_ms"])
    window_end_ms = int(case["window_end_ms"])
    endpoint_a = resource_metrics(
        result_dir / case["resource_a"], window_start_ms, window_end_ms
    )
    endpoint_b = resource_metrics(
        result_dir / case["resource_b"], window_start_ms, window_end_ms
    )
    relay = resource_metrics(
        result_dir / case["resource_relay"], window_start_ms, window_end_ms
    )
    idle_latency = latency_metrics(result_dir / case["idle_latency"])
    load_latency = latency_metrics(
        result_dir / case["load_latency"], window_start_ms, window_end_ms
    )
    throughput = iperf_throughput(result_dir / case["iperf_json"])
    is_underlay = case["scenario"] == "direct-underlay"
    required_resources = [] if is_underlay else [endpoint_a, endpoint_b]
    if case["scenario"] == "relay-compact-l3":
        required_resources.append(relay)
    combined_resources = combined_resource_metrics(required_resources)
    resource_valid = all(
        bool(metrics["sampled"])
        and bool(metrics["complete"])
        and int(metrics["samples"]) >= 2
        and int(metrics["peak_rss_kib"]) > 0
        and int(metrics["process_lifetime_hwm_kib"]) > 0
        and int(metrics["peak_pss_kib"]) > 0
        and int(metrics["peak_threads"]) > 0
        for metrics in required_resources
    )
    if is_underlay:
        memory_ceiling_status = "not_applicable"
    elif resource_valid and all(
        int(metrics["peak_rss_kib"]) <= memory_ceiling_kib
        and int(metrics["process_lifetime_hwm_kib"]) <= memory_ceiling_kib
        for metrics in required_resources
    ):
        memory_ceiling_status = "pass"
    else:
        memory_ceiling_status = "fail"
    idle_expected = int(case["idle_expected"])
    load_expected = int(case["load_expected"])
    idle_transmitted = int(idle_latency["transmitted"] or 0)
    idle_received = int(idle_latency["received"] or 0)
    load_transmitted = load_expected
    load_received = int(load_latency["samples"] or 0)
    idle_latency_valid = (
        int(idle_latency["samples"]) >= idle_expected
        and
        idle_transmitted >= idle_expected
        and idle_received * 100 >= idle_transmitted * 95
        and idle_latency["mean_ms"] is not None
        and idle_latency["p95_ms"] is not None
        and idle_latency["max_ms"] is not None
    )
    load_latency_valid = (
        load_expected > 0
        and load_received * 100 >= load_expected * 95
        and load_latency["mean_ms"] is not None
        and load_latency["p95_ms"] is not None
        and load_latency["max_ms"] is not None
    )
    throughput_valid = math.isfinite(throughput) and throughput > 0
    udp_metrics = (
        iperf_udp_metrics(result_dir / case["iperf_json"])
        if case["protocol"] == "udp"
        else {
            "sent_packets": None,
            "received_packets": None,
            "lost_packets": None,
            "loss_percent": None,
            "jitter_ms": None,
        }
    )
    udp_loss_valid = case["protocol"] != "udp" or (
        udp_metrics["loss_percent"] is not None
        and float(udp_metrics["loss_percent"]) <= 1.0
    )
    if is_underlay:
        compact_l3_packets = 0
        full_ethernet_packets = 0
        mode_valid = True
    else:
        compact_l3_packets = sum(
            max(
                0,
                prometheus_metric(result_dir / case[after], "hybrid_compact_l3_packets_tx")
                - prometheus_metric(result_dir / case[before], "hybrid_compact_l3_packets_tx"),
            )
            for before, after in (
                ("mode_stats_a_before", "mode_stats_a_after"),
                ("mode_stats_b_before", "mode_stats_b_after"),
            )
        )
        full_ethernet_packets = sum(
            max(
                0,
                prometheus_metric(result_dir / case[after], "hybrid_full_ethernet_packets_tx")
                - prometheus_metric(result_dir / case[before], "hybrid_full_ethernet_packets_tx"),
            )
            for before, after in (
                ("mode_stats_a_before", "mode_stats_a_after"),
                ("mode_stats_b_before", "mode_stats_b_after"),
            )
        )
        mode_valid = compact_l3_packets > 0 and full_ethernet_packets == 0
    relay_traffic_valid = case["scenario"] != "relay-compact-l3" or (
        int(relay["rx_packets"]) > 0
        and int(relay["tx_packets"]) > 0
        and int(relay["rx_bytes"]) > 0
        and int(relay["tx_bytes"]) > 0
    )
    route_valid = route_proof_valid(result_dir / case["route_proof"], case["scenario"])
    result = {
        "case_id": case["case_id"],
        "scenario": case["scenario"],
        "mode": case["mode"],
        "queue_count": int(case["queue_count"]),
        "repeat": int(case["repeat"]),
        "protocol": case["protocol"],
        "direction": case["direction"],
        "streams": int(case["streams"]),
        "offered_bps": finite(rate_to_bps(case["offered_rate"])),
        "window_start_ms": window_start_ms,
        "window_end_ms": window_end_ms,
        "wall_time_ms": int(case["wall_time_ms"]),
        "throughput_bps": finite(throughput),
        "throughput_valid": throughput_valid,
        "udp_sent_packets": udp_metrics["sent_packets"],
        "udp_received_packets": udp_metrics["received_packets"],
        "udp_lost_packets": udp_metrics["lost_packets"],
        "udp_loss_percent": finite(udp_metrics["loss_percent"]),
        "udp_jitter_ms": finite(udp_metrics["jitter_ms"]),
        "udp_loss_valid": udp_loss_valid,
        "compact_l3_packets": compact_l3_packets,
        "hybrid_full_ethernet_packets": full_ethernet_packets,
        "mode_valid": mode_valid,
        "relay_traffic_valid": relay_traffic_valid,
        "route_valid": route_valid,
        "total_aligned_samples": combined_resources["aligned_samples"],
        "total_peak_rss_kib": combined_resources["peak_rss_kib"],
        "total_hwm_sum_kib": combined_resources["hwm_sum_kib"],
        "total_peak_rss_anon_kib": combined_resources["peak_rss_anon_kib"],
        "total_peak_rss_file_kib": combined_resources["peak_rss_file_kib"],
        "total_peak_rss_shmem_kib": combined_resources["peak_rss_shmem_kib"],
        "total_peak_pss_kib": combined_resources["peak_pss_kib"],
        "total_peak_private_clean_kib": combined_resources["peak_private_clean_kib"],
        "total_peak_private_dirty_kib": combined_resources["peak_private_dirty_kib"],
        "total_peak_private_kib": combined_resources["peak_private_total_kib"],
        "memory_ceiling_kib": memory_ceiling_kib,
        "memory_ceiling_status": memory_ceiling_status,
        "resource_valid": resource_valid,
        "idle_latency_samples": int(idle_latency["samples"]),
        "idle_latency_transmitted": idle_transmitted,
        "idle_latency_received": idle_received,
        "idle_latency_valid": idle_latency_valid,
        "idle_latency_mean_ms": finite(idle_latency["mean_ms"]),
        "idle_latency_p95_ms": finite(idle_latency["p95_ms"]),
        "idle_latency_max_ms": finite(idle_latency["max_ms"]),
        "load_latency_samples": int(load_latency["samples"]),
        "load_latency_transmitted": load_transmitted,
        "load_latency_received": load_received,
        "load_latency_valid": load_latency_valid,
        "load_latency_mean_ms": finite(load_latency["mean_ms"]),
        "load_latency_p95_ms": finite(load_latency["p95_ms"]),
        "load_latency_max_ms": finite(load_latency["max_ms"]),
        "iperf_json": case["iperf_json"],
        "idle_latency": case["idle_latency"],
        "load_latency": case["load_latency"],
        "resource_a": case["resource_a"],
        "resource_b": case["resource_b"],
        "resource_relay": case["resource_relay"],
        "route_proof": case["route_proof"],
    }
    for prefix, metrics in (
        ("endpoint_a", endpoint_a),
        ("endpoint_b", endpoint_b),
        ("relay", relay),
    ):
        result.update(
            {
                f"{prefix}_sampled": bool(metrics["sampled"]),
                f"{prefix}_complete": bool(metrics["complete"]),
                f"{prefix}_samples": int(metrics["samples"]),
                f"{prefix}_cpu_pct": finite(float(metrics["cpu_pct"])),
                f"{prefix}_peak_rss_kib": int(metrics["peak_rss_kib"]),
                f"{prefix}_process_lifetime_hwm_kib": int(
                    metrics["process_lifetime_hwm_kib"]
                ),
                f"{prefix}_peak_rss_anon_kib": int(metrics["peak_rss_anon_kib"]),
                f"{prefix}_peak_rss_file_kib": int(metrics["peak_rss_file_kib"]),
                f"{prefix}_peak_rss_shmem_kib": int(metrics["peak_rss_shmem_kib"]),
                f"{prefix}_peak_pss_kib": int(metrics["peak_pss_kib"]),
                f"{prefix}_peak_private_clean_kib": int(
                    metrics["peak_private_clean_kib"]
                ),
                f"{prefix}_peak_private_dirty_kib": int(
                    metrics["peak_private_dirty_kib"]
                ),
                f"{prefix}_peak_threads": int(metrics["peak_threads"]),
                f"{prefix}_rx_packets": int(metrics["rx_packets"]),
                f"{prefix}_tx_packets": int(metrics["tx_packets"]),
                f"{prefix}_rx_bytes": int(metrics["rx_bytes"]),
                f"{prefix}_tx_bytes": int(metrics["tx_bytes"]),
            }
        )
    result["case_valid"] = (
        resource_valid
        and idle_latency_valid
        and load_latency_valid
        and throughput_valid
        and udp_loss_valid
        and mode_valid
        and relay_traffic_valid
        and route_valid
        and memory_ceiling_status in ("pass", "not_applicable")
    )
    return result


FIELDS = [
    "case_id",
    "scenario",
    "mode",
    "queue_count",
    "repeat",
    "protocol",
    "direction",
    "streams",
    "offered_bps",
    "window_start_ms",
    "window_end_ms",
    "wall_time_ms",
    "throughput_bps",
    "throughput_valid",
    "udp_sent_packets",
    "udp_received_packets",
    "udp_lost_packets",
    "udp_loss_percent",
    "udp_jitter_ms",
    "udp_loss_valid",
    "compact_l3_packets",
    "hybrid_full_ethernet_packets",
    "mode_valid",
    "relay_traffic_valid",
    "route_valid",
    "total_aligned_samples",
    "total_peak_rss_kib",
    "total_hwm_sum_kib",
    "total_peak_rss_anon_kib",
    "total_peak_rss_file_kib",
    "total_peak_rss_shmem_kib",
    "total_peak_pss_kib",
    "total_peak_private_clean_kib",
    "total_peak_private_dirty_kib",
    "total_peak_private_kib",
    "memory_ceiling_kib",
    "memory_ceiling_status",
    "resource_valid",
    "case_valid",
    "idle_latency_samples",
    "idle_latency_transmitted",
    "idle_latency_received",
    "idle_latency_valid",
    "idle_latency_mean_ms",
    "idle_latency_p95_ms",
    "idle_latency_max_ms",
    "load_latency_samples",
    "load_latency_transmitted",
    "load_latency_received",
    "load_latency_valid",
    "load_latency_mean_ms",
    "load_latency_p95_ms",
    "load_latency_max_ms",
    "route_proof",
]

RESOURCE_FIELDS = [
    "sampled",
    "samples",
    "cpu_pct",
    "peak_rss_kib",
    "process_lifetime_hwm_kib",
    "peak_rss_anon_kib",
    "peak_rss_file_kib",
    "peak_rss_shmem_kib",
    "peak_pss_kib",
    "peak_private_clean_kib",
    "peak_private_dirty_kib",
    "peak_threads",
    "rx_packets",
    "tx_packets",
    "rx_bytes",
    "tx_bytes",
]

for resource_prefix in ("endpoint_a", "endpoint_b", "relay"):
    FIELDS.extend(f"{resource_prefix}_{field}" for field in RESOURCE_FIELDS)


def quartiles(values: list[float]) -> tuple[float, float, float]:
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0], ordered[0], ordered[0]
    first, _, third = statistics.quantiles(ordered, n=4, method="inclusive")
    return first, third, third - first


def aggregate_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = collections.defaultdict(list)
    for result in results:
        key = (
            result["scenario"],
            result["mode"],
            result["queue_count"],
            result["protocol"],
            result["direction"],
            result["streams"],
        )
        groups[key].append(result)

    summaries: list[dict[str, Any]] = []
    for key, group in sorted(groups.items()):
        throughputs = [float(result["throughput_bps"]) for result in group]
        first, third, spread = quartiles(throughputs)
        sampled_rss = [
            int(result[field])
            for result in group
            for field in (
                "endpoint_a_peak_rss_kib",
                "endpoint_b_peak_rss_kib",
                "relay_peak_rss_kib",
            )
            if int(result[field]) > 0
        ]
        sampled_hwm = [
            int(result[field])
            for result in group
            for field in (
                "endpoint_a_process_lifetime_hwm_kib",
                "endpoint_b_process_lifetime_hwm_kib",
                "relay_process_lifetime_hwm_kib",
            )
            if int(result[field]) > 0
        ]
        load_p95_values = [
            float(result["load_latency_p95_ms"])
            for result in group
            if result["load_latency_p95_ms"] is not None
        ]
        summaries.append(
            {
                "scenario": key[0],
                "mode": key[1],
                "queue_count": key[2],
                "protocol": key[3],
                "direction": key[4],
                "streams": key[5],
                "repeats": len(group),
                "throughput_median_bps": statistics.median(throughputs),
                "throughput_q1_bps": first,
                "throughput_q3_bps": third,
                "throughput_iqr_bps": spread,
                "load_latency_p95_median_ms": (
                    statistics.median(load_p95_values) if load_p95_values else None
                ),
                "peak_rss_max_kib": max(sampled_rss, default=0),
                "process_lifetime_hwm_max_kib": max(sampled_hwm, default=0),
                "topology_peak_rss_max_kib": max(
                    (int(result["total_peak_rss_kib"]) for result in group),
                    default=0,
                ),
                "topology_hwm_sum_max_kib": max(
                    (int(result["total_hwm_sum_kib"]) for result in group),
                    default=0,
                ),
                "topology_pss_max_kib": max(
                    (int(result["total_peak_pss_kib"]) for result in group),
                    default=0,
                ),
                "topology_private_max_kib": max(
                    (int(result["total_peak_private_kib"]) for result in group),
                    default=0,
                ),
                "all_cases_valid": all(bool(result["case_valid"]) for result in group),
                "memory_ceiling_status": (
                    "not_applicable"
                    if all(
                        result["memory_ceiling_status"] == "not_applicable"
                        for result in group
                    )
                    else "pass"
                    if all(result["memory_ceiling_status"] == "pass" for result in group)
                    else "fail"
                ),
            }
        )
    return summaries


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} RESULT_DIR MEMORY_CEILING_KIB", file=sys.stderr)
        return 2

    result_dir = Path(sys.argv[1])
    memory_ceiling_kib = int(sys.argv[2])
    cases = read_tsv(result_dir / "cases.tsv")
    results = [build_result(result_dir, case, memory_ceiling_kib) for case in cases]
    summaries = aggregate_results(results)

    with (result_dir / "results.tsv").open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=FIELDS, delimiter="\t", extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)

    summary_fields = list(summaries[0]) if summaries else []
    with (result_dir / "summary.tsv").open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=summary_fields, delimiter="\t")
        writer.writeheader()
        writer.writerows(summaries)

    (result_dir / "results.json").write_text(
        json.dumps({"cases": results, "summary": summaries}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(f"Parsed {len(results)} benchmark cases")
    print(f"Results: {result_dir / 'results.tsv'}")
    invalid = [result["case_id"] for result in results if not result["case_valid"]]
    memory_failures = [
        result["case_id"]
        for result in results
        if result["memory_ceiling_status"] == "fail"
    ]
    if invalid:
        print(
            f"Measurement validity failed for {len(invalid)} cases: {', '.join(invalid)}",
            file=sys.stderr,
        )
    if memory_failures:
        print(
            f"Memory ceiling failed for {len(memory_failures)} cases: "
            f"{', '.join(memory_failures)}",
            file=sys.stderr,
        )
    if invalid or memory_failures:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
