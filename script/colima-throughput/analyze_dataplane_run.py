#!/usr/bin/env python3
"""Summarize one LowTier throughput run from TSV, ping, and Prometheus artifacts."""

from __future__ import annotations

import argparse
import csv
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

METRIC_RE = re.compile(r"^([A-Za-z_:][A-Za-z0-9_:]*)(?:\{([^}]*)\})?\s+([-+0-9.eE]+)$")
LABEL_RE = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')
PING_LOSS_RE = re.compile(r"(\d+(?:\.\d+)?)% packet loss")
PING_RTT_RE = re.compile(
    r"rtt min/avg/max/mdev = ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+) ms"
)
CPU_FILE_RE = re.compile(
    r"auto-(forward|reverse)-(lowertier-throughput-[ab])-prometheus-(before|after)\.txt$"
)

DIRECT_NIC_PACKET_CAPACITY = 192
PRESSURE_PACKET_THRESHOLD = DIRECT_NIC_PACKET_CAPACITY // 4
PRESSURE_STALL_FRACTION_THRESHOLD = 0.01


@dataclass(frozen=True)
class PingSummary:
    loss_percent: float
    minimum_ms: float
    average_ms: float
    maximum_ms: float
    mdev_ms: float


MetricKey = tuple[str, tuple[tuple[str, str], ...]]


def parse_labels(raw: str | None) -> tuple[tuple[str, str], ...]:
    if not raw:
        return ()
    labels = []
    for match in LABEL_RE.finditer(raw):
        labels.append((match.group(1), bytes(match.group(2), "utf-8").decode("unicode_escape")))
    return tuple(sorted(labels))


def parse_prometheus(path: Path) -> dict[MetricKey, float]:
    metrics: dict[MetricKey, float] = {}
    for line in path.read_text(errors="replace").splitlines():
        if not line or line.startswith("#"):
            continue
        match = METRIC_RE.match(line)
        if match is None:
            continue
        metrics[(match.group(1), parse_labels(match.group(2)))] = float(match.group(3))
    return metrics


def label_value(key: MetricKey, label: str) -> str | None:
    return dict(key[1]).get(label)


def metric_value(metrics: dict[MetricKey, float], name: str, **labels: str) -> float:
    expected = tuple(sorted(labels.items()))
    return metrics.get((name, expected), 0.0)


def counter_delta(
    before: dict[MetricKey, float], after: dict[MetricKey, float], name: str, **labels: str
) -> float:
    return max(0.0, metric_value(after, name, **labels) - metric_value(before, name, **labels))


def parse_ping(path: Path) -> PingSummary | None:
    if not path.exists():
        return None
    text = path.read_text(errors="replace")
    loss = PING_LOSS_RE.search(text)
    rtt = PING_RTT_RE.search(text)
    if loss is None or rtt is None:
        return None
    return PingSummary(
        loss_percent=float(loss.group(1)),
        minimum_ms=float(rtt.group(1)),
        average_ms=float(rtt.group(2)),
        maximum_ms=float(rtt.group(3)),
        mdev_ms=float(rtt.group(4)),
    )


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as source:
        return list(csv.DictReader(source, delimiter="\t"))


def read_environment(path: Path) -> dict[str, str]:
    environment: dict[str, str] = {}
    for line in path.read_text(errors="replace").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            environment[key] = value
    return environment


def stage_summary(
    before: dict[MetricKey, float], after: dict[MetricKey, float]
) -> dict[str, dict[str, float]]:
    stages = sorted(
        {
            value
            for key in after
            if key[0] == "lowertier_dataplane_stage_samples_total"
            and (value := label_value(key, "stage")) is not None
        }
    )
    output: dict[str, dict[str, float]] = {}
    for stage in stages:
        labels = {"stage": stage}
        samples = counter_delta(
            before, after, "lowertier_dataplane_stage_samples_total", **labels
        )
        batches = counter_delta(
            before, after, "lowertier_dataplane_stage_sampled_batches_total", **labels
        )
        packets = counter_delta(
            before, after, "lowertier_dataplane_stage_sampled_packets_total", **labels
        )
        bytes_count = counter_delta(
            before, after, "lowertier_dataplane_stage_sampled_bytes_total", **labels
        )
        elapsed_ns = counter_delta(
            before, after, "lowertier_dataplane_stage_sampled_ns_total", **labels
        )
        output[stage] = {
            "samples": samples,
            "sampled_batches": batches,
            "sampled_packets": packets,
            "sampled_bytes": bytes_count,
            "sampled_ns": elapsed_ns,
            "ns_per_batch": elapsed_ns / batches if batches else 0.0,
            "ns_per_packet": elapsed_ns / packets if packets else 0.0,
            "packets_per_batch": packets / batches if batches else 0.0,
            "bytes_per_packet": bytes_count / packets if packets else 0.0,
            "maximum_ns": metric_value(
                after, "lowertier_dataplane_stage_sampled_ns_max", **labels
            ),
        }
    return output


def io_summary(
    before: dict[MetricKey, float], after: dict[MetricKey, float]
) -> dict[str, dict[str, float]]:
    operations = sorted(
        {
            value
            for key in after
            if key[0] == "lowertier_dataplane_io_syscalls_total"
            and (value := label_value(key, "operation")) is not None
        }
    )
    output: dict[str, dict[str, float]] = {}
    for operation in operations:
        labels = {"operation": operation}
        syscalls = counter_delta(
            before, after, "lowertier_dataplane_io_syscalls_total", **labels
        )
        packets = counter_delta(
            before, after, "lowertier_dataplane_io_packets_total", **labels
        )
        bytes_count = counter_delta(
            before, after, "lowertier_dataplane_io_bytes_total", **labels
        )
        output[operation] = {
            "syscalls": syscalls,
            "packets": packets,
            "bytes": bytes_count,
            "packets_per_syscall": packets / syscalls if syscalls else 0.0,
            "bytes_per_syscall": bytes_count / syscalls if syscalls else 0.0,
        }
    return output


def queue_summary(
    before: dict[MetricKey, float], after: dict[MetricKey, float], duration_seconds: float
) -> dict[str, dict[str, float | bool]]:
    queues = sorted(
        {
            (class_name, queue)
            for key in after
            if key[0] == "lowertier_dataplane_queue_occupancy_packets_max"
            and (class_name := label_value(key, "class")) is not None
            and (queue := label_value(key, "queue")) is not None
        }
    )
    output: dict[str, dict[str, float | bool]] = {}
    for class_name, queue in queues:
        labels = {"class": class_name, "queue": queue}
        stall_ns = counter_delta(
            before, after, "lowertier_dataplane_queue_stall_ns_total", **labels
        )
        stall_events = counter_delta(
            before, after, "lowertier_dataplane_queue_stall_events_total", **labels
        )
        before_max = metric_value(
            before, "lowertier_dataplane_queue_occupancy_packets_max", **labels
        )
        after_max = metric_value(
            after, "lowertier_dataplane_queue_occupancy_packets_max", **labels
        )
        current_packets = metric_value(
            after, "lowertier_dataplane_queue_occupancy_packets", **labels
        )
        stall_fraction = stall_ns / (duration_seconds * 1e9) if duration_seconds else 0.0
        pressure = class_name == "direct_nic" and (
            after_max >= PRESSURE_PACKET_THRESHOLD
            or stall_fraction >= PRESSURE_STALL_FRACTION_THRESHOLD
        )
        output[f"{class_name}:{queue}"] = {
            "current_packets": current_packets,
            "maximum_packets_before_probe": before_max,
            "maximum_packets_after_probe": after_max,
            "new_maximum_observed": after_max > before_max,
            "stall_events": stall_events,
            "stall_ns": stall_ns,
            "stall_fraction": stall_fraction,
            "pressure_triggered": pressure,
        }
    return output


def collect_snapshots(root: Path) -> dict[str, dict[str, dict[str, dict[MetricKey, float]]]]:
    snapshots: dict[str, dict[str, dict[str, dict[MetricKey, float]]]] = {}
    for path in (root / "cpu").glob("*-prometheus-*.txt"):
        match = CPU_FILE_RE.search(path.name)
        if match is None:
            continue
        direction, node, phase = match.groups()
        snapshots.setdefault(direction, {}).setdefault(node, {})[phase] = parse_prometheus(path)
    return snapshots


def analyze(root: Path) -> dict[str, object]:
    environment = read_environment(root / "environment.txt")
    duration = float(environment.get("duration", "8") or 8)
    throughput = read_tsv(root / "throughput.tsv")
    cpu = read_tsv(root / "cpu-cores-per-gbit.tsv")
    snapshots = collect_snapshots(root)
    unloaded = parse_ping(root / "latency" / "auto-unloaded.txt")
    directions: dict[str, object] = {}

    for direction, nodes in sorted(snapshots.items()):
        node_summaries: dict[str, object] = {}
        destination = None
        destination_tun_write = -1.0
        for node, phases in sorted(nodes.items()):
            before = phases.get("before", {})
            after = phases.get("after", {})
            tun_write = counter_delta(
                before,
                after,
                "lowertier_dataplane_io_bytes_total",
                operation="tun_write",
            )
            if tun_write > destination_tun_write:
                destination_tun_write = tun_write
                destination = node
            node_summaries[node] = {
                "stages": stage_summary(before, after),
                "io": io_summary(before, after),
                "queues": queue_summary(before, after, duration),
            }

        loaded = parse_ping(root / "latency" / f"auto-{direction}-loaded.txt")
        destination_summary = node_summaries.get(destination or "", {})
        destination_queues = destination_summary.get("queues", {}) if isinstance(destination_summary, dict) else {}
        pressure_triggered = any(
            bool(summary.get("pressure_triggered"))
            for summary in destination_queues.values()
            if isinstance(summary, dict)
        )
        cpu_rows = [row for row in cpu if row.get("direction") == direction]
        directions[direction] = {
            "destination_node": destination,
            "loaded_ping": asdict(loaded) if loaded else None,
            "cpu": cpu_rows,
            "pressure_triggered": pressure_triggered,
            "nodes": node_summaries,
        }

    return {
        "root": str(root),
        "environment": environment,
        "throughput": throughput,
        "unloaded_ping": asdict(unloaded) if unloaded else None,
        "directions": directions,
        "pressure_policy": {
            "direct_nic_capacity_packets": DIRECT_NIC_PACKET_CAPACITY,
            "packet_threshold": PRESSURE_PACKET_THRESHOLD,
            "stall_fraction_threshold": PRESSURE_STALL_FRACTION_THRESHOLD,
            "receiver_pacing_required": any(
                bool(summary.get("pressure_triggered"))
                for summary in directions.values()
                if isinstance(summary, dict)
            ),
        },
    }


def render_markdown(report: dict[str, object]) -> str:
    lines = ["# Dataplane run analysis", ""]
    unloaded = report.get("unloaded_ping")
    if isinstance(unloaded, dict):
        lines.append(
            f"Unloaded RTT: {unloaded['average_ms']:.3f} ms average, "
            f"{unloaded['loss_percent']:.3f}% observed loss."
        )
        lines.append("")
    lines.extend(
        [
            "| Direction | Destination | Received Gbit/s | Loaded RTT avg ms | Loaded loss % | Pressure |",
            "|---|---|---:|---:|---:|---|",
        ]
    )
    cpu_rows = report.get("directions", {})
    if isinstance(cpu_rows, dict):
        for direction, summary in sorted(cpu_rows.items()):
            if not isinstance(summary, dict):
                continue
            cpu = summary.get("cpu", [])
            received = max(
                (float(row.get("received_bps", 0.0)) for row in cpu if isinstance(row, dict)),
                default=0.0,
            )
            loaded = summary.get("loaded_ping") or {}
            lines.append(
                f"| {direction} | {summary.get('destination_node')} | {received / 1e9:.6f} | "
                f"{float(loaded.get('average_ms', 0.0)):.3f} | "
                f"{float(loaded.get('loss_percent', 0.0)):.3f} | "
                f"{summary.get('pressure_triggered')} |"
            )
    lines.append("")
    policy = report.get("pressure_policy", {})
    if isinstance(policy, dict):
        lines.append(
            f"Receiver pacing required: `{str(policy.get('receiver_pacing_required')).lower()}`. "
            f"Trigger: direct-NIC maximum occupancy >= {policy.get('packet_threshold')} packets "
            f"or stall fraction >= {float(policy.get('stall_fraction_threshold', 0.0)):.3%}."
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run", type=Path)
    args = parser.parse_args()
    report = analyze(args.run)
    (args.run / "analysis.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    (args.run / "analysis.md").write_text(render_markdown(report))
    print(json.dumps(report["pressure_policy"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
