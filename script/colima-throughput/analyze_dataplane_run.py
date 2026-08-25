#!/usr/bin/env python3
"""Summarize one LowTier throughput run from TSV, ping, and Prometheus artifacts."""

from __future__ import annotations

import argparse
import csv
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict

from prometheus_metrics import MetricKey, read_prometheus_metrics


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

MetricSnapshot = dict[MetricKey, float]
SnapshotTree = dict[str, dict[str, dict[str, MetricSnapshot]]]


class PingReport(TypedDict):
    loss_percent: float
    minimum_ms: float
    average_ms: float
    maximum_ms: float
    mdev_ms: float


class QueueReport(TypedDict):
    current_packets: float
    maximum_packets_before_probe: float
    maximum_packets_after_probe: float
    new_maximum_observed: bool
    stall_events: float
    stall_ns: float
    stall_fraction: float
    pressure_triggered: bool


class NodeReport(TypedDict):
    stages: dict[str, dict[str, float]]
    io: dict[str, dict[str, float]]
    queues: dict[str, QueueReport]


class DirectionReport(TypedDict):
    destination_node: str | None
    loaded_ping: PingReport | None
    cpu: list[dict[str, str]]
    pressure_triggered: bool
    nodes: dict[str, NodeReport]


class PressurePolicyReport(TypedDict):
    direct_nic_capacity_packets: int
    packet_threshold: int
    stall_fraction_threshold: float
    receiver_pacing_required: bool


class AnalysisReport(TypedDict):
    root: str
    environment: dict[str, str]
    throughput: list[dict[str, str]]
    unloaded_ping: PingReport | None
    directions: dict[str, DirectionReport]
    pressure_policy: PressurePolicyReport


@dataclass(frozen=True)
class PingSummary:
    loss_percent: float
    minimum_ms: float
    average_ms: float
    maximum_ms: float
    mdev_ms: float

    def to_report(self) -> PingReport:
        return {
            "loss_percent": self.loss_percent,
            "minimum_ms": self.minimum_ms,
            "average_ms": self.average_ms,
            "maximum_ms": self.maximum_ms,
            "mdev_ms": self.mdev_ms,
        }


def read_tsv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as source:
        return [
            {key: value or "" for key, value in row.items() if key is not None}
            for row in csv.DictReader(source, delimiter="\t")
        ]


def label_value(key: MetricKey, label: str) -> str | None:
    return dict(key[1]).get(label)


def metric_value(metrics: MetricSnapshot, name: str, **labels: str) -> float:
    expected = tuple(sorted(labels.items()))
    return metrics.get((name, expected), 0.0)


def counter_delta(
    before: MetricSnapshot,
    after: MetricSnapshot,
    name: str,
    **labels: str,
) -> float:
    return max(
        0.0,
        metric_value(after, name, **labels) - metric_value(before, name, **labels),
    )


def read_ping_summary(path: Path) -> PingSummary | None:
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


def read_environment(path: Path) -> dict[str, str]:
    environment: dict[str, str] = {}
    for line in path.read_text(errors="replace").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            environment[key] = value
    return environment


def stage_summary(
    before: MetricSnapshot, after: MetricSnapshot
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
    before: MetricSnapshot, after: MetricSnapshot
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
    before: MetricSnapshot, after: MetricSnapshot, duration_seconds: float
) -> dict[str, QueueReport]:
    queues = sorted(
        {
            (class_name, queue)
            for key in after
            if key[0] == "lowertier_dataplane_queue_occupancy_packets_max"
            and (class_name := label_value(key, "class")) is not None
            and (queue := label_value(key, "queue")) is not None
        }
    )
    output: dict[str, QueueReport] = {}
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
        stall_fraction = (
            stall_ns / (duration_seconds * 1e9) if duration_seconds else 0.0
        )
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


def collect_snapshots(root: Path) -> SnapshotTree:
    snapshots: SnapshotTree = {}
    for path in (root / "cpu").glob("*-prometheus-*.txt"):
        match = CPU_FILE_RE.search(path.name)
        if match is None:
            continue
        direction, node, phase = match.groups()
        snapshots.setdefault(direction, {}).setdefault(node, {})[phase] = (
            read_prometheus_metrics(path)
        )
    return snapshots


def analyze(root: Path) -> AnalysisReport:
    environment = read_environment(root / "environment.txt")
    duration = float(environment.get("duration", "8") or 8)
    throughput = read_tsv_rows(root / "throughput.tsv")
    cpu = read_tsv_rows(root / "cpu-cores-per-gbit.tsv")
    snapshots = collect_snapshots(root)
    unloaded = read_ping_summary(root / "latency" / "auto-unloaded.txt")
    directions: dict[str, DirectionReport] = {}

    for direction, nodes in sorted(snapshots.items()):
        node_summaries: dict[str, NodeReport] = {}
        destination: str | None = None
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

        loaded = read_ping_summary(root / "latency" / f"auto-{direction}-loaded.txt")
        destination_summary = node_summaries.get(destination or "")
        destination_queues = (
            destination_summary["queues"] if destination_summary is not None else {}
        )
        pressure_triggered = any(
            summary["pressure_triggered"] for summary in destination_queues.values()
        )
        cpu_rows = [row for row in cpu if row.get("direction") == direction]
        directions[direction] = {
            "destination_node": destination,
            "loaded_ping": loaded.to_report() if loaded else None,
            "cpu": cpu_rows,
            "pressure_triggered": pressure_triggered,
            "nodes": node_summaries,
        }

    pressure_policy: PressurePolicyReport = {
        "direct_nic_capacity_packets": DIRECT_NIC_PACKET_CAPACITY,
        "packet_threshold": PRESSURE_PACKET_THRESHOLD,
        "stall_fraction_threshold": PRESSURE_STALL_FRACTION_THRESHOLD,
        "receiver_pacing_required": any(
            summary["pressure_triggered"] for summary in directions.values()
        ),
    }
    return {
        "root": str(root),
        "environment": environment,
        "throughput": throughput,
        "unloaded_ping": unloaded.to_report() if unloaded else None,
        "directions": directions,
        "pressure_policy": pressure_policy,
    }


def render_markdown(report: AnalysisReport) -> str:
    lines = ["# Dataplane run analysis", ""]
    unloaded = report["unloaded_ping"]
    if unloaded is not None:
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
    for direction, summary in sorted(report["directions"].items()):
        received = max(
            (float(row.get("received_bps", "0") or "0") for row in summary["cpu"]),
            default=0.0,
        )
        loaded = summary["loaded_ping"]
        loaded_average = loaded["average_ms"] if loaded is not None else 0.0
        loaded_loss = loaded["loss_percent"] if loaded is not None else 0.0
        lines.append(
            f"| {direction} | {summary['destination_node']} | {received / 1e9:.6f} | "
            f"{loaded_average:.3f} | {loaded_loss:.3f} | "
            f"{summary['pressure_triggered']} |"
        )
    lines.append("")
    policy = report["pressure_policy"]
    lines.append(
        f"Receiver pacing required: `{str(policy['receiver_pacing_required']).lower()}`. "
        f"Trigger: direct-NIC maximum occupancy >= {policy['packet_threshold']} packets "
        f"or stall fraction >= {policy['stall_fraction_threshold']:.3%}."
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run", type=Path)
    args = parser.parse_args()
    report = analyze(args.run)
    (args.run / "analysis.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (args.run / "analysis.md").write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps(report["pressure_policy"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
