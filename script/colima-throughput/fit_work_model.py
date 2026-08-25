#!/usr/bin/env python3
"""Fit u(L,B) = beta0 + beta1*L + beta2/B from LowTier sweep results."""

from __future__ import annotations

import argparse
import csv
import json
import math
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path

from prometheus_metrics import MetricKey, read_prometheus_metrics


@dataclass
class WorkSample:
    case: str
    role: str
    node: str
    direction: str
    flows: int
    configured_batch_cap: int
    effective_batch: float
    inner_packet_bytes: int
    udp_payload_bytes: int
    received_bps: float
    packet_rate: float
    average_cpu_percent: float
    cpu_seconds_per_packet: float
    stage: str
    stage_sampled_packets: float
    stage_sampled_batches: float
    stage_sampled_ns: float
    stage_ns_per_packet: float
    quic_io_packets: float
    quic_io_syscalls: float
    quic_packets_per_syscall: float
    tun_io_packets: float
    tun_io_syscalls: float
    tun_packets_per_syscall: float
    direct_nic_stall_events: float
    direct_nic_stall_ns: float
    tun_stall_events: float
    tun_stall_ns: float


@dataclass
class WorkModelFit:
    name: str
    sample_count: int
    beta0_seconds_per_packet: float
    beta1_seconds_per_byte: float
    beta2_seconds_per_packet_batch_term: float
    beta0_ns_per_packet: float
    beta1_ns_per_byte: float
    beta2_ns_per_packet_batch_term: float
    r_squared: float
    rmse_seconds_per_packet: float
    reference_inner_packet_bytes: int
    reference_batch: float
    reference_packet_ns: float
    reference_byte_ns: float
    reference_batch_ns: float
    reference_total_ns: float


def sum_metric(
    metrics: Mapping[MetricKey, float],
    name: str,
    labels: Mapping[str, str] | None = None,
) -> float:
    wanted = labels or {}
    total = 0.0
    for (metric_name, metric_labels), value in metrics.items():
        if metric_name != name:
            continue
        available = dict(metric_labels)
        if all(available.get(key) == expected for key, expected in wanted.items()):
            total += value
    return total


def counter_delta(
    before: Mapping[MetricKey, float],
    after: Mapping[MetricKey, float],
    name: str,
    labels: Mapping[str, str] | None = None,
) -> float:
    return max(
        0.0,
        sum_metric(after, name, labels) - sum_metric(before, name, labels),
    )


def safe_ratio(numerator: float, denominator: float, fallback: float = 0.0) -> float:
    return numerator / denominator if denominator > 0.0 else fallback


def load_samples(result_root: Path) -> list[WorkSample]:
    samples: list[WorkSample] = []
    for case_path in sorted(result_root.glob("*/case.json")):
        case_dir = case_path.parent
        if not (case_dir / "complete.json").exists():
            continue
        case = json.loads(case_path.read_text(encoding="utf-8"))
        model_path = case_dir / "work-model.tsv"
        if not model_path.exists():
            continue
        with model_path.open(newline="", encoding="utf-8") as source:
            rows = list(csv.DictReader(source, delimiter="\t"))
        for row in rows:
            if row.get("protocol") != "udp":
                continue
            node = row["node"]
            role = "sender" if node == case["node_a"] else "receiver"
            stage = "quic_send" if role == "sender" else "tun_schedule"
            prefix = f"{row['mode']}-{row['direction']}-{node}-prometheus"
            before = read_prometheus_metrics(case_dir / "cpu" / f"{prefix}-before.txt")
            after = read_prometheus_metrics(case_dir / "cpu" / f"{prefix}-after.txt")

            stage_labels = {"stage": stage}
            stage_packets = counter_delta(
                before,
                after,
                "lowertier_dataplane_stage_sampled_packets_total",
                stage_labels,
            )
            stage_batches = counter_delta(
                before,
                after,
                "lowertier_dataplane_stage_sampled_batches_total",
                stage_labels,
            )
            stage_ns = counter_delta(
                before,
                after,
                "lowertier_dataplane_stage_sampled_ns_total",
                stage_labels,
            )
            effective_batch = safe_ratio(
                stage_packets,
                stage_batches,
                float(case["configured_batch_cap"]),
            )
            effective_batch = max(1.0, effective_batch)

            received_bps = float(row["received_bps"])
            udp_payload_bytes = int(row["udp_payload_bytes"])
            packet_rate = safe_ratio(received_bps, 8.0 * float(udp_payload_bytes))
            average_cpu_percent = float(row["average_cpu_percent"])
            cpu_seconds_per_packet = safe_ratio(
                average_cpu_percent / 100.0, packet_rate
            )

            quic_operation = "quic_udp_send" if role == "sender" else "quic_udp_receive"
            quic_labels = {"operation": quic_operation}
            quic_packets = counter_delta(
                before,
                after,
                "lowertier_dataplane_io_packets_total",
                quic_labels,
            )
            quic_syscalls = counter_delta(
                before,
                after,
                "lowertier_dataplane_io_syscalls_total",
                quic_labels,
            )
            tun_labels = {"operation": "tun_write"}
            tun_packets = counter_delta(
                before,
                after,
                "lowertier_dataplane_io_packets_total",
                tun_labels,
            )
            tun_syscalls = counter_delta(
                before,
                after,
                "lowertier_dataplane_io_syscalls_total",
                tun_labels,
            )
            direct_labels = {"class": "direct_nic", "queue": "0"}
            tun_queue_labels = {"class": "tun"}

            if (
                received_bps <= 0.0
                or packet_rate <= 0.0
                or cpu_seconds_per_packet <= 0.0
            ):
                continue
            samples.append(
                WorkSample(
                    case=case["case"],
                    role=role,
                    node=node,
                    direction=row["direction"],
                    flows=int(row["flows"]),
                    configured_batch_cap=int(case["configured_batch_cap"]),
                    effective_batch=effective_batch,
                    inner_packet_bytes=int(row["inner_packet_bytes"]),
                    udp_payload_bytes=udp_payload_bytes,
                    received_bps=received_bps,
                    packet_rate=packet_rate,
                    average_cpu_percent=average_cpu_percent,
                    cpu_seconds_per_packet=cpu_seconds_per_packet,
                    stage=stage,
                    stage_sampled_packets=stage_packets,
                    stage_sampled_batches=stage_batches,
                    stage_sampled_ns=stage_ns,
                    stage_ns_per_packet=safe_ratio(stage_ns, stage_packets),
                    quic_io_packets=quic_packets,
                    quic_io_syscalls=quic_syscalls,
                    quic_packets_per_syscall=safe_ratio(quic_packets, quic_syscalls),
                    tun_io_packets=tun_packets,
                    tun_io_syscalls=tun_syscalls,
                    tun_packets_per_syscall=safe_ratio(tun_packets, tun_syscalls),
                    direct_nic_stall_events=counter_delta(
                        before,
                        after,
                        "lowertier_dataplane_queue_stall_events_total",
                        direct_labels,
                    ),
                    direct_nic_stall_ns=counter_delta(
                        before,
                        after,
                        "lowertier_dataplane_queue_stall_ns_total",
                        direct_labels,
                    ),
                    tun_stall_events=counter_delta(
                        before,
                        after,
                        "lowertier_dataplane_queue_stall_events_total",
                        tun_queue_labels,
                    ),
                    tun_stall_ns=counter_delta(
                        before,
                        after,
                        "lowertier_dataplane_queue_stall_ns_total",
                        tun_queue_labels,
                    ),
                )
            )
    return samples


def solve_linear(matrix: list[list[float]], vector: list[float]) -> list[float]:
    size = len(vector)
    if size == 0 or len(matrix) != size or any(len(row) != size for row in matrix):
        raise ValueError("the linear system must be square and nonempty")
    augmented = [[*row, value] for row, value in zip(matrix, vector, strict=True)]
    for column in range(size):
        pivot = max(range(column, size), key=lambda row: abs(augmented[row][column]))
        if abs(augmented[pivot][column]) < 1e-30:
            raise ValueError("the work-model design matrix is singular")
        augmented[column], augmented[pivot] = augmented[pivot], augmented[column]
        scale = augmented[column][column]
        augmented[column] = [value / scale for value in augmented[column]]
        for row in range(size):
            if row == column:
                continue
            factor = augmented[row][column]
            augmented[row] = [
                current - factor * pivot_value
                for current, pivot_value in zip(
                    augmented[row], augmented[column], strict=True
                )
            ]
    return [augmented[row][size] for row in range(size)]


def nonnegative_least_squares(
    x_rows: list[list[float]], observations: list[float]
) -> list[float]:
    """Solve the exact three-coefficient NNLS problem by active-face enumeration."""
    if not x_rows or any(len(row) != 3 for row in x_rows):
        raise ValueError("the work-model design matrix must have three columns")
    if len(x_rows) != len(observations):
        raise ValueError("the design matrix and observation vector differ in length")

    best_beta = [0.0, 0.0, 0.0]
    best_error = sum(value * value for value in observations)
    tolerance = 1e-18
    for mask in range(1, 1 << 3):
        active = [index for index in range(3) if mask & (1 << index)]
        normal = [[0.0 for _ in active] for _ in active]
        rhs = [0.0 for _ in active]
        for row, observed in zip(x_rows, observations, strict=True):
            for i, column_i in enumerate(active):
                rhs[i] += row[column_i] * observed
                for j, column_j in enumerate(active):
                    normal[i][j] += row[column_i] * row[column_j]
        try:
            active_beta = solve_linear(normal, rhs)
        except ValueError:
            continue
        if any(value < -tolerance for value in active_beta):
            continue
        beta = [0.0, 0.0, 0.0]
        for column, value in zip(active, active_beta, strict=True):
            beta[column] = max(0.0, value)
        error = 0.0
        for row, observed in zip(x_rows, observations, strict=True):
            predicted = sum(
                coefficient * value
                for coefficient, value in zip(beta, row, strict=True)
            )
            error += (observed - predicted) ** 2
        if error < best_error:
            best_error = error
            best_beta = beta
    return best_beta


def fit_rows(name: str, rows: Iterable[tuple[float, float, float]]) -> WorkModelFit:
    points = list(rows)
    if len(points) < 4:
        raise ValueError(f"{name}: at least four samples are required")
    x_rows = [[1.0, length, 1.0 / batch] for length, batch, _ in points]
    y = [value for _, _, value in points]
    beta0, beta1, beta2 = nonnegative_least_squares(x_rows, y)
    predictions = [
        beta0 + beta1 * length + beta2 / batch for length, batch, _ in points
    ]
    mean = sum(y) / len(y)
    residual_sum = sum(
        (observed - predicted) ** 2
        for observed, predicted in zip(y, predictions, strict=True)
    )
    total_sum = sum((observed - mean) ** 2 for observed in y)
    r_squared = 1.0 - residual_sum / total_sum if total_sum > 0.0 else 1.0
    rmse = math.sqrt(residual_sum / len(y))
    reference_length = 1360
    reference_batch = 64.0
    packet_term = beta0 * 1e9
    byte_term = beta1 * reference_length * 1e9
    batch_term = beta2 / reference_batch * 1e9
    return WorkModelFit(
        name=name,
        sample_count=len(points),
        beta0_seconds_per_packet=beta0,
        beta1_seconds_per_byte=beta1,
        beta2_seconds_per_packet_batch_term=beta2,
        beta0_ns_per_packet=beta0 * 1e9,
        beta1_ns_per_byte=beta1 * 1e9,
        beta2_ns_per_packet_batch_term=beta2 * 1e9,
        r_squared=r_squared,
        rmse_seconds_per_packet=rmse,
        reference_inner_packet_bytes=reference_length,
        reference_batch=reference_batch,
        reference_packet_ns=packet_term,
        reference_byte_ns=byte_term,
        reference_batch_ns=batch_term,
        reference_total_ns=packet_term + byte_term + batch_term,
    )


def role_fit(
    samples: Iterable[WorkSample], role: str, flows: int | None = None
) -> WorkModelFit:
    selected = [
        sample
        for sample in samples
        if sample.role == role and (flows is None or sample.flows == flows)
    ]
    suffix = "all" if flows is None else f"flows_{flows}"
    return fit_rows(
        f"{role}_{suffix}",
        (
            (
                float(sample.inner_packet_bytes),
                sample.effective_batch,
                sample.cpu_seconds_per_packet,
            )
            for sample in selected
        ),
    )


def combined_samples(
    samples: Iterable[WorkSample],
) -> list[tuple[float, float, float, int]]:
    grouped: dict[str, list[WorkSample]] = {}
    for sample in samples:
        grouped.setdefault(sample.case, []).append(sample)
    combined: list[tuple[float, float, float, int]] = []
    for rows in grouped.values():
        roles = {row.role for row in rows}
        if roles != {"sender", "receiver"}:
            continue
        first = rows[0]
        combined.append(
            (
                float(first.inner_packet_bytes),
                float(first.configured_batch_cap),
                sum(row.cpu_seconds_per_packet for row in rows),
                first.flows,
            )
        )
    return combined


def write_samples(path: Path, samples: list[WorkSample]) -> None:
    fields = list(asdict(samples[0]).keys())
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=fields, delimiter="\t")
        writer.writeheader()
        for sample in samples:
            writer.writerow(asdict(sample))


def write_summary(path: Path, fits: list[WorkModelFit], sample_count: int) -> None:
    lines = [
        "# LowTier transfer-work model",
        "",
        f"Valid endpoint samples: {sample_count}",
        "",
        "The fitted model is `u(L,B) = beta0 + beta1*L + beta2/B`, where `u` is CPU seconds per packet and every coefficient is constrained to be non-negative.",
        "",
        "| Fit | n | beta0 ns/packet | beta1 ns/byte | beta2 ns | R² | RMSE ns/packet | reference total ns |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    lines.extend(
        f"| {fit.name} | {fit.sample_count} | "
        f"{fit.beta0_ns_per_packet:.3f} | {fit.beta1_ns_per_byte:.6f} | "
        f"{fit.beta2_ns_per_packet_batch_term:.3f} | {fit.r_squared:.4f} | "
        f"{fit.rmse_seconds_per_packet * 1e9:.3f} | "
        f"{fit.reference_total_ns:.3f} |"
        for fit in fits
    )
    lines.extend(
        [
            "",
            "Reference contributions use an inner packet length of 1360 bytes and batch 64.",
            "The exact three-variable NNLS solution is obtained by evaluating every active face of the non-negative orthant.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def self_test() -> None:
    beta = (1.2e-6, 0.42e-9, 0.75e-6)
    points: list[tuple[float, float, float]] = []
    for length in [64.0, 256.0, 1024.0, 1360.0]:
        for batch in [1.0, 4.0, 16.0, 64.0]:
            value = beta[0] + beta[1] * length + beta[2] / batch
            points.append((length, batch, value))
    fit = fit_rows("synthetic", points)
    observed = (
        fit.beta0_seconds_per_packet,
        fit.beta1_seconds_per_byte,
        fit.beta2_seconds_per_packet_batch_term,
    )
    for expected, actual in zip(beta, observed, strict=True):
        if not math.isclose(expected, actual, rel_tol=1e-9, abs_tol=1e-18):
            raise AssertionError((expected, actual))
    if fit.r_squared < 0.999999999:
        raise AssertionError(fit.r_squared)

    boundary_points = [
        (64.0, 1.0, 2.0e-6),
        (256.0, 1.0, 1.9e-6),
        (1024.0, 4.0, 1.5e-6),
        (1360.0, 64.0, 1.4e-6),
    ]
    boundary_fit = fit_rows("boundary", boundary_points)
    if (
        min(
            boundary_fit.beta0_seconds_per_packet,
            boundary_fit.beta1_seconds_per_byte,
            boundary_fit.beta2_seconds_per_packet_batch_term,
        )
        < 0.0
    ):
        raise AssertionError(boundary_fit)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("result_root", type=Path, nargs="?")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("fit_work_model self-test passed")
        return 0
    if args.result_root is None:
        parser.error("result_root is required unless --self-test is used")

    result_root = args.result_root.resolve()
    samples = load_samples(result_root)
    if not samples:
        raise SystemExit("no valid work-model samples found")
    write_samples(result_root / "samples.tsv", samples)

    fits: list[WorkModelFit] = []
    flows = sorted({sample.flows for sample in samples})
    for role in ["sender", "receiver"]:
        fits.append(role_fit(samples, role))
        for flow_count in flows:
            role_rows = [
                sample
                for sample in samples
                if sample.role == role and sample.flows == flow_count
            ]
            if len(role_rows) >= 4:
                fits.append(role_fit(samples, role, flow_count))

    combined = combined_samples(samples)
    fits.append(
        fit_rows(
            "combined_all",
            ((length, batch, value) for length, batch, value, _ in combined),
        )
    )
    for flow_count in flows:
        rows = [row for row in combined if row[3] == flow_count]
        if len(rows) >= 4:
            fits.append(
                fit_rows(
                    f"combined_flows_{flow_count}",
                    ((length, batch, value) for length, batch, value, _ in rows),
                )
            )

    (result_root / "fit.json").write_text(
        json.dumps([asdict(fit) for fit in fits], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_summary(result_root / "summary.md", fits, len(samples))
    print((result_root / "summary.md").read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
