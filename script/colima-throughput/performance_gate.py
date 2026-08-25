#!/usr/bin/env python3
"""Strict A/B throughput gate for normalized Colima benchmark results."""

from __future__ import annotations

import argparse
import csv
import math
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from statistics import median

THROUGHPUT_FILE = "throughput.tsv"
WORKLOAD_ERROR_FILE = "workload-errors.tsv"
ENVIRONMENT_FILE = "environment.txt"
SUBSTRATE_STATUS_FILE = "substrate-status.txt"
DEFAULT_REQUIRED_DIRECTIONS = ("forward", "reverse")
DEFAULT_REQUIRED_TCP_STREAMS = (1, 8)

THROUGHPUT_COLUMNS = {
    "mode",
    "direction",
    "run",
    "protocol",
    "streams",
    "offered_bps",
    "received_bps",
    "retransmits",
    "lost_percent",
}

# These describe the workload and substrate rather than the candidate feature.
# Candidate-specific runtime feature flags may differ intentionally, so they are
# excluded and must be documented with the comparison.
COMPARABLE_ENVIRONMENT_KEYS = (
    "docker_context",
    "raw_gate_bps",
    "modes",
    "udp_rates",
    "encryption_algorithm",
    "run_tcp",
    "run_udp",
    "run_cpu_probe",
    "cpu_protocol",
    "cpu_udp_rate",
    "cpu_udp_length",
    "directions",
    "run_raw_gate",
    "underlay_protocol",
    "netem_delay",
    "netem_jitter",
    "netem_loss",
    "netem_loss_correlation",
    "netem_limit",
)


class GateInputError(RuntimeError):
    """The two result sets do not form a valid comparison."""


@dataclass(frozen=True, order=True)
class WorkloadKey:
    mode: str
    direction: str
    protocol: str
    streams: int
    offered_bps: str

    def label(self) -> str:
        rate = "" if self.offered_bps == "0" else f", offered={self.offered_bps} bps"
        return f"{self.mode}/{self.direction}/{self.protocol}/p{self.streams}{rate}"


@dataclass(frozen=True)
class Sample:
    run: int
    received_bps: float
    retransmits: float
    lost_percent: float


@dataclass(frozen=True)
class Comparison:
    key: WorkloadKey
    baseline_median_bps: float
    candidate_median_bps: float
    median_gain_percent: float
    minimum_paired_gain_percent: float
    baseline_retransmit_density: float
    candidate_retransmit_density: float
    baseline_loss_percent: float
    candidate_loss_percent: float
    failures: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.failures


def finite_float(raw: str, *, field: str, path: Path, line: int) -> float:
    try:
        value = float(raw)
    except ValueError as exc:
        raise GateInputError(f"{path}:{line}: {field} is not numeric: {raw!r}") from exc
    if not math.isfinite(value):
        raise GateInputError(f"{path}:{line}: {field} is not finite: {raw!r}")
    return value


def positive_int(raw: str, *, field: str, path: Path, line: int) -> int:
    value = finite_float(raw, field=field, path=path, line=line)
    integer = int(value)
    if value != integer or integer <= 0:
        raise GateInputError(f"{path}:{line}: {field} must be a positive integer")
    return integer


def canonical_number(raw: str, *, field: str, path: Path, line: int) -> str:
    value = finite_float(raw, field=field, path=path, line=line)
    if value < 0:
        raise GateInputError(f"{path}:{line}: {field} must be nonnegative")
    return format(value, ".17g")


def read_tsv_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    if not path.is_file():
        raise GateInputError(f"required result file is missing: {path}")
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        if reader.fieldnames is None:
            raise GateInputError(f"result file has no header: {path}")
        rows = [
            {
                key: (value or "").strip()
                for key, value in row.items()
                if key is not None
            }
            for row in reader
        ]
        return [name.strip() for name in reader.fieldnames], rows


def load_throughput(
    result_dir: Path, protocols: frozenset[str]
) -> dict[WorkloadKey, dict[int, Sample]]:
    path = result_dir / THROUGHPUT_FILE
    fieldnames, rows = read_tsv_rows(path)
    missing = THROUGHPUT_COLUMNS.difference(fieldnames)
    if missing:
        raise GateInputError(
            f"{path}: missing throughput columns: {', '.join(sorted(missing))}"
        )

    workloads: dict[WorkloadKey, dict[int, Sample]] = {}
    for line, row in enumerate(rows, start=2):
        protocol = row["protocol"].lower()
        if protocol not in protocols:
            continue
        mode = row["mode"]
        direction = row["direction"]
        if not mode or not direction:
            raise GateInputError(f"{path}:{line}: mode and direction are required")
        streams = positive_int(row["streams"], field="streams", path=path, line=line)
        run = positive_int(row["run"], field="run", path=path, line=line)
        offered_bps = canonical_number(
            row["offered_bps"], field="offered_bps", path=path, line=line
        )
        received_bps = finite_float(
            row["received_bps"], field="received_bps", path=path, line=line
        )
        if received_bps <= 0:
            raise GateInputError(f"{path}:{line}: received_bps must be positive")
        retransmits = finite_float(
            row["retransmits"], field="retransmits", path=path, line=line
        )
        lost_percent = finite_float(
            row["lost_percent"], field="lost_percent", path=path, line=line
        )
        if retransmits < 0 or lost_percent < 0:
            raise GateInputError(
                f"{path}:{line}: retransmits and lost_percent must be nonnegative"
            )

        key = WorkloadKey(mode, direction, protocol, streams, offered_bps)
        runs = workloads.setdefault(key, {})
        if run in runs:
            raise GateInputError(
                f"{path}:{line}: duplicate run {run} for {key.label()}"
            )
        runs[run] = Sample(run, received_bps, retransmits, lost_percent)

    if not workloads:
        selected = ", ".join(sorted(protocols))
        raise GateInputError(f"{path}: no selected protocol rows found ({selected})")
    return workloads


def merge_throughput(
    result_dirs: Sequence[Path], protocols: frozenset[str]
) -> dict[WorkloadKey, dict[int, Sample]]:
    merged: dict[WorkloadKey, dict[int, Sample]] = {}
    for result_dir in result_dirs:
        for key, runs in load_throughput(result_dir, protocols).items():
            destination = merged.setdefault(key, {})
            duplicate_runs = sorted(set(destination).intersection(runs))
            if duplicate_runs:
                raise GateInputError(
                    f"duplicate run IDs across result directories for {key.label()}: "
                    f"{duplicate_runs}"
                )
            destination.update(runs)
    return merged


def validate_full_tcp_matrix(
    workloads: dict[WorkloadKey, dict[int, Sample]],
) -> None:
    tcp_keys = {key for key in workloads if key.protocol == "tcp"}
    if not tcp_keys:
        return
    modes = sorted({key.mode for key in tcp_keys})
    missing: list[str] = []
    for mode in modes:
        for direction in DEFAULT_REQUIRED_DIRECTIONS:
            for streams in DEFAULT_REQUIRED_TCP_STREAMS:
                present = any(
                    key.mode == mode
                    and key.direction == direction
                    and key.streams == streams
                    for key in tcp_keys
                )
                if not present:
                    missing.append(f"{mode}/{direction}/tcp/p{streams}")
    if missing:
        raise GateInputError(
            "required TCP matrix is incomplete; missing: " + ", ".join(missing)
        )


def read_environment(result_dir: Path) -> dict[str, str]:
    path = result_dir / ENVIRONMENT_FILE
    if not path.is_file():
        raise GateInputError(f"required environment file is missing: {path}")
    values: dict[str, str] = {}
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        if not key:
            raise GateInputError(f"{path}:{line_number}: empty environment key")
        values[key] = value.strip()
    return values


def validate_environment(
    baseline_dir: Path,
    candidate_dir: Path,
    ignored_keys: frozenset[str],
) -> None:
    baseline = read_environment(baseline_dir)
    candidate = read_environment(candidate_dir)
    differences: list[str] = []
    for key in COMPARABLE_ENVIRONMENT_KEYS:
        if key in ignored_keys:
            continue
        baseline_value = baseline.get(key)
        candidate_value = candidate.get(key)
        if (
            baseline_value is None
            or candidate_value is None
            or baseline_value != candidate_value
        ):
            differences.append(
                f"{key}: baseline={baseline_value!r}, candidate={candidate_value!r}"
            )
    if differences:
        details = "\n  ".join(differences)
        raise GateInputError(f"benchmark environments differ:\n  {details}")


def validate_no_workload_errors(result_dir: Path) -> None:
    path = result_dir / WORKLOAD_ERROR_FILE
    _, rows = read_tsv_rows(path)
    populated = [row for row in rows if any(value for value in row.values())]
    if populated:
        raise GateInputError(
            f"{path}: contains {len(populated)} failed workload row(s)"
        )


def validate_substrate(
    baseline_dir: Path, candidate_dir: Path, allow_not_run: bool
) -> None:
    def read_status(result_dir: Path) -> str:
        path = result_dir / SUBSTRATE_STATUS_FILE
        if not path.is_file():
            raise GateInputError(f"required substrate status is missing: {path}")
        status = path.read_text(encoding="utf-8").strip()
        if not status:
            raise GateInputError(f"substrate status is empty: {path}")
        return status

    baseline = read_status(baseline_dir)
    candidate = read_status(candidate_dir)
    if baseline != candidate:
        raise GateInputError(
            f"substrate status differs: baseline={baseline!r}, candidate={candidate!r}"
        )
    allowed = {"valid"}
    if allow_not_run:
        allowed.add("not-run")
    if baseline not in allowed:
        raise GateInputError(
            f"substrate status {baseline!r} cannot authorize a performance result"
        )


def retransmit_density(sample: Sample) -> float:
    return sample.retransmits / sample.received_bps


def compare_workload(
    key: WorkloadKey,
    baseline_runs: dict[int, Sample],
    candidate_runs: dict[int, Sample],
    *,
    min_samples: int,
    min_gain_percent: float,
    max_retransmit_density_increase_percent: float,
    max_loss_increase_points: float,
) -> Comparison:
    baseline_ids = set(baseline_runs)
    candidate_ids = set(candidate_runs)
    if baseline_ids != candidate_ids:
        raise GateInputError(
            f"run IDs differ for {key.label()}: "
            f"baseline={sorted(baseline_ids)}, candidate={sorted(candidate_ids)}"
        )
    if len(baseline_ids) < min_samples:
        raise GateInputError(
            f"{key.label()}: {len(baseline_ids)} sample(s), minimum is {min_samples}"
        )

    ordered_runs = sorted(baseline_ids)
    baseline_samples = [baseline_runs[run] for run in ordered_runs]
    candidate_samples = [candidate_runs[run] for run in ordered_runs]
    baseline_median = median(sample.received_bps for sample in baseline_samples)
    candidate_median = median(sample.received_bps for sample in candidate_samples)
    median_gain = (candidate_median / baseline_median - 1.0) * 100.0
    paired_gains = [
        (candidate.received_bps / baseline.received_bps - 1.0) * 100.0
        for baseline, candidate in zip(baseline_samples, candidate_samples, strict=True)
    ]
    minimum_paired_gain = min(paired_gains)

    baseline_retransmit = median(
        retransmit_density(sample) for sample in baseline_samples
    )
    candidate_retransmit = median(
        retransmit_density(sample) for sample in candidate_samples
    )
    baseline_loss = median(sample.lost_percent for sample in baseline_samples)
    candidate_loss = median(sample.lost_percent for sample in candidate_samples)

    failures: list[str] = []
    if candidate_median <= baseline_median or median_gain < min_gain_percent:
        failures.append(
            f"median throughput gain {median_gain:.3f}% is below the required "
            f"+{min_gain_percent:.3f}%"
        )
    for run, gain in zip(ordered_runs, paired_gains, strict=True):
        if gain <= 0.0:
            failures.append(f"paired run {run} is slower by {-gain:.3f}%")

    if key.protocol == "tcp":
        if baseline_retransmit == 0.0:
            retransmit_increase = math.inf if candidate_retransmit > 0.0 else 0.0
        else:
            retransmit_increase = (
                candidate_retransmit / baseline_retransmit - 1.0
            ) * 100.0
        if retransmit_increase > max_retransmit_density_increase_percent:
            failures.append(
                "normalized retransmission density increased by "
                f"{retransmit_increase:.3f}%"
            )
    elif candidate_loss - baseline_loss > max_loss_increase_points:
        failures.append(
            f"median UDP loss increased by {candidate_loss - baseline_loss:.3f} "
            "percentage points"
        )

    return Comparison(
        key=key,
        baseline_median_bps=baseline_median,
        candidate_median_bps=candidate_median,
        median_gain_percent=median_gain,
        minimum_paired_gain_percent=minimum_paired_gain,
        baseline_retransmit_density=baseline_retransmit,
        candidate_retransmit_density=candidate_retransmit,
        baseline_loss_percent=baseline_loss,
        candidate_loss_percent=candidate_loss,
        failures=tuple(failures),
    )


def compare_results(
    baseline_dirs: Sequence[Path],
    candidate_dirs: Sequence[Path],
    *,
    protocols: frozenset[str],
    min_samples: int,
    min_gain_percent: float,
    max_retransmit_density_increase_percent: float,
    max_loss_increase_points: float,
    allow_substrate_not_run: bool,
    require_full_tcp_matrix: bool,
    ignored_environment_keys: frozenset[str],
) -> list[Comparison]:
    if not baseline_dirs or not candidate_dirs:
        raise GateInputError(
            "at least one baseline and candidate result directory is required"
        )
    if len(baseline_dirs) != len(candidate_dirs):
        raise GateInputError(
            "baseline and candidate result-directory counts differ: "
            f"{len(baseline_dirs)} != {len(candidate_dirs)}"
        )

    for baseline_dir, candidate_dir in zip(baseline_dirs, candidate_dirs, strict=True):
        validate_environment(baseline_dir, candidate_dir, ignored_environment_keys)
        validate_no_workload_errors(baseline_dir)
        validate_no_workload_errors(candidate_dir)
        validate_substrate(baseline_dir, candidate_dir, allow_substrate_not_run)

    baseline_reference = baseline_dirs[0]
    candidate_reference = candidate_dirs[0]
    for result_dir in baseline_dirs[1:]:
        validate_environment(baseline_reference, result_dir, ignored_environment_keys)
    for result_dir in candidate_dirs[1:]:
        validate_environment(candidate_reference, result_dir, ignored_environment_keys)

    baseline = merge_throughput(baseline_dirs, protocols)
    candidate = merge_throughput(candidate_dirs, protocols)
    if require_full_tcp_matrix:
        validate_full_tcp_matrix(baseline)
        validate_full_tcp_matrix(candidate)
    baseline_keys = set(baseline)
    candidate_keys = set(candidate)
    if baseline_keys != candidate_keys:
        missing = sorted(baseline_keys - candidate_keys)
        extra = sorted(candidate_keys - baseline_keys)
        details: list[str] = []
        if missing:
            details.append(
                "candidate is missing: " + ", ".join(key.label() for key in missing)
            )
        if extra:
            details.append(
                "candidate has unmatched: " + ", ".join(key.label() for key in extra)
            )
        raise GateInputError("workload sets differ; " + "; ".join(details))

    return [
        compare_workload(
            key,
            baseline[key],
            candidate[key],
            min_samples=min_samples,
            min_gain_percent=min_gain_percent,
            max_retransmit_density_increase_percent=(
                max_retransmit_density_increase_percent
            ),
            max_loss_increase_points=max_loss_increase_points,
        )
        for key in sorted(baseline_keys)
    ]


def nonnegative_argument(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be numeric") from exc
    if not math.isfinite(value) or value < 0:
        raise argparse.ArgumentTypeError("must be a finite nonnegative number")
    return value


def positive_integer_argument(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if value <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Reject a candidate unless every matched workload is faster and "
            "reliability is no worse than the baseline."
        )
    )
    parser.add_argument("baseline_result_dir", type=Path)
    parser.add_argument("candidate_result_dir", type=Path)
    parser.add_argument(
        "--baseline-extra-result-dir",
        type=Path,
        action="append",
        default=[],
        help="additional baseline result directory; pair by option order",
    )
    parser.add_argument(
        "--candidate-extra-result-dir",
        type=Path,
        action="append",
        default=[],
        help="additional candidate result directory; pair by option order",
    )
    parser.add_argument(
        "--protocol",
        dest="protocols",
        action="append",
        choices=("tcp", "udp"),
        help="protocol to compare; repeat for both (default: tcp)",
    )
    parser.add_argument(
        "--min-samples",
        type=positive_integer_argument,
        default=5,
        help="minimum matched runs per workload (default: 5)",
    )
    parser.add_argument(
        "--min-throughput-gain-percent",
        type=nonnegative_argument,
        default=2.0,
        help="required median gain for every workload (default: 2.0)",
    )
    parser.add_argument(
        "--max-retransmit-density-increase-percent",
        type=nonnegative_argument,
        default=0.0,
        help="maximum TCP retransmission-density increase (default: 0.0)",
    )
    parser.add_argument(
        "--max-loss-increase-points",
        type=nonnegative_argument,
        default=0.0,
        help="maximum UDP median loss increase in percentage points (default: 0.0)",
    )
    parser.add_argument(
        "--allow-substrate-not-run",
        action="store_true",
        help="allow matched 'not-run' substrate status for smoke comparisons",
    )
    parser.add_argument(
        "--allow-partial-matrix",
        action="store_true",
        help="allow a subset of forward/reverse p1/p8 TCP workloads for smoke tests",
    )
    parser.add_argument(
        "--ignore-environment-key",
        action="append",
        default=[],
        metavar="KEY",
        help="ignore one workload environment key; repeat as needed",
    )
    return parser


def print_comparisons(comparisons: Iterable[Comparison]) -> list[str]:
    all_failures: list[str] = []
    for comparison in comparisons:
        status = "PASS" if comparison.passed else "FAIL"
        print(
            f"{status} {comparison.key.label()}: "
            f"baseline={comparison.baseline_median_bps / 1e9:.3f} Gbit/s, "
            f"candidate={comparison.candidate_median_bps / 1e9:.3f} Gbit/s, "
            f"median_gain={comparison.median_gain_percent:+.3f}%, "
            f"minimum_pair={comparison.minimum_paired_gain_percent:+.3f}%"
        )
        for failure in comparison.failures:
            message = f"{comparison.key.label()}: {failure}"
            all_failures.append(message)
            print(f"  {message}", file=sys.stderr)
    return all_failures


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    protocols = frozenset(args.protocols or ("tcp",))
    try:
        comparisons = compare_results(
            (args.baseline_result_dir, *args.baseline_extra_result_dir),
            (args.candidate_result_dir, *args.candidate_extra_result_dir),
            protocols=protocols,
            min_samples=args.min_samples,
            min_gain_percent=args.min_throughput_gain_percent,
            max_retransmit_density_increase_percent=(
                args.max_retransmit_density_increase_percent
            ),
            max_loss_increase_points=args.max_loss_increase_points,
            allow_substrate_not_run=args.allow_substrate_not_run,
            require_full_tcp_matrix=not args.allow_partial_matrix,
            ignored_environment_keys=frozenset(args.ignore_environment_key),
        )
    except GateInputError as error:
        print(f"INVALID PERFORMANCE COMPARISON: {error}", file=sys.stderr)
        return 2

    failures = print_comparisons(comparisons)
    if failures:
        print(
            f"PERFORMANCE GATE FAILED: {len(failures)} regression condition(s)",
            file=sys.stderr,
        )
        return 1
    print(f"PERFORMANCE GATE PASSED: {len(comparisons)} workload(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
