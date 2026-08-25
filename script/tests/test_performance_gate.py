#!/usr/bin/env python3
"""Deterministic tests for the strict Colima performance gate."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from collections.abc import Iterable
from pathlib import Path

SCRIPT = (
    Path(__file__).resolve().parents[1] / "colima-throughput" / "performance_gate.py"
)

THROUGHPUT_HEADER = (
    "mode\tdirection\trun\tprotocol\tstreams\toffered_bps\t"
    "received_bps\tretransmits\tlost_percent\thost_cpu_percent\t"
    "remote_cpu_percent\n"
)
ERROR_HEADER = "mode\tdirection\trun\tprotocol\tstreams\toffered_bps\terror\n"

ENVIRONMENT = {
    "docker_context": "colima-easytier-bench",
    "raw_gate_bps": "12000000000",
    "modes": "routed",
    "udp_rates": "10000M",
    "encryption_algorithm": "chacha20-poly1305",
    "run_tcp": "1",
    "run_udp": "0",
    "run_cpu_probe": "0",
    "cpu_protocol": "tcp",
    "cpu_udp_rate": "10000M",
    "cpu_udp_length": "1352",
    "directions": "forward reverse",
    "run_raw_gate": "1",
    "underlay_protocol": "udp",
    "netem_delay": "",
    "netem_jitter": "0ms",
    "netem_loss": "0%",
    "netem_loss_correlation": "0%",
    "netem_limit": "250000",
}


def tcp_rows(
    direction: str,
    streams: int,
    throughputs: Iterable[float],
    retransmits: Iterable[float],
) -> list[str]:
    return [
        (
            f"routed\t{direction}\t{run}\ttcp\t{streams}\t0\t{throughput}\t"
            f"{retransmit}\t0\t0\t0\n"
        )
        for run, (throughput, retransmit) in enumerate(
            zip(throughputs, retransmits, strict=True), start=1
        )
    ]


def udp_rows(
    direction: str,
    offered_bps: float,
    throughputs: Iterable[float],
    losses: Iterable[float],
) -> list[str]:
    return [
        (
            f"routed\t{direction}\t{run}\tudp\t1\t{offered_bps}\t{throughput}\t"
            f"0\t{loss}\t0\t0\n"
        )
        for run, (throughput, loss) in enumerate(
            zip(throughputs, losses, strict=True), start=1
        )
    ]


def write_result(
    directory: Path,
    rows: Iterable[str],
    *,
    environment: dict[str, str] | None = None,
    status: str = "valid",
    errors: Iterable[str] = (),
) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "throughput.tsv").write_text(
        THROUGHPUT_HEADER + "".join(rows), encoding="utf-8"
    )
    (directory / "workload-errors.tsv").write_text(
        ERROR_HEADER + "".join(errors), encoding="utf-8"
    )
    values = ENVIRONMENT if environment is None else environment
    (directory / "environment.txt").write_text(
        "".join(f"{key}={value}\n" for key, value in values.items()),
        encoding="utf-8",
    )
    (directory / "substrate-status.txt").write_text(status + "\n", encoding="utf-8")


class PerformanceGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.baseline = root / "baseline"
        self.candidate = root / "candidate"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_gate(self, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(self.baseline),
                str(self.candidate),
                *extra,
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def write_passing_pair(self, *, status: str = "valid") -> None:
        baseline_rows = (
            tcp_rows("forward", 1, [1.00e9] * 5, [100.0] * 5)
            + tcp_rows("reverse", 1, [0.98e9] * 5, [105.0] * 5)
            + tcp_rows("forward", 8, [2.02e9] * 5, [175.0] * 5)
            + tcp_rows("reverse", 8, [2.00e9] * 5, [180.0] * 5)
        )
        candidate_rows = (
            tcp_rows("forward", 1, [1.05e9] * 5, [95.0] * 5)
            + tcp_rows("reverse", 1, [1.03e9] * 5, [100.0] * 5)
            + tcp_rows("forward", 8, [2.12e9] * 5, [165.0] * 5)
            + tcp_rows("reverse", 8, [2.10e9] * 5, [170.0] * 5)
        )
        write_result(self.baseline, baseline_rows, status=status)
        write_result(self.candidate, candidate_rows, status=status)

    def test_accepts_faster_candidate_for_every_workload(self) -> None:
        self.write_passing_pair()
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PERFORMANCE GATE PASSED", result.stdout)

    def test_rejects_equal_throughput(self) -> None:
        baseline_rows = tcp_rows("forward", 1, [1.00e9] * 5, [100.0] * 5)
        candidate_rows = tcp_rows("forward", 1, [1.00e9] * 5, [90.0] * 5)
        write_result(self.baseline, baseline_rows)
        write_result(self.candidate, candidate_rows)
        result = self.run_gate("--allow-partial-matrix")
        self.assertEqual(result.returncode, 1)
        self.assertIn("median throughput gain", result.stderr)

    def test_rejects_one_slower_paired_run(self) -> None:
        baseline_rows = tcp_rows("forward", 1, [1.00e9] * 5, [100.0] * 5)
        candidate_rows = tcp_rows(
            "forward",
            1,
            [1.05e9, 1.05e9, 0.99e9, 1.06e9, 1.05e9],
            [90.0] * 5,
        )
        write_result(self.baseline, baseline_rows)
        write_result(self.candidate, candidate_rows)
        result = self.run_gate("--allow-partial-matrix")
        self.assertEqual(result.returncode, 1)
        self.assertIn("paired run 3 is slower", result.stderr)

    def test_rejects_missing_workload(self) -> None:
        baseline_rows = (
            tcp_rows("forward", 1, [1.00e9] * 5, [100.0] * 5)
            + tcp_rows("reverse", 1, [0.98e9] * 5, [105.0] * 5)
            + tcp_rows("forward", 8, [2.02e9] * 5, [175.0] * 5)
            + tcp_rows("reverse", 8, [2.00e9] * 5, [180.0] * 5)
        )
        candidate_rows = (
            tcp_rows("forward", 1, [1.05e9] * 5, [90.0] * 5)
            + tcp_rows("reverse", 1, [1.03e9] * 5, [95.0] * 5)
            + tcp_rows("forward", 8, [2.12e9] * 5, [165.0] * 5)
        )
        write_result(self.baseline, baseline_rows)
        write_result(self.candidate, candidate_rows)
        result = self.run_gate()
        self.assertEqual(result.returncode, 2)
        self.assertIn("required TCP matrix is incomplete", result.stderr)

    def test_rejects_workload_error_rows(self) -> None:
        self.write_passing_pair()
        error = "routed\tforward\t1\ttcp\t1\t0\tconnection reset\n"
        write_result(
            self.candidate,
            tcp_rows("forward", 1, [1.05e9] * 5, [95.0] * 5)
            + tcp_rows("reverse", 8, [2.10e9] * 5, [170.0] * 5),
            errors=[error],
        )
        result = self.run_gate()
        self.assertEqual(result.returncode, 2)
        self.assertIn("failed workload row", result.stderr)

    def test_rejects_retransmission_density_increase(self) -> None:
        baseline_rows = tcp_rows("forward", 1, [1.00e9] * 5, [100.0] * 5)
        candidate_rows = tcp_rows("forward", 1, [1.05e9] * 5, [200.0] * 5)
        write_result(self.baseline, baseline_rows)
        write_result(self.candidate, candidate_rows)
        result = self.run_gate("--allow-partial-matrix")
        self.assertEqual(result.returncode, 1)
        self.assertIn("normalized retransmission density increased", result.stderr)

    def test_rejects_udp_loss_increase(self) -> None:
        baseline_environment = dict(ENVIRONMENT)
        baseline_environment["run_tcp"] = "0"
        baseline_environment["run_udp"] = "1"
        baseline_rows = udp_rows("forward", 10.0e9, [8.0e9] * 5, [0.1] * 5)
        candidate_rows = udp_rows("forward", 10.0e9, [8.4e9] * 5, [0.2] * 5)
        write_result(self.baseline, baseline_rows, environment=baseline_environment)
        write_result(self.candidate, candidate_rows, environment=baseline_environment)
        result = self.run_gate("--protocol", "udp")
        self.assertEqual(result.returncode, 1)
        self.assertIn("median UDP loss increased", result.stderr)

    def test_rejects_environment_mismatch(self) -> None:
        self.write_passing_pair()
        changed = dict(ENVIRONMENT)
        changed["encryption_algorithm"] = "aes-256-gcm"
        write_result(
            self.candidate,
            tcp_rows("forward", 1, [1.05e9] * 5, [95.0] * 5)
            + tcp_rows("reverse", 8, [2.10e9] * 5, [170.0] * 5),
            environment=changed,
        )
        result = self.run_gate()
        self.assertEqual(result.returncode, 2)
        self.assertIn("benchmark environments differ", result.stderr)

    def test_substrate_not_run_requires_explicit_smoke_flag(self) -> None:
        self.write_passing_pair(status="not-run")
        strict = self.run_gate()
        self.assertEqual(strict.returncode, 2)
        self.assertIn("cannot authorize", strict.stderr)

        smoke = self.run_gate("--allow-substrate-not-run")
        self.assertEqual(smoke.returncode, 0, smoke.stdout + smoke.stderr)

    def test_accepts_full_matrix_split_across_result_pairs(self) -> None:
        baseline_p8 = self.baseline.with_name("baseline-p8")
        candidate_p8 = self.candidate.with_name("candidate-p8")
        write_result(
            self.baseline,
            tcp_rows("forward", 1, [1.00e9] * 5, [100.0] * 5)
            + tcp_rows("reverse", 1, [0.98e9] * 5, [105.0] * 5),
        )
        write_result(
            self.candidate,
            tcp_rows("forward", 1, [1.05e9] * 5, [95.0] * 5)
            + tcp_rows("reverse", 1, [1.03e9] * 5, [100.0] * 5),
        )
        write_result(
            baseline_p8,
            tcp_rows("forward", 8, [2.02e9] * 5, [175.0] * 5)
            + tcp_rows("reverse", 8, [2.00e9] * 5, [180.0] * 5),
        )
        write_result(
            candidate_p8,
            tcp_rows("forward", 8, [2.12e9] * 5, [165.0] * 5)
            + tcp_rows("reverse", 8, [2.10e9] * 5, [170.0] * 5),
        )

        result = self.run_gate(
            "--baseline-extra-result-dir",
            str(baseline_p8),
            "--candidate-extra-result-dir",
            str(candidate_p8),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("4 workload(s)", result.stdout)

    def test_rejects_unpaired_extra_result_directory(self) -> None:
        self.write_passing_pair()
        baseline_extra = self.baseline.with_name("baseline-extra")
        write_result(
            baseline_extra,
            tcp_rows("forward", 1, [1.00e9] * 5, [100.0] * 5),
        )

        result = self.run_gate(
            "--baseline-extra-result-dir",
            str(baseline_extra),
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("result-directory counts differ", result.stderr)

    def test_default_gate_rejects_partial_tcp_matrix(self) -> None:
        baseline_rows = tcp_rows("forward", 1, [1.00e9] * 5, [100.0] * 5)
        candidate_rows = tcp_rows("forward", 1, [1.05e9] * 5, [90.0] * 5)
        write_result(self.baseline, baseline_rows)
        write_result(self.candidate, candidate_rows)

        strict = self.run_gate()
        self.assertEqual(strict.returncode, 2)
        self.assertIn("required TCP matrix is incomplete", strict.stderr)

        partial = self.run_gate("--allow-partial-matrix")
        self.assertEqual(partial.returncode, 0, partial.stdout + partial.stderr)

    def test_rejects_too_few_samples(self) -> None:
        baseline_rows = tcp_rows("forward", 1, [1.00e9], [100.0])
        candidate_rows = tcp_rows("forward", 1, [1.05e9], [90.0])
        write_result(self.baseline, baseline_rows)
        write_result(self.candidate, candidate_rows)
        result = self.run_gate("--allow-partial-matrix")
        self.assertEqual(result.returncode, 2)
        self.assertIn("minimum is 5", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
