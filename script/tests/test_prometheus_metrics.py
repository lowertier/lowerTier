#!/usr/bin/env python3
"""Tests for the shared Prometheus text parser."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


PARSER_PATH = (
    Path(__file__).resolve().parents[1] / "colima-throughput" / "prometheus_metrics.py"
)
SPEC = importlib.util.spec_from_file_location("prometheus_metrics", PARSER_PATH)
assert SPEC is not None
assert SPEC.loader is not None
PROMETHEUS_METRICS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROMETHEUS_METRICS)


class PrometheusMetricsTests(unittest.TestCase):
    def test_parses_and_unescapes_labels(self) -> None:
        labels = PROMETHEUS_METRICS.parse_prometheus_labels(
            r'quote="a\"b",line="a\nb",path="a\\b",stage="quic_send"'
        )

        self.assertEqual(
            labels,
            (
                ("line", "a\nb"),
                ("path", "a\\b"),
                ("quote", 'a"b'),
                ("stage", "quic_send"),
            ),
        )

    def test_reads_snapshot_and_uses_last_duplicate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "metrics.txt"
            path.write_text(
                "# TYPE probe_total counter\n"
                'probe_total{stage="send"} 1.25\n'
                'probe_total{stage="send"} 2.5\n'
                "malformed metric\n",
                encoding="utf-8",
            )

            metrics = PROMETHEUS_METRICS.read_prometheus_metrics(path)

        self.assertEqual(metrics[("probe_total", (("stage", "send"),))], 2.5)

    def test_missing_snapshot_is_empty(self) -> None:
        self.assertEqual(
            PROMETHEUS_METRICS.read_prometheus_metrics(Path("does-not-exist")), {}
        )


if __name__ == "__main__":
    unittest.main()
