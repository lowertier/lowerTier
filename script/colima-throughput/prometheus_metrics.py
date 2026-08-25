#!/usr/bin/env python3
"""Parse Prometheus text snapshots used by the benchmark tooling."""

from __future__ import annotations

import re
from pathlib import Path


MetricLabels = tuple[tuple[str, str], ...]
MetricKey = tuple[str, MetricLabels]

_METRIC_RE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(?P<labels>.*)\})?\s+"
    r"(?P<value>[-+]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][-+]?[0-9]+)?)$"
)
_LABEL_RE = re.compile(r'(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)="(?P<value>(?:\\.|[^"])*)"')
_LABEL_ESCAPE_RE = re.compile(r"\\([\\n\"])")
_LABEL_ESCAPES = {"\\": "\\", "n": "\n", '"': '"'}


def _replace_label_escape(match: re.Match[str]) -> str:
    return _LABEL_ESCAPES[match.group(1)]


def parse_prometheus_labels(text: str | None) -> MetricLabels:
    if not text:
        return ()
    return tuple(
        sorted(
            (
                match.group("name"),
                _LABEL_ESCAPE_RE.sub(_replace_label_escape, match.group("value")),
            )
            for match in _LABEL_RE.finditer(text)
        )
    )


def read_prometheus_metrics(path: Path) -> dict[MetricKey, float]:
    """Read one scrape; a later duplicate sample replaces an earlier one."""

    metrics: dict[MetricKey, float] = {}
    if not path.exists():
        return metrics
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _METRIC_RE.fullmatch(line)
        if match is None:
            continue
        key = (
            match.group("name"),
            parse_prometheus_labels(match.group("labels")),
        )
        metrics[key] = float(match.group("value"))
    return metrics
