"""Metrics collector for authorization operations."""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Protocol

logger = logging.getLogger("gatedhouse.metrics")


class MetricsCollector(Protocol):
    """Protocol for metrics collection."""

    def increment(self, metric: str, labels: dict[str, str] | None = None) -> None: ...
    def observe(self, metric: str, value: float, labels: dict[str, str] | None = None) -> None: ...


class DefaultMetricsCollector:
    """Simple in-memory metrics collector."""

    def __init__(self) -> None:
        self._counters: dict[str, int] = defaultdict(int)
        self._histograms: dict[str, list[float]] = defaultdict(list)

    def increment(self, metric: str, labels: dict[str, str] | None = None) -> None:
        key = self._make_key(metric, labels)
        self._counters[key] += 1

    def observe(self, metric: str, value: float, labels: dict[str, str] | None = None) -> None:
        key = self._make_key(metric, labels)
        self._histograms[key].append(value)

    def get_counter(self, metric: str, labels: dict[str, str] | None = None) -> int:
        key = self._make_key(metric, labels)
        return self._counters.get(key, 0)

    def get_observations(self, metric: str, labels: dict[str, str] | None = None) -> list[float]:
        key = self._make_key(metric, labels)
        return self._histograms.get(key, [])

    @staticmethod
    def _make_key(metric: str, labels: dict[str, str] | None) -> str:
        if not labels:
            return metric
        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{metric}{{{label_str}}}"
