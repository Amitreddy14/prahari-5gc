"""Ensemble: the rules, Isolation Forest and sequence layers scored together.

Each layer has a different strength -- rules are precise and name a protocol violation, the
Isolation Forest finds statistically odd windows (including slow attacks the rules miss), the
sequence model flags improbable message orders. An event is flagged if any layer fires, and
every alert is tagged with its layer, so an analyst sees not just that something fired but
which kind of evidence it was. The combination is the Phase 5b headline: it detects attacks
no single layer catches alone.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from itertools import chain
from typing import Any

from prahari_analytics.detect.isoforest import IsolationForestDetector
from prahari_analytics.detect.rules import Alert, RuleEngine
from prahari_analytics.detect.sequence import SequenceDetector


@dataclass
class Ensemble:
    rules: RuleEngine = field(default_factory=RuleEngine)
    isoforest: IsolationForestDetector = field(default_factory=IsolationForestDetector)
    sequence: SequenceDetector = field(default_factory=SequenceDetector)

    @property
    def layers(self) -> dict[str, Any]:
        return {"rules": self.rules, "isoforest": self.isoforest, "sequence": self.sequence}

    def calibrate(self, benign: Iterable[dict[str, Any]]) -> Ensemble:
        benign = list(benign)
        for layer in self.layers.values():
            layer.calibrate(benign)
        return self

    def reset(self) -> None:
        for layer in self.layers.values():
            layer.reset()

    def score(self, ev: dict[str, Any]) -> list[Alert]:
        alerts: list[Alert] = []
        for layer in self.layers.values():
            alerts.extend(layer.score(ev))
        return alerts

    def score_all(self, rows: list[dict[str, Any]]) -> list[list[Alert]]:
        """Each layer scores the full stream causally; results are OR-combined per event."""
        per_layer = []
        for layer in self.layers.values():
            batch = getattr(layer, "score_all", None)
            per_layer.append(
                list(batch(rows)) if callable(batch) else [layer.score(e) for e in rows]
            )
        return [list(chain.from_iterable(la)) for la in zip(*per_layer, strict=True)]
