"""Sequence layer: a message-transition model of normal signalling flows.

Normal 5G signalling follows learnable orders -- a registration is NG Setup, then an Initial
UE Message, then authentication, and so on. This learns, per interface, how likely each
message is to follow the previous one *from the same source*, as benign add-k-smoothed
bigram probabilities. An event's surprisal is -log2 of that probability; a source whose
recent mean surprisal exceeds the benign baseline is flagged. It catches what rates and
outliers can miss: repetitive storms (a transition benign never makes), malformed messages
(an unseen token), and out-of-order procedures. The alert names the improbable transition,
so it stays explainable, and a Markov model neither overfits nor needs a GPU on one campaign
-- an LSTM is the richer variant once several campaigns exist (see ADR-0009 / phase 5b doc).
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from prahari_analytics.detect.features import source_key
from prahari_analytics.detect.rules import Alert

WINDOW_NS = 2_000_000_000
SMOOTHING = 0.5  # add-k: an unseen transition is improbable, not impossible


@dataclass
class SequenceDetector:
    window_ns: int = WINDOW_NS
    benign_fp: float = 0.01  # surprisal threshold = this upper-tail quantile of benign
    _counts: dict[str, dict[str, dict[str, int]]] = field(default_factory=dict, repr=False)
    _vocab: dict[str, set[str]] = field(default_factory=dict, repr=False)
    _all_messages: set[str] = field(default_factory=set, repr=False)
    _novel_surprisal: float = field(default=20.0, repr=False)
    _threshold: float = field(default=float("inf"), repr=False)
    _prev: dict[str, str] = field(default_factory=dict, repr=False)

    # ---------------------------------------------------------------- calibration
    def _learn(self, events: list[dict[str, Any]]) -> None:
        prev: dict[str, str] = {}
        for ev in events:
            iface = str(ev.get("interface"))
            key = source_key(ev)
            msg = str(ev.get("message"))
            last = prev.get(key, "<start>")
            self._counts.setdefault(iface, defaultdict(lambda: defaultdict(int)))
            self._counts[iface][last][msg] += 1
            self._vocab.setdefault(iface, set()).add(msg)
            self._all_messages.add(msg)
            prev[key] = msg
        # A message type never seen in benign is maximally surprising; put its surprisal
        # clearly above anything add-k smoothing of known messages can reach.
        self._novel_surprisal = math.log2(max(len(self._all_messages), 2)) + 8.0

    def _surprisal(self, iface: str, last: str, msg: str) -> float:
        if msg not in self._all_messages:  # out of the benign vocabulary entirely
            return self._novel_surprisal
        table = self._counts.get(iface, {})
        row = table.get(last, {})
        vocab = max(len(self._vocab.get(iface, ())), 1)
        total = sum(row.values())
        prob = (row.get(msg, 0) + SMOOTHING) / (total + SMOOTHING * vocab)
        return -math.log2(prob)

    def calibrate(self, benign: Iterable[dict[str, Any]]) -> SequenceDetector:
        rows = sorted(benign, key=lambda e: int(e["ts_ns"]))
        self._learn(rows)
        # The threshold is the upper tail of benign per-event transition surprisals, so a
        # fraction `benign_fp` of benign transitions is above it.
        self.reset()
        surprisals = sorted(self._transition(ev) for ev in rows)
        if surprisals:
            idx = min(len(surprisals) - 1, int((1.0 - self.benign_fp) * len(surprisals)))
            self._threshold = surprisals[idx]
        self.reset()
        return self

    # ---------------------------------------------------------------- scoring
    def _transition(self, ev: dict[str, Any]) -> float:
        """Surprisal of this event's message given the previous one from the same source."""
        key = source_key(ev)
        msg = str(ev.get("message"))
        s = self._surprisal(str(ev.get("interface")), self._prev.get(key, "<start>"), msg)
        self._prev[key] = msg
        return s

    def reset(self) -> None:
        self._prev.clear()

    def score(self, ev: dict[str, Any]) -> list[Alert]:
        prev = self._prev.get(source_key(ev), "<start>")
        s = self._transition(ev)
        if s > self._threshold:
            why = f"improbable transition {prev} -> {ev.get('message')} ({s:.1f} bits)"
            return [Alert("sequence", why)]
        return []
