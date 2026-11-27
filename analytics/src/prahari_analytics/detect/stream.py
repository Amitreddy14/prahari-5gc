"""Streaming scorer: calibrate once on benign, then score a live event stream.

The same ensemble that the harness evaluates offline runs here online -- each layer's score()
is causal, so scoring one event at a time needs no change. It reads probe events as JSON
Lines (a file, or stdin for a live `tail -f` / Kafka consumer) and emits one alert per
flagged event: the event id, time, the layers that fired, and their explanations.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from prahari_analytics.detect.ensemble import Ensemble
from prahari_analytics.detect.isoforest import IsolationForestDetector
from prahari_analytics.detect.rules import Alert
from prahari_analytics.detect.sequence import SequenceDetector


@dataclass
class StreamScorer:
    ensemble: Ensemble

    @classmethod
    def calibrated_on(
        cls, benign: Iterable[dict[str, Any]], benign_fp: float = 0.01
    ) -> StreamScorer:
        ens = Ensemble(
            isoforest=IsolationForestDetector(benign_fp=benign_fp),
            sequence=SequenceDetector(benign_fp=benign_fp),
        )
        ens.calibrate(benign)
        ens.reset()
        return cls(ens)

    def process(self, ev: dict[str, Any]) -> list[Alert]:
        return self.ensemble.score(ev)

    def alerts(self, events: Iterable[dict[str, Any]]) -> Iterator[dict[str, Any]]:
        for ev in events:
            found = self.process(ev)
            if found:
                layers = sorted({a.rule.split("_")[0] if "_" in a.rule else a.rule for a in found})
                yield {
                    "event_id": ev.get("event_id"),
                    "ts_ns": ev.get("ts_ns"),
                    "interface": ev.get("interface"),
                    "message": ev.get("message"),
                    "layers": [self._layer_of(a) for a in found],
                    "alerts": [{"rule": a.rule, "why": a.explanation} for a in found],
                    "_layers_summary": layers,
                }

    @staticmethod
    def _layer_of(a: Alert) -> str:
        if a.rule in ("isoforest", "sequence"):
            return a.rule
        return "rules"


def _read_jsonl(path: Path | None) -> Iterator[dict[str, Any]]:
    stream = sys.stdin if path is None else path.open(encoding="utf-8")
    try:
        for raw in stream:
            line = raw.strip()
            if line.startswith("{") and line.endswith("}"):
                yield json.loads(line)
    finally:
        if path is not None:
            stream.close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Stream-score probe events with the ensemble.")
    ap.add_argument("--calibrate", type=Path, required=True, help="benign events (JSON Lines)")
    ap.add_argument("--events", type=Path, help="events to score (default: stdin)")
    ap.add_argument("--benign-fp", type=float, default=0.01)
    args = ap.parse_args(argv)

    benign = [
        e for e in _read_jsonl(args.calibrate) if not (e.get("labels") or {}).get("is_attack")
    ]
    scorer = StreamScorer.calibrated_on(benign, benign_fp=args.benign_fp)
    n = 0
    try:
        for alert in scorer.alerts(_read_jsonl(args.events)):
            print(json.dumps(alert, separators=(",", ":")))
            n += 1
    except BrokenPipeError:  # a downstream `head`/consumer closed the pipe
        return 0
    print(f"{n} alerts", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
