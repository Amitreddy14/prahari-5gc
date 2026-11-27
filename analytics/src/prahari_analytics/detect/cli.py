"""prahari-detect: run a detector (or compare all) over labelled events and report results.

python -m prahari_analytics.detect.cli --events labelled.jsonl --detector ensemble
python -m prahari_analytics.detect.cli --events labelled.jsonl --compare --out compare.md
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from prahari_analytics.detect.ensemble import Ensemble
from prahari_analytics.detect.eval import (
    Detector,
    compare,
    comparison_markdown,
    evaluate,
    load_events,
    results_markdown,
)
from prahari_analytics.detect.isoforest import IsolationForestDetector
from prahari_analytics.detect.rules import RuleEngine
from prahari_analytics.detect.sequence import SequenceDetector


def _make(name: str, benign_fp: float, window_ns: int) -> Detector:
    if name == "rules":
        return RuleEngine(window_ns=window_ns)
    if name == "isoforest":
        return IsolationForestDetector(window_ns=window_ns, benign_fp=benign_fp)
    if name == "sequence":
        return SequenceDetector(benign_fp=benign_fp)
    return Ensemble(
        rules=RuleEngine(window_ns=window_ns),
        isoforest=IsolationForestDetector(window_ns=window_ns, benign_fp=benign_fp),
        sequence=SequenceDetector(benign_fp=benign_fp),
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run a detector and report metrics.")
    ap.add_argument("--events", type=Path, required=True, help="labelled JSON Lines")
    ap.add_argument(
        "--detector", default="ensemble", choices=["rules", "isoforest", "sequence", "ensemble"]
    )
    ap.add_argument("--compare", action="store_true", help="evaluate every detector side by side")
    ap.add_argument("--out", type=Path, help="write the Markdown results/comparison here")
    ap.add_argument("--train-frac", type=float, default=0.4)
    ap.add_argument("--benign-fp", type=float, default=0.01)
    ap.add_argument("--window-ms", type=int, default=2000)
    args = ap.parse_args(argv)

    events = load_events(args.events)
    window_ns = args.window_ms * 1_000_000

    if args.compare:
        names = ["rules", "isoforest", "sequence", "ensemble"]
        results = compare(
            events, {n: _make(n, args.benign_fp, window_ns) for n in names}, args.train_frac
        )
        for name, r in results.items():
            print(
                f"{name:10} {r.runs_detected}/{len(r.runs)}  P={r.precision:.3f} "
                f"R={r.recall:.3f} F1={r.f1:.3f} FP={r.fp_rate:.2%}"
            )
        if args.out:
            args.out.write_text(comparison_markdown(results), encoding="utf-8")
            print(f"comparison -> {args.out}")
        return 0

    res = evaluate(events, _make(args.detector, args.benign_fp, window_ns), args.train_frac)
    print(f"attacks detected: {res.runs_detected}/{len(res.runs)}")
    print(f"precision={res.precision:.3f} recall={res.recall:.3f} f1={res.f1:.3f}")
    print(f"benign false-positive rate (held-out): {res.fp_rate:.3%}")
    for run in res.runs:
        lat = f"{run.latency_s:.2f}s" if run.latency_s is not None else "not detected"
        print(f"  {run.attack_id:7} {run.flagged:5}/{run.total:<5} {lat}")
    if args.out:
        args.out.write_text(
            results_markdown(res, title=f"{args.detector} detector"), encoding="utf-8"
        )
        print(f"results table -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
