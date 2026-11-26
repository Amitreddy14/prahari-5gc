"""prahari-detect: run the rules detector over labelled events and report results.

python -m prahari_analytics.detect.cli --events labelled.jsonl --out results.md
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from prahari_analytics.detect.eval import evaluate, load_events, results_markdown
from prahari_analytics.detect.rules import RuleEngine


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run the rules detector and report metrics.")
    ap.add_argument("--events", type=Path, required=True, help="labelled JSON Lines")
    ap.add_argument("--out", type=Path, help="write the Markdown results table here")
    ap.add_argument("--train-frac", type=float, default=0.4, help="benign calibration fraction")
    ap.add_argument("--window-ms", type=int, default=2000, help="burst window (ms)")
    args = ap.parse_args(argv)

    events = load_events(args.events)
    engine = RuleEngine(window_ns=args.window_ms * 1_000_000)
    res = evaluate(events, engine, train_frac=args.train_frac)

    print(f"attacks detected: {res.runs_detected}/{len(res.runs)}")
    print(f"precision={res.precision:.3f} recall={res.recall:.3f} f1={res.f1:.3f}")
    print(f"benign false-positive rate (held-out): {res.fp_rate:.3%}")
    for r in res.runs:
        lat = f"{r.latency_s:.2f}s" if r.latency_s is not None else "not detected"
        print(f"  {r.attack_id:7} {r.flagged:5}/{r.total:<5} {lat}")
    if args.out:
        args.out.write_text(results_markdown(res), encoding="utf-8")
        print(f"results table -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
