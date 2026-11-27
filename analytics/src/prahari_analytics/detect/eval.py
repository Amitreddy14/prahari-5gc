"""Evaluation harness: run a detector over labelled events and measure it honestly.

Calibration uses benign traffic from the first `train_frac` of the timeline only; the
false-positive rate is then measured on the held-out benign after that point, so it is not
optimistic. Detection is reported three ways:

- per run: was the attack detected at all (>=1 alert in its window), and how fast;
- per attack class: fraction of its events flagged (recall);
- overall: precision / recall / F1 per event, attack vs benign.

The harness is detector-agnostic: anything with calibrate(benign), reset() and
score(event) -> list[Alert] works, so the Phase 5b models plug into the same metrics.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


class Detector(Protocol):
    def calibrate(self, benign: Iterable[dict[str, Any]]) -> Any: ...
    def reset(self) -> None: ...
    def score(self, ev: dict[str, Any]) -> list[Any]: ...


def _verdicts(engine: Detector, rows: list[dict[str, Any]]) -> list[list[Any]]:
    """Per-event alerts over the time-ordered stream. A detector may offer score_all for a
    batched (but still causal) pass -- the Isolation Forest uses it to score in one call."""
    batch = getattr(engine, "score_all", None)
    if callable(batch):
        return list(batch(rows))
    return [engine.score(ev) for ev in rows]


def _attack_id(ev: dict[str, Any]) -> str | None:
    lab = ev.get("labels") or {}
    return str(lab["attack_id"]) if lab.get("is_attack") and lab.get("attack_id") else None


def _run_id(ev: dict[str, Any]) -> str | None:
    lab = ev.get("labels") or {}
    return str(lab.get("run_id")) if lab.get("is_attack") else None


@dataclass
class RunResult:
    run_id: str
    attack_id: str
    total: int = 0
    flagged: int = 0
    start_ns: int = 0
    first_alert_ns: int | None = None

    @property
    def detected(self) -> bool:
        return self.first_alert_ns is not None

    @property
    def latency_s(self) -> float | None:
        if self.first_alert_ns is None:
            return None
        return (self.first_alert_ns - self.start_ns) / 1e9


@dataclass
class EvalResult:
    runs: list[RunResult] = field(default_factory=list)
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    benign_heldout: int = 0
    benign_heldout_fp: int = 0
    rule_hits: dict[str, int] = field(default_factory=dict)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def fp_rate(self) -> float:
        return self.benign_heldout_fp / self.benign_heldout if self.benign_heldout else 0.0

    @property
    def runs_detected(self) -> int:
        return sum(r.detected for r in self.runs)


def evaluate(
    events: Iterable[dict[str, Any]], engine: Detector, train_frac: float = 0.4
) -> EvalResult:
    rows = sorted(events, key=lambda e: int(e["ts_ns"]))
    if not rows:
        return EvalResult()
    t0, t1 = int(rows[0]["ts_ns"]), int(rows[-1]["ts_ns"])
    split = t0 + int((t1 - t0) * train_frac)
    engine.calibrate([r for r in rows if _attack_id(r) is None and int(r["ts_ns"]) < split])
    return _score(engine, rows, heldout_from=split)


def _score(engine: Detector, rows: list[dict[str, Any]], heldout_from: int | None) -> EvalResult:
    """Score an already-calibrated detector over time-ordered rows. Benign events with
    ts >= heldout_from count toward the false-positive rate (None => all benign counts)."""
    engine.reset()
    res = EvalResult()
    runs: dict[str, RunResult] = {}
    rule_hits: dict[str, int] = defaultdict(int)
    for ev, alerts in zip(rows, _verdicts(engine, rows), strict=True):
        ts = int(ev["ts_ns"])
        hit = bool(alerts)
        for a in alerts:
            rule_hits[getattr(a, "rule", str(a))] += 1
        aid = _attack_id(ev)
        if aid is not None:
            rid = _run_id(ev) or aid
            run = runs.setdefault(rid, RunResult(rid, aid, start_ns=ts))
            run.start_ns = min(run.start_ns, ts)
            run.total += 1
            if hit:
                run.flagged += 1
                prev = run.first_alert_ns
                run.first_alert_ns = ts if prev is None else min(prev, ts)
            res.tp += hit
            res.fn += not hit
        else:
            res.fp += hit
            res.tn += not hit
            if heldout_from is None or ts >= heldout_from:
                res.benign_heldout += 1
                res.benign_heldout_fp += hit
    res.runs = sorted(runs.values(), key=lambda r: r.attack_id)
    res.rule_hits = dict(sorted(rule_hits.items()))
    return res


def evaluate_cross(
    train: Iterable[dict[str, Any]], test: Iterable[dict[str, Any]], engine: Detector
) -> EvalResult:
    """Cross-campaign: calibrate on the training campaigns' benign, measure on held-out test
    campaigns. Every test benign event counts toward the false-positive rate."""
    engine.calibrate([e for e in train if _attack_id(e) is None])
    rows = sorted(test, key=lambda e: int(e["ts_ns"]))
    return _score(engine, rows, heldout_from=None)


def compare(
    events: Iterable[dict[str, Any]], detectors: dict[str, Detector], train_frac: float = 0.4
) -> dict[str, EvalResult]:
    rows = list(events)
    return {name: evaluate(rows, det, train_frac) for name, det in detectors.items()}


def comparison_markdown(
    results: dict[str, EvalResult], *, title: str = "Detector comparison"
) -> str:
    lines = [
        f"# {title}",
        "",
        "| detector | attacks detected | precision | recall | F1 | held-out FP |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for name, r in results.items():
        lines.append(
            f"| {name} | {r.runs_detected}/{len(r.runs)} | {r.precision:.3f} | "
            f"{r.recall:.3f} | {r.f1:.3f} | {r.fp_rate:.2%} |"
        )
    lines.append("")
    return "\n".join(lines)


def load_events(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if line.startswith("{") and line.endswith("}"):
                rows.append(json.loads(line))
    return rows


def results_markdown(res: EvalResult, *, title: str = "Rules detector") -> str:
    lines = [
        f"# {title} — evaluation",
        "",
        "Calibrated on benign traffic from the first 40% of the timeline; false positives",
        "measured on held-out benign after that point. Detection is behavioural — no event's",
        "source address is used as a feature.",
        "",
        "## Headline",
        "",
        f"- Attacks detected (≥1 alert in the run): **{res.runs_detected}/{len(res.runs)}**",
        f"- Precision: **{res.precision:.3f}** · Recall: **{res.recall:.3f}** · "
        f"F1: **{res.f1:.3f}** (per event, attack vs benign)",
        f"- False-positive rate on held-out benign: **{res.fp_rate:.3%}** "
        f"({res.benign_heldout_fp}/{res.benign_heldout})",
        "",
        "## Per attack run",
        "",
        "| attack | detected | latency (s) | events flagged |",
        "| --- | --- | ---: | ---: |",
    ]
    for r in res.runs:
        lat = f"{r.latency_s:.2f}" if r.latency_s is not None else "—"
        mark = "✓" if r.detected else "✗"
        lines.append(f"| {r.attack_id} | {mark} | {lat} | {r.flagged}/{r.total} |")
    lines += ["", "## Alerts by rule", "", "| rule | events |", "| --- | ---: |"]
    for rule, n in sorted(res.rule_hits.items(), key=lambda kv: -kv[1]):
        lines.append(f"| `{rule}` | {n} |")
    lines.append("")
    return "\n".join(lines)
