"""Ground-truth labelling: probe events + attack-run manifests -> labelled events.

An event belongs to an attack run when it falls inside the run's window (with a small
margin for clock skew and late responses) and either

- involves the run's attacker address (as source or destination), or
- is a PFCP message carrying one of the run's sequence numbers. The injector draws
  those from a reserved block, so spoofed requests (which carry another NF's source
  address) and the UPF's answers to the real SMF are attributed exactly.

Everything else is benign. Consequences an attack causes in other NFs' own traffic
(for example the SMF re-associating after the UPF crashed) stay benign here: they are
effects, not attack messages, and the evaluation treats them as such.

    python -m prahari_analytics.labels --events events.jsonl --runs runs/ --out labelled.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from prahari_analytics.events import SignallingEvent

PRE_MARGIN_NS = 1_000_000_000  # 1 s before the run starts
POST_MARGIN_NS = 5_000_000_000  # 5 s after it ends: late responses, retransmissions


@dataclass(frozen=True)
class Run:
    run_id: str
    attack_id: str
    attacker_ip: str
    start_ns: int  # as recorded by the injector
    end_ns: int
    pfcp_seqs: frozenset[int] = field(default_factory=frozenset)

    @classmethod
    def from_manifest(cls, m: dict[str, Any]) -> Run:
        return cls(
            run_id=str(m["run_id"]),
            attack_id=str(m["attack_id"]),
            attacker_ip=str(m["attacker_ip"]),
            start_ns=int(m["started_ns"]),
            end_ns=int(m["ended_ns"]),
            pfcp_seqs=frozenset(int(s) for s in m.get("pfcp_seqs", [])),
        )

    def distance(self, ts: int) -> int:
        """0 inside the recorded window, else how far outside it (ns)."""
        if ts < self.start_ns:
            return self.start_ns - ts
        return max(0, ts - self.end_ns)

    def matches(self, ev: dict[str, Any]) -> bool:
        ts = int(ev["ts_ns"])
        if not self.start_ns - PRE_MARGIN_NS <= ts <= self.end_ns + POST_MARGIN_NS:
            return False
        if ev.get("protocol") == "PFCP" and ev.get("sequence") in self.pfcp_seqs:
            return True
        return self.attacker_ip in (ev["src"]["ip"], ev["dst"]["ip"])


def load_runs(paths: Iterable[Path]) -> list[Run]:
    """Manifests from files or directories. Dry runs never sent anything: skipped."""
    runs: list[Run] = []
    for p in paths:
        files = sorted(p.glob("*.json")) if p.is_dir() else [p]
        for f in files:
            m = json.loads(f.read_text(encoding="utf-8"))
            if m.get("dry_run"):
                continue
            runs.append(Run.from_manifest(m))
    return sorted(runs, key=lambda r: r.start_ns)


def label(ev: dict[str, Any], runs: list[Run]) -> dict[str, Any]:
    """Back-to-back runs overlap once margins are added: a PFCP sequence marker is
    unambiguous and wins; otherwise the run whose recorded window is closest does."""
    ts = int(ev["ts_ns"])
    best: Run | None = None
    for r in runs:
        if not r.matches(ev):
            continue
        if ev.get("protocol") == "PFCP" and ev.get("sequence") in r.pfcp_seqs:
            best = r
            break
        if best is None or r.distance(ts) < best.distance(ts):
            best = r
    if best is None:
        return {"is_attack": False}
    return {"is_attack": True, "attack_id": best.attack_id, "run_id": best.run_id}


def label_stream(lines: Iterable[str], runs: list[Run]) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yields (labelled JSON line, labels). Lines that are not complete events are skipped."""
    for raw in lines:
        line = raw.strip()
        if not line.startswith("{") or not line.endswith("}"):
            continue
        ev = json.loads(line)
        ev["labels"] = label(ev, runs)
        yield json.dumps(ev, separators=(",", ":")), ev["labels"]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Label probe events with attack-run manifests.")
    ap.add_argument("--events", type=Path, required=True, help="probe JSON Lines")
    ap.add_argument("--runs", type=Path, nargs="+", required=True, help="manifests or dirs")
    ap.add_argument("--out", type=Path, required=True, help="labelled JSON Lines")
    ap.add_argument("--validate", action="store_true", help="check every output line")
    args = ap.parse_args(argv)

    runs = load_runs(args.runs)
    per_run: Counter[str] = Counter()
    total = 0
    with args.events.open(encoding="utf-8") as src, args.out.open("w", encoding="utf-8") as dst:
        for out_line, lab in label_stream(src, runs):
            if args.validate:
                SignallingEvent.from_json(out_line)
            dst.write(out_line + "\n")
            total += 1
            per_run[lab.get("run_id", "benign")] += 1
    print(f"{total} events, {len(runs)} runs")
    for r in runs:
        print(f"  {r.attack_id:7} {r.run_id:36} {per_run[r.run_id]:7} events")
    print(f"  {'benign':44} {per_run['benign']:7} events")
    return 0


if __name__ == "__main__":
    sys.exit(main())
