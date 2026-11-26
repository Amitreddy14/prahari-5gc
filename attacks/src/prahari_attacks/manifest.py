"""Run manifests: the ground truth that turns captured events into a labelled dataset.

One JSON file per run. The labeller (prahari_analytics.labels) marks an event as part
of this run if it falls inside [started_ns - pre, ended_ns + post] and either involves
`attacker_ip` or carries one of the run's markers (PFCP sequence numbers of spoofed
messages, which the UPF echoes in its responses to the real SMF).
"""

from __future__ import annotations

import json
import secrets
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

MANIFEST_VERSION = 1

# Injector PFCP sequence numbers come from this reserved block so spoofed messages
# (which bear another NF's source address) can still be attributed exactly.
PFCP_SEQ_BASE = 0xA00000
PFCP_SEQ_LIMIT = 0xFFFFFF


@dataclass
class Manifest:
    attack_id: str
    title: str
    params: dict[str, Any]
    attacker_ip: str
    targets: list[str]
    dry_run: bool = False
    run_id: str = ""
    started_ns: int = 0
    ended_ns: int = 0
    pfcp_seqs: list[int] = field(default_factory=list)
    spoofed_sources: list[str] = field(default_factory=list)
    outcome: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    version: int = MANIFEST_VERSION
    _counts: Counter[str] = field(default_factory=Counter, repr=False)
    _next_seq: int = field(default=0, repr=False)

    def start(self) -> None:
        if not self.run_id:
            stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
            self.run_id = f"{self.attack_id}-{stamp}-{secrets.token_hex(3)}"
        self.started_ns = time.time_ns()
        # Random start inside the reserved block: two runs do not share sequences.
        self._next_seq = PFCP_SEQ_BASE + secrets.randbelow(0x100000)

    def finish(self) -> None:
        self.ended_ns = time.time_ns()
        self.outcome.setdefault("counts", dict(self._counts))

    def next_pfcp_seq(self) -> int:
        seq = self._next_seq
        self._next_seq = PFCP_SEQ_BASE + ((self._next_seq + 1 - PFCP_SEQ_BASE) % 0x5FFFFF)
        self.pfcp_seqs.append(seq)
        return seq

    def count(self, key: str, n: int = 1) -> None:
        self._counts[key] += n

    def to_json(self) -> str:
        d = asdict(self)
        d.pop("_counts", None)
        d.pop("_next_seq", None)
        return json.dumps(d, indent=2, sort_keys=True)

    def write(self, out_dir: Path) -> Path:
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"{self.run_id}.json"
        path.write_text(self.to_json() + "\n", encoding="utf-8")
        return path
