"""Benign traffic: scripted UE churn through UERANSIM's nr-cli.

The testbed's UEs register once at start-up and then sit idle, which is a thin "normal"
class for a dataset. This drives them through realistic subscriber behaviour -- PDU
session establish/release and status polls -- so benign signalling (N4 session setup,
N2 PDU Session Resource Setup, 5GSM NAS) keeps flowing while attacks are injected.

It issues commands through an injected `run_cli(imsi, command)` so it is testable
without Docker; the CLI wires that to `docker compose exec -T ue nr-cli`.
"""

from __future__ import annotations

import random
import threading
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field

RunCli = Callable[[str, str], str]

# nr-cli commands and their weights. Weighted toward data-session churn, which is the
# richest benign signalling; status/ps-list are cheap polls that add variety.
DEFAULT_ACTIONS: tuple[tuple[str, int], ...] = (
    ("ps-establish IPv4 --sst 1 --dnn internet", 4),
    ("ps-release-all", 3),
    ("ps-list", 2),
    ("status", 1),
)


@dataclass(frozen=True)
class BenignConfig:
    imsi_base: str = "001010000000001"
    ue_count: int = 10
    rate: float = 2.0  # commands per second across all UEs
    seed: int = 0
    actions: tuple[tuple[str, int], ...] = DEFAULT_ACTIONS


@dataclass
class BenignGenerator:
    cfg: BenignConfig
    run_cli: RunCli
    counts: Counter[str] = field(default_factory=Counter)
    errors: int = 0

    def imsis(self) -> list[str]:
        base = int(self.cfg.imsi_base)
        return [f"{base + i:015d}" for i in range(self.cfg.ue_count)]

    def _choose(self, rng: random.Random) -> tuple[str, str]:
        imsi = rng.choice(self.imsis())
        actions = [a for a, _ in self.cfg.actions]
        weights = [w for _, w in self.cfg.actions]
        command = rng.choices(actions, weights=weights, k=1)[0]
        return imsi, command

    def step(self, rng: random.Random) -> tuple[str, str]:
        """Issue one benign command; returns (imsi, command) for the caller/tests."""
        imsi, command = self._choose(rng)
        try:
            self.run_cli(imsi, command)
            self.counts[command.split()[0]] += 1
        except Exception:  # a single UE hiccup must not stop the generator
            self.errors += 1
        return imsi, command

    def run(
        self, stop: threading.Event, sleep: Callable[[float], None] = time.sleep
    ) -> dict[str, object]:
        """Loop until `stop` is set, pacing to cfg.rate. Returns a summary."""
        rng = random.Random(self.cfg.seed)  # noqa: S311 - traffic shaping, not crypto
        interval = 1.0 / self.cfg.rate if self.cfg.rate > 0 else 0.0
        issued = 0
        while not stop.is_set():
            self.step(rng)
            issued += 1
            if interval:
                sleep(interval)
        return {"commands": issued, "by_action": dict(self.counts), "errors": self.errors}
