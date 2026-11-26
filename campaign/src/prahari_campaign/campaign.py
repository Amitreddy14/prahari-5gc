"""Campaign runner: benign traffic + a timeline of attacks, captured together.

A campaign runs the benign generator continuously in the background while firing attack
scenarios at scheduled offsets, so attacks land inside realistic traffic rather than
against a quiet core. Every attack writes its own run manifest (the labeller's ground
truth); the campaign writes one campaign.json tying them together with the benign summary.

The orchestration is injected (`attack_runner`, benign generator, clock/sleep) so it is
unit-testable without Docker; the CLI wires the real `docker compose exec` commands.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from prahari_campaign.benign import BenignConfig, BenignGenerator

# attack_runner(attack_id, params, out_dir) -> result dict (run_id, status, ...).
AttackRunner = Callable[[str, "dict[str, str]", Path], "dict[str, Any]"]


@dataclass(frozen=True)
class AttackStep:
    at: float  # seconds from campaign start
    attack_id: str
    params: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class CampaignSpec:
    name: str
    steps: tuple[AttackStep, ...]
    benign: BenignConfig | None = None
    tail_seconds: float = 5.0  # keep benign running this long after the last attack

    @property
    def duration(self) -> float:
        last = max((s.at for s in self.steps), default=0.0)
        return last + self.tail_seconds

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CampaignSpec:
        steps = tuple(
            AttackStep(
                float(s["at"]),
                str(s["id"]),
                {k: str(v) for k, v in s.get("params", {}).items()},
            )
            for s in d.get("steps", [])
        )
        benign = None
        if d.get("benign") is not None:
            b = d["benign"]
            benign = BenignConfig(
                imsi_base=str(b.get("imsi_base", "001010000000001")),
                ue_count=int(b.get("ue_count", 10)),
                rate=float(b.get("rate", 2.0)),
                seed=int(b.get("seed", 0)),
            )
        return cls(
            name=str(d["name"]),
            steps=tuple(sorted(steps, key=lambda s: s.at)),
            benign=benign,
            tail_seconds=float(d.get("tail_seconds", 5.0)),
        )


def load_spec(path: Path) -> CampaignSpec:
    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yaml", ".yml"):
        import yaml  # noqa: PLC0415 - optional; JSON specs need no dependency

        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    return CampaignSpec.from_dict(data)


@dataclass
class Campaign:
    spec: CampaignSpec
    attack_runner: AttackRunner
    run_cli: Callable[[str, str], str] | None = None  # for benign; None disables it
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic

    def run(self, out_dir: Path) -> dict[str, Any]:
        out_dir.mkdir(parents=True, exist_ok=True)
        started_ns = time.time_ns()
        start = self.clock()

        stop = threading.Event()
        gen: BenignGenerator | None = None
        thread: threading.Thread | None = None
        benign_summary: dict[str, Any] = {"enabled": False}
        if self.spec.benign is not None and self.run_cli is not None:
            gen = BenignGenerator(self.spec.benign, self.run_cli)
            summary_box: dict[str, Any] = {}
            thread = threading.Thread(
                target=lambda: summary_box.update(gen.run(stop, self.sleep)), daemon=True
            )
            thread.start()
            benign_summary = {"enabled": True, "box": summary_box}

        attacks: list[dict[str, Any]] = []
        try:
            for step in self.spec.steps:
                self._wait_until(start + step.at)
                result = self.attack_runner(step.attack_id, dict(step.params), out_dir)
                attacks.append(
                    {"at": step.at, "attack_id": step.attack_id, "params": step.params, **result}
                )
            self._wait_until(start + self.spec.duration)
        finally:
            stop.set()
            if thread is not None:
                thread.join(timeout=10.0)

        if gen is not None:
            benign_summary = {
                "enabled": True,
                "commands": sum(gen.counts.values()),
                "by_action": dict(gen.counts),
                "errors": gen.errors,
            }

        manifest = {
            "campaign": self.spec.name,
            "started_ns": started_ns,
            "ended_ns": time.time_ns(),
            "benign": benign_summary,
            "attacks": attacks,
        }
        (out_dir / "campaign.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        return manifest

    def _wait_until(self, deadline: float) -> None:
        remaining = deadline - self.clock()
        if remaining > 0:
            self.sleep(remaining)
