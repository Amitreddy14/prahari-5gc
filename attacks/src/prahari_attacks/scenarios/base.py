"""Scenario framework: parameters, pacing, and the context every attack runs in."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, ClassVar

from prahari_attacks.guard import ATTACKER_IP, Guard
from prahari_attacks.manifest import Manifest

# Testbed addresses (Architecture.md section 6).
AMF_IP = "172.22.0.5"
SMF_IP = "172.22.0.7"
UPF_IP = "172.22.0.8"
NRF_IP = "172.22.0.10"
GNB_IP = "172.22.0.20"
PFCP_PORT = 8805
SBI_PORT = 7777
NGAP_SCTP_PORT = 38412  # N2: NGAP over SCTP (AMF)


@dataclass(frozen=True)
class Param:
    name: str
    default: Any
    help: str

    def parse(self, raw: str) -> Any:
        d = self.default
        if isinstance(d, bool):
            if raw.lower() in ("1", "true", "yes", "on"):
                return True
            if raw.lower() in ("0", "false", "no", "off"):
                return False
            raise ValueError(f"{self.name}: expected true/false, got {raw!r}")
        if isinstance(d, int):
            return int(raw, 0)
        if isinstance(d, float):
            return float(raw)
        return raw


class Pacer:
    """Sends at most `rate` items per second (0 = as fast as possible)."""

    def __init__(self, rate: float) -> None:
        self._interval = 1.0 / rate if rate > 0 else 0.0
        self._next = time.monotonic()

    def wait(self) -> None:
        if self._interval == 0.0:
            return
        now = time.monotonic()
        if now < self._next:
            time.sleep(self._next - now)
        self._next = max(self._next + self._interval, time.monotonic() - self._interval)


@dataclass
class Context:
    guard: Guard
    manifest: Manifest
    params: dict[str, Any]
    log: Callable[[str], None] = print
    attacker_ip: str = str(ATTACKER_IP)
    stop_at: float = field(default=float("inf"))

    def expired(self) -> bool:
        return time.monotonic() >= self.stop_at


class Scenario(ABC):
    attack_id: ClassVar[str]
    title: ClassVar[str]
    interface: ClassVar[str]
    mechanism: ClassVar[str]
    params: ClassVar[tuple[Param, ...]]

    @classmethod
    def defaults(cls) -> dict[str, Any]:
        return {p.name: p.default for p in cls.params}

    @classmethod
    @abstractmethod
    def targets(cls, params: dict[str, Any]) -> list[str]:
        """Every address this run may send to (checked by the guard before anything)."""

    @classmethod
    def spoofed_sources(cls, params: dict[str, Any]) -> list[str]:
        """Addresses this run impersonates, if any (recorded in the manifest)."""
        del params
        return []

    @abstractmethod
    def run(self, ctx: Context) -> None:
        """Performs the attack, recording outcomes in ctx.manifest."""
