"""Behavioural features for detection, computed without any party's identity.

The dataset is labelled by the attacker's address, so any feature that encodes "who sent
this" (an IP, or the NF-role the probe inferred from a fixed address map) would leak the
label. Detection here is deliberately identity-free: events are *grouped* by source entity
to measure its behaviour, but the identity is never a feature. A detector that fires does
so because of what an entity did -- a burst, a protocol-state violation, a decode failure --
so it would flag a compromised real NF behaving the same way, not just the known attacker.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Hashable
from dataclasses import dataclass, field
from typing import Any


def source_key(ev: dict[str, Any]) -> str:
    """Grouping key only (never a feature): the source address of the event."""
    return str((ev.get("src") or {}).get("ip", "?"))


def event_features(ev: dict[str, Any]) -> dict[str, Any]:
    """Per-event behavioural features. No addresses, NF roles, UE ids or run ids."""
    sbi = ev.get("sbi") or {}
    pfcp = ev.get("pfcp") or {}
    ngap = ev.get("ngap") or {}
    nas = ev.get("nas") or {}
    return {
        "interface": ev.get("interface"),
        "protocol": ev.get("protocol"),
        "message": ev.get("message"),
        "direction": ev.get("direction"),
        "decode_ok": ev.get("decode_status") == "ok",
        "decode_status": ev.get("decode_status"),
        "size_bytes": int(ev.get("size_bytes", 0)),
        "has_cause": ev.get("cause") is not None,
        "is_response": ev.get("direction") == "response",
        "sbi_service": sbi.get("service"),
        "sbi_is_known_op": bool(sbi.get("service")),
        "pfcp_session_known": pfcp.get("session_known"),
        "ngap_procedure": ngap.get("procedure_code"),
        "nas_registration": nas.get("registration_type"),
    }


@dataclass
class RateTracker:
    """Sliding-window event counter per key. `add` returns the count in the last
    `window_ns` for that key (the current event included). Keys are opaque."""

    window_ns: int
    _events: dict[Hashable, deque[int]] = field(default_factory=dict)

    def add(self, key: Hashable, ts_ns: int) -> int:
        dq = self._events.setdefault(key, deque())
        dq.append(ts_ns)
        cutoff = ts_ns - self.window_ns
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def reset(self) -> None:
        self._events.clear()


@dataclass
class FanoutTracker:
    """Distinct values seen per key within a sliding window (e.g. distinct RAN-UE-NGAP-IDs
    or SEIDs a source touches): the breadth of a scan or storm."""

    window_ns: int
    _seen: dict[Hashable, deque[tuple[int, Hashable]]] = field(default_factory=dict)

    def add(self, key: Hashable, value: Hashable, ts_ns: int) -> int:
        dq = self._seen.setdefault(key, deque())
        dq.append((ts_ns, value))
        cutoff = ts_ns - self.window_ns
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        return len({v for _, v in dq})

    def reset(self) -> None:
        self._seen.clear()
