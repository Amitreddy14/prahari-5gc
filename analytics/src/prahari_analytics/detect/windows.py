"""Windowed behavioural feature vectors per source entity, for the statistical layer.

Each vector summarises what one source did in a trailing time window: how much, how varied,
how concentrated on one message, how often it failed to decode, and how wide it fanned out
over sessions/UEs/targets. All features are counts and ratios -- never an address, NF role
or identity (see features.py for why that matters). The same builder runs in batch (to fit
the model on benign windows) and streaming (one vector per event, for scoring).
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

from prahari_analytics.detect.features import source_key

# Order matters: this is the model's input vector. All identity-free.
WINDOW_FEATURES: tuple[str, ...] = (
    "count",  # events from this source in the window
    "n_msg_types",  # distinct message names
    "max_type_frac",  # share of the most frequent message (burst concentration)
    "decode_fail_ratio",  # non-ok decodes / count
    "response_ratio",  # responses / count
    "unknown_session_ratio",  # PFCP requests for unknown sessions / count
    "seid_fanout",  # distinct SEIDs touched
    "ranue_fanout",  # distinct RAN-UE-NGAP-IDs touched
    "dst_fanout",  # distinct destination addresses (count only)
    "cause_ratio",  # events carrying a cause / count
    "mean_size",  # mean signalling size (bytes)
)


@dataclass
class _Summary:
    ts: int
    msg: str
    decode_ok: bool
    is_response: bool
    unknown_session: bool
    seid: Any
    ranue: Any
    dst: Any
    has_cause: bool
    size: int


def _summarise(ev: dict[str, Any]) -> _Summary:
    pfcp = ev.get("pfcp") or {}
    ue = ev.get("ue") or {}
    return _Summary(
        ts=int(ev["ts_ns"]),
        msg=str(ev.get("message")),
        decode_ok=ev.get("decode_status") == "ok",
        is_response=ev.get("direction") == "response",
        unknown_session=ev.get("protocol") == "PFCP" and pfcp.get("session_known") is False,
        seid=ue.get("seid"),
        ranue=ue.get("ran_ue_ngap_id"),
        dst=(ev.get("dst") or {}).get("ip"),
        has_cause=ev.get("cause") is not None,
        size=int(ev.get("size_bytes", 0)),
    )


def _vector(window: list[_Summary]) -> list[float]:
    n = len(window)
    if n == 0:
        return [0.0] * len(WINDOW_FEATURES)
    types: dict[str, int] = {}
    for s in window:
        types[s.msg] = types.get(s.msg, 0) + 1
    return [
        float(n),
        float(len(types)),
        max(types.values()) / n,
        sum(not s.decode_ok for s in window) / n,
        sum(s.is_response for s in window) / n,
        sum(s.unknown_session for s in window) / n,
        float(len({s.seid for s in window if s.seid is not None})),
        float(len({s.ranue for s in window if s.ranue is not None})),
        float(len({s.dst for s in window if s.dst is not None})),
        sum(s.has_cause for s in window) / n,
        sum(s.size for s in window) / n,
    ]


@dataclass
class WindowBuilder:
    """Per-source sliding window; `add` returns the source's current window vector."""

    window_ns: int
    _win: dict[str, deque[_Summary]] = field(default_factory=dict)

    def add(self, ev: dict[str, Any]) -> list[float]:
        key = source_key(ev)
        dq = self._win.setdefault(key, deque())
        s = _summarise(ev)
        dq.append(s)
        cutoff = s.ts - self.window_ns
        while dq and dq[0].ts < cutoff:
            dq.popleft()
        return _vector(list(dq))

    def reset(self) -> None:
        self._win.clear()
