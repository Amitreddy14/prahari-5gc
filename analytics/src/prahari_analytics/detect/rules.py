"""Rules detection layer: explainable, high-precision protocol-state and rate checks.

Each rule maps to a threat-model detection cue and fires on behaviour, never on a known
attacker address (see features.py). The engine is causal -- it scores one event at a time
from state built only from earlier events -- so it runs unchanged as a streaming detector.

Calibration learns a baseline from benign traffic only (known gNB ids, per-message-type
burst thresholds); it never sees attack labels, so recall measured afterwards is honest.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from prahari_analytics.detect.features import RateTracker, source_key

# Message types whose *rate from one source* is a volumetric-attack signal, with the
# threat-model attack each targets. Benign 5G signalling does not burst these from a
# single peer; the threshold is still learned from benign so the claim is measured.
RATE_SIGNALS: dict[str, str] = {
    "NFDiscover": "SBI reconnaissance (NF discovery sweep)",
    "InitialUEMessage": "NGAP registration storm",
    "SessionEstablishmentRequest": "PFCP establishment flood",
    "SessionDeletionRequest": "PFCP deletion sweep",
    "UEContextReleaseRequest": "forged UE context release sweep",
    "NGSetupRequest": "NG Setup flood / malformed NG Setup",
    "NFRegister": "rogue NF registration",
    "NFDeregister": "NF deregistration / profile tampering",
}

WINDOW_NS = 2_000_000_000  # 2 s burst window
RATE_FLOOR = 15  # a source must exceed this many in a window even if benign never does it


@dataclass(frozen=True)
class Alert:
    rule: str
    explanation: str


@dataclass
class RuleEngine:
    window_ns: int = WINDOW_NS
    known_gnb_ids: set[int] = field(default_factory=set)
    thresholds: dict[str, int] = field(default_factory=dict)
    _rate: RateTracker = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._rate = RateTracker(self.window_ns)

    # ---------------------------------------------------------------- calibration
    def calibrate(self, benign: Iterable[dict[str, Any]]) -> RuleEngine:
        """Learn the benign baseline: known gNB ids and per-type burst thresholds."""
        events = sorted(benign, key=lambda e: int(e["ts_ns"]))
        peak: dict[str, int] = dict.fromkeys(RATE_SIGNALS, 0)
        tracker = RateTracker(self.window_ns)
        for ev in events:
            msg = ev.get("message")
            if ev.get("message") == "NGSetupRequest":
                gid = (ev.get("ngap") or {}).get("gnb_id")
                if gid is not None:
                    self.known_gnb_ids.add(int(gid))
            if msg in RATE_SIGNALS:
                count = tracker.add((source_key(ev), msg), int(ev["ts_ns"]))
                peak[msg] = max(peak[msg], count)
        # Threshold: comfortably above the benign peak, and never below a sane floor.
        self.thresholds = {m: max(peak[m] * 2 + 1, RATE_FLOOR) for m in RATE_SIGNALS}
        self._rate.reset()
        return self

    # ---------------------------------------------------------------- scoring
    def score(self, ev: dict[str, Any]) -> list[Alert]:
        alerts: list[Alert] = []
        msg = ev.get("message")
        direction = ev.get("direction")

        if ev.get("decode_status") not in ("ok", None):
            alerts.append(Alert("malformed_decode", f"decode failed: {ev['decode_status']}"))

        is_pfcp_req = ev.get("protocol") == "PFCP" and direction == "request"
        if is_pfcp_req and (ev.get("pfcp") or {}).get("session_known") is False:
            alerts.append(
                Alert("pfcp_unknown_session", f"PFCP {msg} for a session the UPF has no record of")
            )

        if msg == "NGSetupRequest":
            gid = (ev.get("ngap") or {}).get("gnb_id")
            if gid is not None and int(gid) not in self.known_gnb_ids:
                alerts.append(Alert("ngap_unknown_gnb", f"NG Setup from unknown gNB id {gid}"))

        is_sbi_req = ev.get("interface") == "SBI" and direction == "request"
        if is_sbi_req and not (ev.get("sbi") or {}).get("service"):
            alerts.append(Alert("sbi_unknown_operation", "SBI request to a non-SBI / unknown path"))

        # Volumetric: per-source, per-message-type rate over the window. No direction
        # filter -- the message name already names a specific request/indication, and its
        # response carries a different name, so responses are never counted here.
        if msg in RATE_SIGNALS:
            count = self._rate.add((source_key(ev), msg), int(ev["ts_ns"]))
            threshold = self.thresholds.get(msg, RATE_FLOOR)
            if count > threshold:
                why = f"{count} {msg}/window from one source — {RATE_SIGNALS[msg]}"
                alerts.append(Alert(f"rate_{msg}", why))
        return alerts

    def reset(self) -> None:
        self._rate.reset()


def is_attack(alerts: list[Alert]) -> bool:
    return bool(alerts)
