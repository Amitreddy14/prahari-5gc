"""Detection layer: features, rules, and the evaluation harness."""

from __future__ import annotations

from typing import Any

from prahari_analytics.detect.eval import evaluate, results_markdown
from prahari_analytics.detect.features import FanoutTracker, RateTracker, event_features
from prahari_analytics.detect.rules import RuleEngine, is_attack

S = 1_000_000_000


def ev(ts_s: float, message: str, **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "ts_ns": int(ts_s * S),
        "interface": over.pop("interface", "N4"),
        "protocol": over.pop("protocol", "PFCP"),
        "message": message,
        "direction": over.pop("direction", "request"),
        "decode_status": over.pop("decode_status", "ok"),
        "size_bytes": over.pop("size_bytes", 40),
        "src": {"ip": over.pop("src_ip", "172.22.0.40"), "port": 8805},
        "dst": {"ip": "172.22.0.8", "port": 8805},
    }
    base.update(over)
    return base


# ---------------------------------------------------------------- features
def test_rate_tracker_slides() -> None:
    rt = RateTracker(2 * S)
    assert rt.add("k", 0) == 1
    assert rt.add("k", 1 * S) == 2
    assert rt.add("k", 5 * S) == 1  # the earlier two fell out of the 2 s window


def test_fanout_counts_distinct_values_in_window() -> None:
    ft = FanoutTracker(2 * S)
    ft.add("k", "a", 0)
    ft.add("k", "b", 0)
    assert ft.add("k", "a", 1 * S) == 2  # a, b
    assert ft.add("k", "c", 10 * S) == 1  # window slid, only c


def test_event_features_carry_no_identity() -> None:
    feats = event_features(ev(1, "SessionDeletionRequest", src_ip="172.22.0.40"))
    joined = " ".join(str(v) for v in feats.values())
    assert "172.22.0.40" not in joined  # no address leaks into features
    assert feats["protocol"] == "PFCP"


# ---------------------------------------------------------------- rules
def test_malformed_decode_fires() -> None:
    eng = RuleEngine()
    alerts = eng.score(ev(1, "InitialUEMessage", protocol="NGAP", decode_status="malformed"))
    assert any(a.rule == "malformed_decode" for a in alerts)


def test_pfcp_unknown_session_fires() -> None:
    eng = RuleEngine()
    alerts = eng.score(ev(1, "SessionDeletionRequest", pfcp={"session_known": False}))
    assert any(a.rule == "pfcp_unknown_session" for a in alerts)


def test_unknown_gnb_fires_only_for_unlearned_id() -> None:
    eng = RuleEngine()
    eng.calibrate([ev(0, "NGSetupRequest", protocol="NGAP", interface="N2", ngap={"gnb_id": 1})])
    assert eng.known_gnb_ids == {1}
    n2 = {"protocol": "NGAP", "interface": "N2"}
    known = eng.score(ev(1, "NGSetupRequest", ngap={"gnb_id": 1}, **n2))
    rogue = eng.score(ev(2, "NGSetupRequest", ngap={"gnb_id": 999}, **n2))
    assert not any(a.rule == "ngap_unknown_gnb" for a in known)
    assert any(a.rule == "ngap_unknown_gnb" for a in rogue)


def test_rate_rule_fires_on_a_burst_not_a_trickle() -> None:
    eng = RuleEngine().calibrate([])  # empty baseline -> floor threshold (15)
    eng.reset()
    fired = False
    for i in range(30):
        disc = ev(
            0.01 * i, "NFDiscover", interface="SBI", protocol="HTTP2", sbi={"service": "nnrf-disc"}
        )
        fired = any(a.rule == "rate_NFDiscover" for a in eng.score(disc))
    assert fired  # 30 in a 2 s window exceeds the floor


def test_identity_does_not_change_the_verdict() -> None:
    # Same behaviour from a "legit" NF address must score the same as from the attacker.
    eng = RuleEngine().calibrate([])
    eng.reset()
    a = [
        is_attack(
            eng.score(
                ev(
                    0.01 * i,
                    "SessionDeletionRequest",
                    pfcp={"session_known": False},
                    src_ip="172.22.0.7",
                )
            )
        )
        for i in range(5)
    ]
    assert all(a)  # unknown-session rule fires regardless of who sent it


# ---------------------------------------------------------------- eval
def _stream() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    # benign baseline: a trickle of heartbeats
    for i in range(40):
        rows.append(
            ev(i * 0.1, "HeartbeatRequest", src_ip="172.22.0.7", labels={"is_attack": False})
        )
    # attack: a deletion sweep of unknown sessions
    for i in range(40):
        rows.append(
            ev(
                5 + i * 0.01,
                "SessionDeletionRequest",
                pfcp={"session_known": False},
                labels={"is_attack": True, "attack_id": "N4-01", "run_id": "N4-01-x"},
            )
        )
    return rows


def test_evaluate_detects_the_attack_with_no_false_positives() -> None:
    res = evaluate(_stream(), RuleEngine(), train_frac=0.4)
    assert res.runs_detected == 1
    assert res.precision == 1.0
    assert res.fp_rate == 0.0
    assert res.runs[0].detected
    assert res.runs[0].latency_s is not None


def test_results_markdown_has_headline_and_table() -> None:
    md = results_markdown(evaluate(_stream(), RuleEngine()))
    assert "Attacks detected" in md
    assert "N4-01" in md
    assert "Precision" in md
