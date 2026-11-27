"""Statistical, sequence and ensemble layers, the streaming scorer, and cross-campaign eval.

These need numpy/scikit-learn (the analytics `detect`/`dev` extras)."""

from __future__ import annotations

import random
from typing import Any

from prahari_analytics.detect.ensemble import Ensemble
from prahari_analytics.detect.eval import evaluate, evaluate_cross
from prahari_analytics.detect.isoforest import IsolationForestDetector
from prahari_analytics.detect.sequence import SequenceDetector
from prahari_analytics.detect.stream import StreamScorer

S = 1_000_000_000
BENIGN_MSGS = ["NFUpdate", "HeartbeatRequest", "HeartbeatResponse", "Authenticate"]


def ev(
    ts_s: float, message: str, *, attack: bool = False, aid: str = "SBI-99", **over: Any
) -> dict:
    e: dict[str, Any] = {
        "ts_ns": int(ts_s * S),
        "interface": over.pop("interface", "SBI"),
        "protocol": over.pop("protocol", "HTTP2"),
        "message": message,
        "direction": over.pop("direction", "request"),
        "decode_status": over.pop("decode_status", "ok"),
        "size_bytes": over.pop("size_bytes", 100),
        "src": {"ip": over.pop("src_ip", "172.22.0.10"), "port": 1},
        "dst": {"ip": "172.22.0.5", "port": 1},
    }
    e.update(over)
    e["labels"] = (
        {"is_attack": True, "attack_id": aid, "run_id": f"{aid}-r"}
        if attack
        else {"is_attack": False}
    )
    return e


def benign_stream(n: int = 600, seed: int = 0, start: float = 0.0) -> list[dict]:
    """Realistic multi-interface benign: SBI NF management plus a trickle of N4 session
    activity, so the feature space (rates, SEID fan-out, message mix) has natural variance
    the Isolation Forest can learn -- a pure single-interface stream is degenerate for it."""
    rng = random.Random(seed)
    sbi_srcs = ["172.22.0.10", "172.22.0.11"]
    rows: list[dict] = []
    for i in range(n):
        t = start + i * 0.5 + rng.random() * 0.1
        if i % 4 == 0:  # some benign N4 session traffic from the SMF (known sessions)
            rows.append(
                ev(
                    t,
                    rng.choice(["SessionModificationRequest", "SessionReportRequest"]),
                    interface="N4",
                    protocol="PFCP",
                    src_ip="172.22.0.7",
                    pfcp={"session_known": True},
                    ue={"seid": str(rng.randint(1, 8))},
                )
            )
        else:
            rows.append(ev(t, rng.choice(BENIGN_MSGS), src_ip=rng.choice(sbi_srcs)))
    return rows


def burst_attack(start: float, n: int = 120) -> list[dict]:
    # A realistic PFCP establishment flood exchange: request+response pairs, varied sizes,
    # many distinct SEIDs. It shifts several benign-varying features at once (rate, response
    # ratio, SEID fan-out, size), which is the *distributed* anomaly Isolation Forest is for
    # -- unlike a one-feature spike, which is the rules layer's job.
    rng = random.Random(7)
    rows: list[dict] = []
    for i in range(n):
        t = start + i * 0.01
        rows.append(
            ev(
                t,
                "SessionEstablishmentRequest",
                interface="N4",
                protocol="PFCP",
                src_ip="172.22.0.40",
                size_bytes=rng.randint(200, 600),
                ue={"seid": str(1000 + i)},
                attack=True,
                aid="N4-03",
            )
        )
        rows.append(
            ev(
                t + 0.002,
                "SessionEstablishmentResponse",
                interface="N4",
                protocol="PFCP",
                direction="response",
                src_ip="172.22.0.8",
                size_bytes=rng.randint(80, 200),
                ue={"seid": str(1000 + i)},
                attack=True,
                aid="N4-03",
            )
        )
    return rows


def test_isoforest_flags_a_distributed_anomaly() -> None:
    # IF's strength is windows that are unusual across many features at once (a flood with
    # responses, varied sizes, wide SEID fan-out), not one-feature spikes (those are rules').
    events = benign_stream() + burst_attack(start=400)
    res = evaluate(events, IsolationForestDetector(benign_fp=0.05), train_frac=0.4)
    assert res.runs_detected == 1
    assert res.fp_rate < 0.15


def test_sequence_flags_an_unseen_transition() -> None:
    eng = SequenceDetector(benign_fp=0.01).calibrate(benign_stream())
    eng.reset()
    # A message the benign vocabulary never contained -> high surprisal.
    alerts = eng.score(
        ev(999, "NGSetupRequest", interface="N2", protocol="NGAP", src_ip="172.22.0.40")
    )
    assert any(a.rule == "sequence" for a in alerts)


def test_ensemble_detects_what_a_single_layer_misses() -> None:
    events = benign_stream() + burst_attack(start=400)
    ens = Ensemble(
        isoforest=IsolationForestDetector(benign_fp=0.02), sequence=SequenceDetector(benign_fp=0.02)
    )
    res = evaluate(events, ens, train_frac=0.4)
    assert res.runs_detected == 1
    assert res.recall > 0.0


def test_stream_scorer_emits_layer_tagged_alerts() -> None:
    benign = benign_stream()
    scorer = StreamScorer.calibrated_on(benign, benign_fp=0.02)
    alerts = list(scorer.alerts(burst_attack(start=400, n=60)))
    assert alerts
    assert all("layers" in a and a["alerts"] for a in alerts)


def test_evaluate_cross_campaign() -> None:
    # Calibrate on campaign A (benign only), evaluate on campaign B (benign + attack).
    train = benign_stream(seed=1)
    test = benign_stream(seed=2, start=0.0) + burst_attack(start=400)
    res = evaluate_cross(
        train,
        test,
        Ensemble(
            isoforest=IsolationForestDetector(benign_fp=0.02),
            sequence=SequenceDetector(benign_fp=0.02),
        ),
    )
    assert res.runs_detected == 1
    assert res.benign_heldout > 0  # every test benign event counts toward FP
