"""Adversarial-robustness ablation: detection measured after an evasion removes the signals
it defeats. Reuses the benign/flood fixtures from the ML detection tests."""

from __future__ import annotations

from prahari_analytics.detect.ensemble import Ensemble
from prahari_analytics.detect.isoforest import IsolationForestDetector
from prahari_analytics.detect.robustness import (
    EVASIONS,
    AblatedDetector,
    _matches,
    robustness,
    robustness_markdown,
)
from prahari_analytics.detect.rules import Alert, RuleEngine
from prahari_analytics.detect.sequence import SequenceDetector
from test_detect_ml import benign_stream, burst_attack


def _build() -> Ensemble:
    return Ensemble(
        rules=RuleEngine(),
        isoforest=IsolationForestDetector(benign_fp=0.05),
        sequence=SequenceDetector(benign_fp=0.05),
    )


def test_matches_exact_and_prefix() -> None:
    assert _matches("isoforest", ("isoforest",))
    assert _matches("rate_SessionEstablishmentRequest", ("rate_*",))
    assert not _matches("rate_x", ("isoforest",))
    assert not _matches("sequence", ("rate_*",))


def test_ablated_detector_hides_the_named_signals() -> None:
    inner = RuleEngine()
    dropped = AblatedDetector(inner, drop=("isoforest", "rate_*"))

    def alert(rule: str) -> Alert:
        return Alert(rule=rule, explanation="x")

    kept = dropped._filter(
        [alert("isoforest"), alert("rate_SessionEstablishmentRequest"), alert("sequence")]
    )
    assert [a.rule for a in kept] == ["sequence"]


def test_baseline_catches_the_flood_but_full_ablation_does_not() -> None:
    events = benign_stream() + burst_attack(start=400)
    # The flood is caught by the volumetric rules, the window-outlier layer and the novel-
    # message layer; strip all three and nothing protocol-semantic is left to catch it.
    results = robustness(
        events, _build, train_frac=0.4, evasions={"kill_all": ("rate_*", "isoforest", "sequence")}
    )
    assert results["baseline"].runs_detected == 1
    assert results["kill_all"].runs_detected == 0
    assert results["kill_all"].recall < results["baseline"].recall


def test_default_evasions_run_and_render() -> None:
    events = benign_stream() + burst_attack(start=400)
    results = robustness(events, _build, train_frac=0.4)
    assert set(results) == {"baseline", *EVASIONS}
    md = robustness_markdown(results)
    assert "N4-03" in md
    assert "combined_adaptive" in md
    assert "cost to the attacker" in md
