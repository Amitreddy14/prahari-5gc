"""Adversarial robustness: how much detection survives an adaptive attacker.

The threat model's Phase-6 adversary knows a detector exists and shapes rate, timing and
ordering to evade it while staying protocol-compliant. Each such evasion defeats specific
signals: pacing under the thresholds silences the volumetric rules and the window-outlier
layer; spoofing a known gNB id silences the unknown-gNB rule; deleting only real sessions
silences the unknown-session rule; well-formed payloads silence the decode-failure rule.

This models each evasion by dropping the signals it defeats (an ablation over the already
calibrated ensemble) and re-measures. An attack that is still detected after an evasion is
caught by a signal that evasion cannot remove -- which is the robustness result: the
rate/statistical layers are evadable, the protocol-state rules are the backbone that holds
unless the attacker also changes what the attack *does* (and so weakens it).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from prahari_analytics.detect.eval import Detector, EvalResult, evaluate
from prahari_analytics.detect.rules import Alert

# An evasion -> the signal names (exact, or `prefix_*`) it defeats.
EVASIONS: dict[str, tuple[str, ...]] = {
    "low_and_slow": ("rate_*", "isoforest"),  # pace under thresholds; windows stay quiet
    "spoof_known_gnb": ("ngap_unknown_gnb",),  # present a legitimate gNB id
    "target_valid_sessions": ("pfcp_unknown_session",),  # delete only real sessions
    "well_formed_payloads": ("malformed_decode", "sbi_unknown_operation"),
    "mimicry_cover_traffic": ("isoforest", "sequence"),  # pad with benign-looking messages
    # A capable adversary combining the protocol-compliant evasions at once.
    "combined_adaptive": ("rate_*", "isoforest", "ngap_unknown_gnb", "sequence"),
}

# What each evasion costs the attacker. This is the honest half of the result: a signal being
# "evadable" does not make it worthless -- some evasions are free (just pace/pad the traffic),
# while others force reconnaissance or make the attack weaker/narrower, which is itself a win
# for the defender.
EVASION_COST: dict[str, str] = {
    "low_and_slow": "free — only slows the attack down",
    "spoof_known_gnb": "needs recon: a valid gNB id the AMF already trusts",
    "target_valid_sessions": "needs recon: live SEIDs, and only touches sessions that exist",
    "well_formed_payloads": "blunts the attack: a fuzzer that stops sending malformed PDUs",
    "mimicry_cover_traffic": "free, but cannot hide message *types* the attack must send",
    "combined_adaptive": "every free/recon evasion at once (still not well-formed payloads)",
}


def _matches(rule: str, patterns: tuple[str, ...]) -> bool:
    for p in patterns:
        if p.endswith("*") and rule.startswith(p[:-1]):
            return True
        if rule == p:
            return True
    return False


@dataclass
class AblatedDetector:
    """Wraps a detector and hides the alerts an evasion would defeat. calibrate/reset and the
    batched path delegate unchanged, so only the surviving signals decide detection."""

    inner: Detector
    drop: tuple[str, ...]

    def calibrate(self, benign: Any) -> AblatedDetector:
        self.inner.calibrate(benign)
        return self

    def reset(self) -> None:
        self.inner.reset()

    def _filter(self, alerts: list[Alert]) -> list[Alert]:
        return [a for a in alerts if not _matches(a.rule, self.drop)]

    def score(self, ev: dict[str, Any]) -> list[Alert]:
        return self._filter(self.inner.score(ev))

    def score_all(self, rows: list[dict[str, Any]]) -> list[list[Alert]]:
        batch = getattr(self.inner, "score_all", None)
        inner = list(batch(rows)) if callable(batch) else [self.inner.score(e) for e in rows]
        return [self._filter(a) for a in inner]


def robustness(
    events: list[dict[str, Any]],
    build: Callable[[], Detector],
    *,
    train_frac: float = 0.4,
    evasions: dict[str, tuple[str, ...]] = EVASIONS,
) -> dict[str, EvalResult]:
    """Baseline plus one ablation per evasion. `build` returns a fresh ensemble each call."""
    results = {"baseline": evaluate(events, build(), train_frac)}
    for name, drop in evasions.items():
        results[name] = evaluate(events, AblatedDetector(build(), drop), train_frac)
    return results


def robustness_markdown(results: dict[str, EvalResult]) -> str:
    attacks = sorted({r.attack_id for res in results.values() for r in res.runs})
    detected: dict[str, dict[str, bool]] = {
        name: {r.attack_id: r.detected for r in res.runs} for name, res in results.items()
    }
    lines = [
        "# Adversarial robustness — detection under adaptive evasion",
        "",
        "Each column is an evasion; a ✓ means the attack is still detected once the signals",
        "that evasion defeats are removed. Fewer ✓ down a column = a more effective evasion.",
        "",
        "| attack | " + " | ".join(results) + " |",
        "| --- | " + " | ".join("---" for _ in results) + " |",
    ]
    for aid in attacks:
        row = [aid] + ["✓" if detected[name].get(aid) else "✗" for name in results]
        lines.append("| " + " | ".join(row) + " |")
    lines += [
        "",
        "## Detection rate (attacks caught / total), false positives, and attacker cost",
        "",
    ]
    lines += [
        "| evasion | attacks detected | recall | held-out FP | cost to the attacker |",
        "| --- | --- | ---: | ---: | --- |",
    ]
    for name, res in results.items():
        cost = "—" if name == "baseline" else EVASION_COST.get(name, "")
        lines.append(
            f"| {name} | {res.runs_detected}/{len(res.runs)} | {res.recall:.3f} "
            f"| {res.fp_rate:.2%} | {cost} |"
        )
    lines.append("")
    return "\n".join(lines)
