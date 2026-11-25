# ADR-0004: Python analytics with layered detection

- Status: Accepted
- Date: 2026-11-25

## Context
Detection must be explainable to an analyst, measurable, and strong enough to
publish. A single deep model is hard to trust; rules alone are easy to evade.

## Decision
Python 3.11+ (pydantic, scikit-learn, PyTorch on the RTX 4060). Three layers,
each scored and reported separately, then combined:

1. **Rules**: protocol-state and baseline violations (e.g. deletion for a SEID never established; NG Setup from an unknown node). High precision, explainable.
2. **Statistical**: Isolation Forest on windowed features (rates, fan-out, error ratios per peer/UE).
3. **Sequence model**: per-UE / per-session message sequences (LSTM or small transformer) scoring how unlikely a sequence is under benign behaviour.

Evaluation splits are by run and by time, never random over events. Phase 6
attacks each layer adaptively and reports the drop.

## Consequences
- The "detector badge" in the console shows which layer fired.
- More moving parts, but each layer is independently testable and comparable to published baselines.
