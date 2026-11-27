# Detection results — Phase 5b (statistical + sequence layers, ensemble)

Two more detection layers on the Phase 5a harness — an Isolation Forest over windowed
behavioural features, and a message-transition (sequence) model — fused with the rules into
an ensemble, plus a streaming scorer. All identity-free (no source address is a feature).
Measured on `prahari-dataset-v1` (12,015 events, 9 attack runs + benign), 2026-11-27.
Reproduce with `prahari-detect --events labelled.jsonl --compare`.

## Comparison

| detector | attacks detected | precision | recall | F1 | held-out FP |
|---|---|---:|---:|---:|---:|
| rules | 8/9 | 1.000 | 0.474 | 0.644 | 0.00% |
| isoforest | 5/9 | 0.846 | 0.361 | 0.506 | 1.88% |
| sequence | 9/9 | 0.993 | 0.933 | 0.962 | 0.00% |
| **ensemble** | **9/9** | **0.932** | **0.988** | **0.959** | **1.88%** |

The headline is the ensemble: **9/9 attacks, F1 0.959** — it catches SBI-02, the rogue NF
registration the rules layer alone missed in 5a, because the sequence layer flags its
improbable control-plane transition. No single layer is best at everything; fusing them is.

## What each layer is, and what its number really means

- **Rules** (5a): precise, explainable protocol/volumetric checks. Perfect precision, and
  the floor the others build on.
- **Isolation Forest**: trained on benign windows, flags windows that are statistically odd
  across many features at once. It is the weakest here (5/9) and that is informative — two
  engineering findings came out of it:
  - It can only isolate on features that **vary in benign**; a feature that is always 0 in
    benign (e.g. "unknown-session ratio") gives the forest no split to make, so those binary
    signals are the rules' job, not the forest's. The detector now drops zero-variance
    features before fitting.
  - It misses anomalies that **spike on one or two features** (a pure rate burst) — those
    get averaged away across the irrelevant dimensions. Its niche is *distributed* anomalies
    (a flood that shifts rate, response ratio, fan-out and size together), which is what it
    did catch (N4-03, N2-01). This is exactly why the layered design exists.
- **Sequence** (message-transition model): learns, per interface, how likely each message is
  to follow the previous one from the same source, as benign add-k-smoothed bigram
  probabilities; an event's surprisal is `-log2` of that, and a message type never seen in
  benign is maximally surprising. It names the improbable transition, so it stays explainable.

## Honest reading of the sequence score

The sequence model's 0.962 F1 is strong **but optimistic for a specific reason**: on this
dataset the attacks use message types benign never does — benign is PDU-session churn and NF
management (~9 message types), attacks bring 66 others. So "novel message type" alone
separates most attacks, and the sequence model is partly acting as a vocabulary allowlist.
That is a real anomaly signal, but its strength here reflects the **benign generator's narrow
vocabulary**, not a guarantee that these attacks are detectable against richer normal
traffic. In production, legitimate-but-rare procedures would be "novel" too and cost false
positives. The robust part of the model — improbable *orders of known messages* — needs
richer benign to show its value.

This is the same single-campaign limitation as 5a, amplified. The harness already supports
the fix (`evaluate_cross`: calibrate on some campaigns, test on held-out ones); it just needs
2–3 more campaigns with different benign seeds, which is the remaining 5b data task.

## Streaming scorer

`prahari-detect-stream --calibrate benign.jsonl --events -` calibrates the ensemble once
then scores a live stream (a file or stdin / `tail -f` / a Kafka consumer), emitting one
alert per flagged event with the layers that fired and their explanations, e.g.
`improbable transition NFUpdate -> NFListRetrieval (12.8 bits)` or
`window is a statistical outlier (score -0.145)`. Each layer's `score()` is causal, so the
same code that the harness evaluates offline runs online unchanged.

## Limits and next

- One campaign; the sequence and rules numbers are optimistic for the benign-narrowness
  reason above. Cross-campaign evaluation (held-out campaigns) is the real generalization
  test and is wired but needs more data.
- The Isolation Forest would benefit from richer benign variance; its contamination
  threshold trades false positives for recall (reported at `benign_fp=0.01`).
- An LSTM/transformer sequence model is the richer variant once several campaigns exist; the
  Markov model is the honest, non-overfitting choice on one campaign (ADR-0009, 5b note).
