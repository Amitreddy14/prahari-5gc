# Robustness results — Phase 6 (detection under an adaptive attacker)

Phase 5 measured detection against attacks that do not know a detector is watching. A real
adversary does. This phase asks the harder question: **how much detection survives once the
attacker shapes the attack to evade the signals it can see?**

We model each evasion as an *ablation* over the already-calibrated ensemble — remove the
alerts the evasion defeats, then re-measure. This is sound because every signal is causal and
independent: an attacker who paces under the rate thresholds removes exactly the `rate_*`
alerts and nothing else; the remaining layers decide detection on their own. An attack still
caught after an evasion is caught by a signal that evasion *cannot* remove. Measured on
`prahari-dataset-v1` (12,015 events, 9 attack runs + benign), 2026-11-27.
Reproduce with `prahari-detect --events labelled.jsonl --robustness`.

## Which attacks survive each evasion

A ✓ means the attack is still detected once the evaded signals are removed.

| attack | baseline | low_and_slow | spoof_known_gnb | target_valid_sessions | well_formed_payloads | mimicry_cover_traffic | combined_adaptive |
| --- | --- | --- | --- | --- | --- | --- | --- |
| N2-01 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| N2-02 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| N2-03 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| N2-04 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | **✓** |
| N4-01 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | **✓** |
| N4-03 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| SBI-01 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| SBI-02 | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ |
| SBI-04 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | **✓** |

## Detection rate, false positives, and what each evasion costs the attacker

| evasion | detected | recall | held-out FP | cost to the attacker |
| --- | --- | ---: | ---: | --- |
| baseline | 9/9 | 0.988 | 1.88% | — |
| low_and_slow | 9/9 | 0.933 | 0.00% | free — only slows the attack down |
| spoof_known_gnb | 9/9 | 0.988 | 1.88% | recon: a valid gNB id the AMF already trusts |
| target_valid_sessions | 9/9 | 0.988 | 1.88% | recon: live SEIDs, and only touches sessions that exist |
| well_formed_payloads | 9/9 | 0.988 | 1.88% | blunts the attack: a fuzzer that stops sending malformed PDUs |
| mimicry_cover_traffic | 8/9 | 0.474 | 0.00% | free, but cannot hide the message *types* the attack must send |
| combined_adaptive | **3/9** | 0.270 | 0.00% | every free/recon evasion at once (still not well-formed payloads) |

## What this says

**No single evasion defeats detection.** Every attack is caught by more than one independent
signal, so removing one layer is never enough — `low_and_slow` strips the entire volumetric
and window-outlier side of the system and still leaves 9/9, because the sequence layer and the
protocol-state rules are untouched by timing. The attacker's recall-erosion (0.988 → 0.933) is
real but buys nothing on its own: the attack is still flagged.

**The layers fail in a revealing order.** `mimicry_cover_traffic` (dropping the statistical +
sequence layers) is the first to lose an attack — SBI-02, the rogue-NF registration, which
*only* the behavioural layers ever caught; no protocol rule fires on it (the 5a blind spot).
Then `combined_adaptive` — a capable adversary who paces slowly, pads with cover traffic,
spoofs a trusted gNB id, and defeats the sequence model all at once — collapses detection to
**3/9**.

**The three that survive are the point.** N2-04, N4-01 and SBI-04 hold under the full combined
evasion because each carries an *irreducible* protocol-semantic signature:

- **N4-01** references a PFCP session the core never established → `pfcp_unknown_session`.
- **N2-04** sends NGAP that does not decode against the ASN.1 grammar → `malformed_decode`.
- **SBI-04** calls a service operation no NF exposes → `sbi_unknown_operation`.

These are not statistical outliers that cover traffic can dilute, nor rates that pacing can
hide. They are statements about protocol *state and content*. The only way to make them stop
firing is `target_valid_sessions` (know live SEIDs) and `well_formed_payloads` (stop fuzzing)
— and those two "evasions" are the two that change what the attack *does*: a blind SEID scan
that only touches real sessions is no longer a scan, and a fuzzer that only sends valid PDUs is
no longer a fuzzer. **Evading the backbone costs the attacker the attack.**

## The headline

The rate and statistical layers are cheap to evade and should be treated as *recall*, not as
*guarantees*. The protocol-state rules are the backbone: rate-invariant, timing-invariant,
cover-traffic-invariant, and evadable only by an attacker who already has the reconnaissance
the attack was trying to obtain, or who weakens the attack into something benign. Defense in
depth here is not three redundant alarms — it is three *different kinds* of signal, so that
silencing the evadable ones leaves the un-evadable ones exposed.

## Honest limits

- **Ablation is an upper bound on the attacker, not a perfect model.** It assumes an evasion
  removes a signal cleanly and for free. `low_and_slow` in reality still has to complete the
  attack, so "pace indefinitely" trades evasion for dwell time a longer window would catch;
  the model credits the attacker the whole evasion at zero cost.
- **The sequence layer's robustness is borrowed from benign narrowness.** It survives most
  single evasions only because the benign vocabulary is small (~9 message types); in a busier
  network those "novel" messages would be less novel, and the layer would behave more like the
  evadable statistical one. The combined evasion already assumes this away (it drops sequence).
- **Single campaign.** Same caveat as Phase 5b: these are one benign/attack mix. The ranking of
  layers is the durable finding; the exact recall numbers are not.
- The evasive campaign spec (`testbed/campaigns/evasive.json`) encodes these same evasions as
  *runnable* attack variants (low-rate, spoofed gNB id, valid-SEID-targeted, benign-cover), so
  the ablation can be checked against live traffic once the testbed is up — the ablation
  predicts the outcome; the campaign is how you falsify it.
