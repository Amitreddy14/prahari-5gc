# Detection results — Phase 5a (rules layer)

The first detection layer: explainable, high-precision rules over the probe's event stream.
Measured on the Phase 4b dataset (`prahari-dataset-v1`, 12,015 events, 9 attack runs + benign),
2026-11-27. Reproduce with `prahari-detect --events labelled.jsonl`.

## Method, and the trap it avoids

The dataset is labelled by the attacker's address (172.22.0.40), which appears in 1,490
attack events and only 3 benign ones. So a detector that used "is this the attacker's IP"
would score ~perfectly while learning nothing. Every rule here is **identity-free**: events
are grouped by source entity to measure its behaviour, but no address or NF-role is a
feature. A rule fires on *what an entity did* — a burst, a protocol-state violation, a
decode failure — so it would flag a compromised real NF behaving the same way.

Calibration (per-message-type burst thresholds, the set of known gNB ids) uses benign
traffic from the first 40% of the timeline only; it never sees attack labels. False
positives are measured on the held-out benign after that point.

## Headline

- **Attacks detected (≥1 alert in the run): 8 / 9**
- **Precision 1.000 · Recall 0.474 · F1 0.644** (per event, attack vs benign)
- **False-positive rate on held-out benign: 0.000%** (0 / 2,766)
- First-alert latency ≤ 0.30 s for every detected attack

## Per attack

| attack | detected | latency | events flagged | the rule that caught it |
|---|---|---:|---:|---|
| N4-01 session deletion | ✓ | 0.00 s | 1024/2048 | `pfcp_unknown_session` (every deletion hit a session the UPF never had) + `rate_SessionDeletionRequest` |
| N4-03 establishment flood | ✓ | 0.10 s | 570/1204 | `rate_SessionEstablishmentRequest` |
| N2-01 registration storm | ✓ | 0.00 s | 186/502 | `rate_InitialUEMessage` |
| N2-02 rogue gNB | ✓ | 0.00 s | 3/3 | `ngap_unknown_gnb` |
| N2-03 forged UE release | ✓ | 0.00 s | 34/98 | `rate_UEContextReleaseRequest` |
| N2-04 malformed NGAP | ✓ | 0.00 s | 354/750 | `malformed_decode` + `ngap_unknown_gnb` |
| SBI-01 NRF recon | ✓ | 0.30 s | 154/204 | `rate_NFDiscover` |
| SBI-04 SBI fuzz | ✓ | 0.04 s | 90/269 | `sbi_unknown_operation` |
| SBI-02 rogue NF registration | ✗ | — | 0/12 | — (see below) |

## Reading the numbers honestly

- **Per-event recall (0.47) understates detection.** The labeller marks *both directions*
  of an attack exchange — the attacker's messages and the victim NF's responses. The rules
  flag the malicious requests (N4-01 **100%** of deletion requests, N4-03 **95%** of
  establishments) but correctly do **not** flag the UPF/AMF's own replies, which look
  normal. That is why all-event recall sits near 50% while every attack is still caught.
- **The one miss, SBI-02, is the honest result.** A rogue NF registration is a handful of
  well-formed NFRegister/NFUpdate calls — indistinguishable by behaviour from a legitimate
  NF joining, against a benign stream that contains 3,758 NFUpdate messages. Catching it
  needs NF-identity allowlisting (an authentication control), not anomaly detection. The
  rules layer is right to stay silent rather than guess.
- **Precision is perfect here partly because the benign class is narrow.** Benign and
  attack share only 4 of ~70 message types; the benign generator does PDU-session churn and
  NF management, not registration storms or SEID scans (which genuinely do not occur in
  normal operation). So the 0% false-positive rate is real but optimistic — a production
  network has legitimate bursts (a tracking-area-update storm after an outage) this dataset
  does not model. This is a single campaign; cross-campaign evaluation is Phase 5b.

## What each rule is

| rule | fires on | threat-model cue |
|---|---|---|
| `malformed_decode` | any event the probe could not fully decode | N2-04, SBI-04 fuzzing |
| `pfcp_unknown_session` | PFCP modify/delete for a SEID the UPF never established | N4-01, N4-02 |
| `ngap_unknown_gnb` | NG Setup from a gNB id not in the benign baseline | N2-02, N2-04 |
| `sbi_unknown_operation` | SBI request to a non-SBI / unknown path | SBI-04 |
| `rate_<message>` | one source exceeding the benign per-type burst threshold | volumetric: N4-03, N2-01, N2-03, SBI-01 |

## Next (5b)

The Isolation Forest and the sequence model extend this on the same harness: the statistical
layer should raise recall on the diluted response traffic and on slow attacks, and a
cross-campaign split (several campaigns, held-out) will replace the single-campaign
calibration here. SBI-02 stays a known behavioural blind spot, documented as an auth gap.
