# Attack results — Phase 4b (N2/NGAP attacks, benign traffic, labelled dataset)

Phase 4b adds the four N2 (NGAP over SCTP) attacks, a benign traffic generator, a
campaign runner, and the labelled Parquet dataset build. Recorded 2026-11-26.

## How N2 was validated without a live AMF in the build sandbox

The build sandbox has no SCTP (kernel `Protocol not supported`), so N2 attacks could not
be fired at a live AMF here as the N4/SBI attacks were in Phase 4a. The *encoders* are
instead proven two independent ways, and the live attack is confirmed on the Docker
testbed (which has the SCTP module the gNB↔AMF link already uses).

1. **Wire compatibility with the real testbed.** pycrate's NGAP release decodes this
   testbed's own captured UERANSIM↔Open5GS PDUs (NG Setup, Initial UE Message, UE Context
   Release) and re-encodes them **byte-for-byte identical**. Anything the builders emit is
   therefore structured exactly as Open5GS already accepts.
2. **The project's own probe decodes every generated PDU.** The C++ probe's new
   `decode-ngap` / `decode-nas` read back each builder's output with the exact field
   values set — e.g. a rogue NG Setup with `gnb_id=2989` decodes to `"gnb_id":2989`, an
   Initial UE Message with `ran_ue_ngap_id=4242` to `"ran_ue_ngap_id":4242`, a
   Registration Request to `"message":"RegistrationRequest","registration_type":1`.

Both run in CI (`probe-contract` job) against the release probe.

## The four N2 attacks

All ride the attacker's own SCTP association (no IP spoofing); the "forgery" is a fake
gNB ID or another UE's AMF-UE-NGAP-ID. Observed against Open5GS v2.7.7 in the first full
dataset campaign (`campaigns/dataset.json`), 2026-11-26:

| ID | Attack | Mechanism | Observed against Open5GS v2.7.7 (no N2 security) |
|---|---|---|---|
| N2-01 | Registration storm | After NG Setup, floods Initial UE Messages with rising RAN-UE-NGAP-IDs, each a NAS Registration Request | **The AMF accepted the rogue gNB and processed the storm**: 200 Initial UE Messages each drew an authentication challenge back (Downlink NAS Transport), 502 captured events. Confirms N2 is unauthenticated here and the storm is a real signalling-plane load |
| N2-02 | Rogue gNB | NG Setup from an unauthenticated node with a chosen gNB ID | NG Setup sent; its own accept/reject verdict was suppressed by a scenario bug (below) — re-run after rebuild captures it. The storm (which starts with the same NG Setup) shows the AMF does accept the association |
| N2-03 | Forged UE release | From the rogue gNB, sweeps UE Context Release Requests across AMF-UE-NGAP-IDs | 48-ID sweep sent and captured (98 events) |
| N2-04 | Malformed NGAP fuzz | Seeded mutations of valid PDUs + random bytes over SCTP | 400 malformed PDUs sent; the AMF stayed up (the rest of the campaign ran against it afterwards), 750 captured events |

### Bug found and fixed: NG Setup verdict suppressed by premature close

The first N2-02 manifest read `"setups": ["no response"]` with only the 3 outbound NG
Setup Requests captured. Root cause: `_ng_setup` did a single `recv()`, and a fresh SCTP
association delivers the `COMM_UP` **notification** first — read as "no response", which
closed the association before the AMF's NG Setup Response reached the wire. The storm hid
it (it keeps the association open and floods, so its `_drain` collects the response). Fixed
by looping until a real NGAP reply decodes or the budget expires (regression test
`test_ng_setup_skips_a_leading_notification_before_the_response`). The dataset labels are
unaffected — labelling is by attacker address and window, not by the verdict.

## Benign traffic and campaigns

- The benign generator drives the UEs through PDU session establish/release and status
  polls via `nr-cli`, so the dataset's "normal" class is live N4/N2/5GSM signalling.
- `prahari-campaign` runs benign traffic continuously while firing a timed attack
  sequence, so attacks are captured inside realistic traffic (`campaigns/dataset.json`).

## Dataset pipeline

`prahari-dataset` flattens labelled events into 40 typed columns and writes Parquet + a
dataset card (provenance, labelling method, class balance, column dictionary, limits).

First full campaign on the testbed (`campaigns/dataset.json`, 2026-11-26): **12,015 rows ×
40 columns**, 5,090 attack / 6,925 benign (42.4% attack), all 9 attack classes present,
every line schema-validated. By interface: SBI 5,639, N4 4,107, N2 2,269. The benign class
is live PDU-session churn, not padding. `scripts/dataset-run.sh` produces
`runs/<name>/dataset.parquet` + `dataset-card.md`; CI runs a short campaign and asserts the
Parquet is non-empty and carries attack labels.

## Reproduce on the testbed

```bash
cd testbed
docker compose down && docker compose build probe && docker compose up -d   # probe 0.6.0
bash scripts/smoke.sh                       # 10/10
bash scripts/attack-check.sh                # now includes N2-02/N2-01/N2-04
bash scripts/dataset-run.sh campaigns/dataset.json   # full labelled dataset
```
