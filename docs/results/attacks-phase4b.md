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
gNB ID or another UE's AMF-UE-NGAP-ID. Fill the "observed" column from the testbed run
(`scripts/attack-check.sh` for the non-destructive ones, `scripts/dataset-run.sh` for the
full set).

| ID | Attack | Mechanism | Expected against Open5GS v2.7.7 (no N2 security) |
|---|---|---|---|
| N2-02 | Rogue gNB | NG Setup from an unauthenticated node with a chosen gNB ID | Accepted: with no IPsec/NDS on N2, the AMF trusts any peer that completes SCTP, so the rogue base station can then speak for UEs |
| N2-01 | Registration storm | After NG Setup, floods Initial UE Messages with rising RAN-UE-NGAP-IDs, each a NAS Registration Request | Each ID allocates a RAN UE context and starts authentication (AUSF/UDM vector fetch): a signalling-plane DoS; contexts time out if left |
| N2-03 | Forged UE release | From the rogue gNB, sweeps UE Context Release Requests across AMF-UE-NGAP-IDs | A correct AMF rejects release of a context not on this association; the run records honoured vs rejected (destructive if honoured — dataset-only) |
| N2-04 | Malformed NGAP fuzz | Seeded mutations of valid PDUs + random bytes over SCTP | A robust AMF answers Error Indication or ignores; a crash or dropped association is a finding |

## Benign traffic and campaigns

- The benign generator drives the UEs through PDU session establish/release and status
  polls via `nr-cli`, so the dataset's "normal" class is live N4/N2/5GSM signalling.
- `prahari-campaign` runs benign traffic continuously while firing a timed attack
  sequence, so attacks are captured inside realistic traffic (`campaigns/dataset.json`).

## Dataset pipeline

`prahari-dataset` flattens labelled events into 40 typed columns and writes Parquet + a
dataset card (provenance, labelling method, class balance, column dictionary, limits).

End-to-end check in the build sandbox on **687 real probe events** (the N2/N4/SBI
fixtures), labelled against a run manifest: 687 rows × 40 columns, 23 attack-labelled,
664 benign, 0 schema-validation failures, Parquet round-trips. On the testbed,
`scripts/dataset-run.sh` runs a campaign and produces `runs/<name>/dataset.parquet` and
`dataset-card.md`; CI runs a short campaign and asserts the Parquet is non-empty and
carries attack labels.

## Reproduce on the testbed

```bash
cd testbed
docker compose down && docker compose build probe && docker compose up -d   # probe 0.6.0
bash scripts/smoke.sh                       # 10/10
bash scripts/attack-check.sh                # now includes N2-02/N2-01/N2-04
bash scripts/dataset-run.sh campaigns/dataset.json   # full labelled dataset
```
