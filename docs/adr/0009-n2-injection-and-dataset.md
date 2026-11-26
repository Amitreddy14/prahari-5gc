# ADR-0009: N2 (NGAP) injection, benign traffic, and the labelled dataset

- Status: Accepted
- Date: 2026-11-26

## Context
Phase 4b extends the injector to N2 (NGAP over SCTP) and turns the testbed into a
labelled dataset generator. Three decisions were open: how to build NGAP/NAS (ASN.1,
unlike PFCP's TLV), how to produce realistic *benign* traffic to sit alongside attacks,
and how to pack captured, labelled events into something a model can train on.

## NGAP/NAS encoding

| Option | For | Against |
|---|---|---|
| **pycrate for NGAP, pycrate_mobile for NAS** | Spec-correct APER by construction; any field controllable; its NGAP release re-encodes this testbed's real traffic byte-for-byte | A real dependency in the attacker image (pure-Python, acceptable) |
| Hand-roll APER (as PFCP) | Matches the PFCP story; no dependency | NGAP APER (SupportedTAList, S-NSSAI, BIT STRING gNB-ID) is large and error-prone, with no live AMF in the sandbox to catch a wrong bit |
| Template-and-mutate captured pcaps | Guaranteed AMF-accepted | Editing fields inside APER by offset is fragile; hard to vary IDs for a storm |

**Decision.** PFCP stays hand-rolled (it is simple TLV and the flex is the C++ decoder);
NGAP and NAS use pycrate. The compatibility risk — "will Open5GS accept generated NGAP?"
— is closed *in the sandbox*, without a live AMF, by decoding the testbed's own captured
UERANSIM↔Open5GS PDUs with pycrate and re-encoding them byte-identical
(`tests/test_ngap.py::test_pycrate_round_trips_real_testbed_traffic`). Every generated
PDU is then cross-checked a second way: the C++ probe decodes it (`decode-ngap` /
`decode-nas`, added for this), with the exact field values asserted.

## Transport and attribution

- **SCTP** via `pysctp` (one-to-one, PPID 60), added to `guard.py` behind the same
  allowlist as every other socket; imported lazily so the CLI and the N4/SBI attacks
  never need it. SCTP needs the host kernel module, which the testbed already relies on
  (the gNB↔AMF link); the sandbox has no SCTP, so N2 is unit-tested with a fake
  association and validated live on the testbed.
- **No IP spoofing on N2.** Every NGAP PDU rides the attacker's own association, so the
  forgery is at the NGAP identity layer (a fake gNB ID, another UE's AMF-UE-NGAP-ID), not
  the source address. Labelling by attacker address alone is therefore exact for N2 — the
  reserved PFCP sequence numbers are only needed for spoofed N4.

## Benign traffic and campaigns
- **Benign generator** (`prahari_campaign.benign`): drives the UERANSIM UEs through PDU
  session establish/release and status polls via `nr-cli`, so the "normal" class is live
  signalling (N4 setup, N2 PDU Session Resource Setup, 5GSM NAS), not an idle core.
- **Campaign runner** (`prahari-campaign`): runs benign traffic continuously while firing
  attacks on a timeline, so attacks land inside normal traffic. Orchestration (the
  `docker compose exec` calls, the clock) is injected, so it is unit-tested without Docker.

## Dataset
- **`prahari-dataset`** flattens labelled events into a typed, flat column set and writes
  **Parquet** (pyarrow), plus a **Markdown dataset card** (provenance, labelling method,
  class balance, column dictionary, limits). Parquet over CSV: typed columns, nulls for
  absent protocol views, and columnar reads for training. `is_attack` is the binary
  target, `attack_id` the multiclass one.

## Consequences
- The attacker image gains libsctp, pycrate, pysctp and pyarrow; still lab-only
  (`PRAHARI_LAB=1`, allowlist, `NET_RAW`, off the `obs`/Kafka network).
- `scripts/dataset-run.sh` produces `runs/<name>/dataset.parquet` + `dataset-card.md`; CI
  runs a short campaign and asserts the Parquet is non-empty and carries attack labels.
- Dataset realism is bounded by one small PLMN and fixed NF versions — stated in the card.
