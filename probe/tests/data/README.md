# Test captures

## n4-lifecycle.pcap

24 PFCP packets (5 KB) cut from the Prahari testbed (Open5GS v2.7.7 SMF 172.22.0.7 ↔
UPF 172.22.0.8) on 2026-11-25:

| Frames | Content |
|---|---|
| 1–2 | Association Setup Request / Response |
| 3–6 | Heartbeats in both directions |
| 7–24 | Three complete PDU sessions: Establishment, Modification, Deletion (request + response each) |

Every field was cross-checked against tshark 4.2 with `probe/tools/crosscheck_tshark.py`.

**Identities:** the Session Establishment Requests carry a PFCP *User ID* IE holding the
UE's IMSI and IMEI. These are synthetic test-network values (test PLMN 001/01, IMSIs
`001010000000xxx`, UERANSIM's default IMEI), not real subscribers, which is why this one
capture is committed. Real or production captures must never be added here
(see `rules.md`). The probe only flags the User ID IE as present; a test asserts no
IMSI ever reaches an event.
