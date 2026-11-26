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

## n2-registration.pcap

16 SCTP frames (4 KB, 23 NGAP messages) cut from the same testbed (UERANSIM gNB
172.22.0.20 ↔ AMF 172.22.0.5): one UE's full life on N2.

| Frames | Content |
|---|---|
| 1–2 | NG Setup Request / Response (gNB ID, PLMN 00101, RAN node name) |
| 3 | InitialUEMessage + Registration Request (SUCI, null scheme) |
| 4–7 | Authentication, including one synch failure and retry |
| 8 | Security Mode Command (selects NEA0, so later NAS bodies are readable) |
| 9–12 | Registration Accept / Complete, Configuration Update (several NGAP messages bundled per frame) |
| 13–14 | PDU Session Resource Setup with the PDU Session Establishment Accept inside |
| 15–16 | UE Context Release Command / Complete (UE-NGAP-IDs IE 114) |

Cross-checked against tshark 4.2 (`-o nas-5gs.null_decipher:TRUE`) with
`probe/tools/crosscheck_tshark.py`.

**Identities:** the SUCI carries test IMSI `001010000000008` in clear (null scheme),
synthetic like the N4 fixture. Tests assert its MSIN never appears in probe output and
that the probe and Python produce the same pseudonym for it with the test key.

## sbi-registration.pcap

1,122 TCP segments (240 KB) from the same testbed on 2026-11-26: the second
registration wave, when all 10 UEs deregistered and registered again. Covers 11 HTTP/2
connections opened inside the capture (so HPACK state is complete from the first
byte): 320 requests + 320 responses, 25 service operations across AMF, SMF, AUSF, UDM,
UDR, PCF and BSF. Pure-ACK segments were removed (the probe does not need them); every
segment carrying data, SYN, FIN or RST is untouched.

Cross-checked against tshark 4.2 (`-d tcp.port==7777,http2`): every request's stream,
method and sanitised path and every response's status match; each request whose path
holds a SUPI has the expected HMAC pseudonym.

**Identities:** SUPIs `imsi-0010100000000xx` and null-scheme SUCIs appear in paths and
JSON bodies, and AUSF/UDM bodies carry 5G-AKA vectors derived from the public UERANSIM
example K/OPc. All synthetic test values. Tests assert none of the identities reaches
probe output and that the 10 UEs get 10 pseudonyms, one shared with the N2 fixture.
