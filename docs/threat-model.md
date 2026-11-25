# Threat model and attack catalogue

## 1. What we protect

| Asset | Why it matters |
|---|---|
| AMF availability | Every UE registration and mobility event goes through it |
| PDU sessions (SMF ↔ UPF state) | Tearing down or rewriting them cuts or redirects user traffic |
| NRF registry | Whoever controls discovery controls which NF talks to which |
| Subscriber identities | SUPI/IMSI exposure enables tracking |

## 2. Adversary model

The attacker has gained a foothold **inside the core's network domain**: a
compromised or malicious container, a rogue base station connected to N2, or
access to an unprotected transport segment. This matches published 5G core
research and real deployment gaps where N2/N4 rely on network isolation instead of
IPsec/NDS-IP (3GPP TS 33.501 / 33.210).

The attacker:
- can send well-formed or malformed NGAP, PFCP and SBI messages to reachable NFs,
- can observe some traffic and guess identifiers (e.g. sequential SEIDs),
- does **not** hold operator keys (cannot break NAS security or mTLS if enabled),
- in Phase 6 is **adaptive**: knows a detector exists and shapes rate, timing and ordering to evade it, while staying protocol-compliant.

## 3. Attack catalogue

Each scenario has an ID used as `labels.attack_id` in datasets.

| ID | Interface | Attack | Mechanism | Expected impact | First detection signal |
|---|---|---|---|---|---|
| N2-01 | N2 | Registration storm | Thousands of Registration Requests from many fake UEs via one or more gNBs | AMF CPU/memory exhaustion, legit registrations time out | Rate of InitialUEMessage per gNB / per window; ratio of incomplete registrations |
| N2-02 | N2 | Rogue gNB | NG Setup from an unknown Global RAN Node ID or spoofed TAC | Fake cell injected into the core | NG Setup from a peer not in the learned baseline |
| N2-03 | N2 | Forged UE context release | UEContextReleaseRequest for UEs the sender does not serve | Targeted UEs dropped | Release for a RAN-UE-NGAP-ID never seen from that gNB |
| N2-04 | N2 | Malformed NGAP | Fuzzed IEs, bad lengths, unknown procedure codes | NF crash or undefined behaviour | `decode_status != ok` rate; unknown procedure codes |
| N4-01 | N4 | PFCP session deletion | Spoofed Session Deletion Request with a guessed SEID | User's data session torn down | Deletion for a SEID with no matching establishment from that SMF |
| N4-02 | N4 | PFCP session modification hijack | Modify FAR to drop or redirect traffic | Traffic black-holed or redirected | Modification from an unexpected peer / outside a procedure context |
| N4-03 | N4 | PFCP establishment flood | High-rate Session Establishment Requests | UPF resource exhaustion | Establishment rate vs registered-UE count |
| N4-04 | N4 | Rogue PFCP association | Association Setup/Release from an unknown SMF | UPF accepts a fake control node, or drops a real one | Association from a peer outside baseline |
| SBI-01 | SBI | NRF reconnaissance | Systematic NFDiscover across all NF types | Maps the core for follow-up attacks | Discovery fan-out per source; NF types never used by that source |
| SBI-02 | SBI | Rogue NF registration | NFRegister with a fake profile | Traffic steered to attacker NF | NFRegister from an unexpected IP; profile mismatch |
| SBI-03 | SBI | NF deregistration / profile tampering | NFDeregister or PATCH on another NF's profile | Denial of service between NFs | Deregistration not preceded by that NF's shutdown pattern |
| SBI-04 | SBI | SBI API fuzzing | Malformed paths, methods, bodies | NF crash / info leak | 4xx/5xx burst; paths outside the OpenAPI set |

Phase 4 implements the full catalogue. Each scenario has parameters (rate,
duration, number of targets, stealth knobs) recorded with every run.

## 4. Benign traffic profile

To keep false-alarm numbers honest, the benign generator mixes: UE power-on
registration waves, periodic re-registration, PDU session setup/teardown churn,
idle/active transitions, NF heartbeats, and occasional legitimate NF restarts.
Benign and attack runs are recorded separately and mixed only at evaluation time.

## 5. Explicitly out of scope

Radio/RF attacks, user-plane payload attacks (GTP-U), roaming (N32), attacks
needing broken cryptography, and any testing against networks other than the
local testbed.
