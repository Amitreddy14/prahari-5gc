#!/usr/bin/env python3
"""Field-by-field cross-check of prahari-probe events against tshark.

    python3 probe/tools/crosscheck_tshark.py --probe build/release/prahari-probe capture.pcap

tshark is the oracle.
  PFCP (N4), per message: type, sequence, endpoints, cause, Node ID, and how the header
      SEID / F-SEID map onto the probe's CP/UP SEIDs.
  NGAP (N2), per frame (SCTP bundles several PDUs into one packet): the multiset of
      (procedure code, PDU type), the multiset of RAN-UE-NGAP-IDs, the set of
      AMF-UE-NGAP-IDs (the probe back-fills AMF IDs from its UE table, so counts differ
      by design but values must not), the decoded NAS 5GMM/5GSM message types, and the
      Global gNB ID + PLMN on NG Setup.
  Privacy: no MSIN from any SUCI in the capture may appear anywhere in the output.
Exits non-zero on any mismatch.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import Counter
from typing import Any

PFCP_FIELDS = [
    "frame.number",
    "ip.src",
    "ip.dst",
    "pfcp.msg_type",
    "pfcp.seqno",
    "pfcp.seid",
    "pfcp.cause",
    "pfcp.node_id_ipv4",
]
NGAP_FIELDS = [
    "frame.number",
    "ngap.procedureCode",
    "ngap.NGAP_PDU",
    "ngap.RAN_UE_NGAP_ID",
    "ngap.AMF_UE_NGAP_ID",
    "nas_5gs.mm.message_type",
    "nas_5gs.sm.message_type",
    "ngap.gNB_ID",
    "nas_5gs.mm.suci.msin",
    "e212.mcc",
    "e212.mnc",
]
CP_HEADER = {51, 53, 55, 56}  # PFCP header SEID is the SMF's (CP) SEID
UP_HEADER = {52, 54, 57}  # PFCP header SEID is the UPF's (UP) SEID
PDU_TYPE = {"initiating": 0, "successful": 1, "unsuccessful": 2}

Event = dict[str, Any]


def tshark(
    pcap: str, display_filter: str, fields: list[str]
) -> list[dict[str, list[str]]]:
    # null_decipher: let tshark read NEA0 "ciphered" NAS, as the probe does.
    cmd = [
        "tshark",
        "-r",
        pcap,
        "-o",
        "nas-5gs.null_decipher:TRUE",
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "separator=|",
        "-E",
        "occurrence=a",
        "-E",
        "aggregator=,",
    ]
    for f in fields:
        cmd += ["-e", f]
    out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    return [
        {
            f: [x for x in v.split(",") if x]
            for f, v in zip(fields, line.split("|"), strict=True)
        }
        for line in out.splitlines()
    ]


def check_pfcp(row: dict[str, list[str]], ev: Event, bad: list[str]) -> None:
    n = row["frame.number"][0]

    def fail(what: str, want: object, got: object) -> None:
        bad.append(f"frame {n} {ev['message']}: {what} tshark={want} probe={got}")

    t = int(row["pfcp.msg_type"][0])
    if ev["message_code"] != t:
        fail("type", t, ev["message_code"])
    if ev.get("sequence") != int(row["pfcp.seqno"][0]):
        fail("sequence", row["pfcp.seqno"], ev.get("sequence"))
    if ev["src"]["ip"] != row["ip.src"][0] or ev["dst"]["ip"] != row["ip.dst"][0]:
        fail(
            "endpoints",
            (row["ip.src"], row["ip.dst"]),
            (ev["src"]["ip"], ev["dst"]["ip"]),
        )
    p = ev.get("pfcp", {})
    if row["pfcp.cause"] and p.get("cause_code") != int(row["pfcp.cause"][0]):
        fail("cause", row["pfcp.cause"], p.get("cause_code"))
    if row["pfcp.node_id_ipv4"] and p.get("node_id") != row["pfcp.node_id_ipv4"][0]:
        fail("node_id", row["pfcp.node_id_ipv4"], p.get("node_id"))
    seids = [int(s, 16) for s in row["pfcp.seid"]]
    if t == 50 and len(seids) == 2 and p.get("cp_seid") != str(seids[1]):
        fail("cp_seid (F-SEID)", seids[1], p.get("cp_seid"))
    if t == 51 and len(seids) == 2 and p.get("up_seid") != str(seids[1]):
        fail("up_seid (F-SEID)", seids[1], p.get("up_seid"))
    if t in CP_HEADER and seids and p.get("cp_seid") != str(seids[0]):
        fail("cp_seid (header)", seids[0], p.get("cp_seid"))
    if t in UP_HEADER and seids and p.get("up_seid") != str(seids[0]):
        fail("up_seid (header)", seids[0], p.get("up_seid"))


def group_n2_by_frame(events: list[Event]) -> list[list[Event]]:
    groups: list[list[Event]] = []
    key = None
    for ev in events:
        if ev["interface"] != "N2":
            continue
        k = (
            ev["ts_ns"],
            ev["src"]["ip"],
            ev["src"]["port"],
            ev["dst"]["ip"],
            ev["dst"]["port"],
        )
        if k != key:
            groups.append([])
            key = k
        groups[-1].append(ev)
    return groups


def check_ngap_frame(
    row: dict[str, list[str]], group: list[Event], bad: list[str]
) -> None:
    n = row["frame.number"][0]

    def fail(what: str, want: object, got: object) -> None:
        bad.append(f"frame {n}: {what} tshark={want} probe={got}")

    want = Counter(
        zip(
            map(int, row["ngap.procedureCode"]),
            map(int, row["ngap.NGAP_PDU"]),
            strict=True,
        )
    )
    got = Counter(
        (e["message_code"], PDU_TYPE[e["ngap"]["pdu_type"]])
        for e in group
        if "ngap" in e
    )
    if want != got:
        fail("procedures", sorted(want.items()), sorted(got.items()))

    ran_w = Counter(int(x) for x in row["ngap.RAN_UE_NGAP_ID"])
    ran_g = Counter(
        e["ue"]["ran_ue_ngap_id"] for e in group if "ran_ue_ngap_id" in e.get("ue", {})
    )
    if ran_w != ran_g:
        fail("ran_ue_ngap_id", sorted(ran_w.elements()), sorted(ran_g.elements()))
    amf_w = {int(x) for x in row["ngap.AMF_UE_NGAP_ID"]}
    amf_g = {
        e["ue"]["amf_ue_ngap_id"] for e in group if "amf_ue_ngap_id" in e.get("ue", {})
    }
    if not amf_w <= amf_g:
        fail("amf_ue_ngap_id", sorted(amf_w), sorted(amf_g))

    mm = Counter(int(x, 16) for x in row["nas_5gs.mm.message_type"])
    sm = Counter(int(x, 16) for x in row["nas_5gs.sm.message_type"])
    g_mm: Counter[int] = Counter()
    g_sm: Counter[int] = Counter()
    for e in group:
        nas = e.get("nas")
        if not nas or not nas["decoded"]:
            continue
        (g_sm if nas["epd"] == "5GSM" else g_mm)[nas["message_type"]] += 1
        if "sm_message_type" in nas:
            g_sm[nas["sm_message_type"]] += 1
    # Every NAS type the probe reports must be one tshark sees in that frame.
    if g_mm - mm or g_sm - sm:
        fail(
            "nas types",
            (sorted(mm.elements()), sorted(sm.elements())),
            (sorted(g_mm.elements()), sorted(g_sm.elements())),
        )

    for e in group:
        ng = e.get("ngap", {})
        if "gnb_id" in ng:
            if row["ngap.gNB_ID"] and ng["gnb_id"] != int(row["ngap.gNB_ID"][0], 16):
                fail("gnb_id", row["ngap.gNB_ID"], ng["gnb_id"])
            plmn = (row["e212.mcc"] or [""])[0] + (row["e212.mnc"] or [""])[0]
            if plmn and ng.get("plmn") != plmn:
                fail("plmn", plmn, ng.get("plmn"))


def check_capture(probe: str, pcap: str) -> list[str]:
    env = dict(os.environ, PRAHARI_SUPI_KEY="crosscheck-key-not-secret-0123")
    out = subprocess.run(
        [
            probe,
            "run",
            "--pcap",
            pcap,
            "--seed",
            "1",
            "--filter",
            "udp port 8805 or sctp",
        ],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    ).stdout
    events = [json.loads(line) for line in out.splitlines()]
    bad: list[str] = []

    pfcp_rows = tshark(pcap, "pfcp", PFCP_FIELDS)
    n4 = [e for e in events if e["interface"] == "N4"]
    if len(pfcp_rows) != len(n4):
        bad.append(f"PFCP count: tshark={len(pfcp_rows)} probe={len(n4)}")
    else:
        for row, ev in zip(pfcp_rows, n4, strict=True):
            check_pfcp(row, ev, bad)

    ngap_rows = tshark(pcap, "ngap", NGAP_FIELDS)
    groups = group_n2_by_frame(events)
    n2_count = sum(len(g) for g in groups)
    if len(groups) != len(ngap_rows):
        bad.append(f"NGAP frame count: tshark={len(ngap_rows)} probe={len(groups)}")
    else:
        for row, group in zip(ngap_rows, groups, strict=True):
            check_ngap_frame(row, group, bad)

    msins = {m for row in ngap_rows for m in row["nas_5gs.mm.suci.msin"]}
    leaks = [m for m in msins if m in out]
    if leaks:
        bad.append(f"PRIVACY: {len(leaks)} MSIN(s) found verbatim in probe output")

    for m in bad[:20]:
        print("MISMATCH", m)
    status = "PASS" if not bad else "FAIL"
    print(
        f"{status} {pcap}: {len(n4)} PFCP + {n2_count} NGAP messages compared "
        f"({len(ngap_rows)} N2 frames), {len(msins)} SUCI MSINs checked for leaks, "
        f"{len(bad)} mismatches"
    )
    return bad


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", nargs="+")
    ap.add_argument("--probe", default="probe/build/release/prahari-probe")
    args = ap.parse_args()
    failed = [p for p in args.pcap if check_capture(args.probe, p)]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
