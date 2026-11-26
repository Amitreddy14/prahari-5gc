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
  SBI (HTTP/2), as multisets per connection side: every request's (stream, method,
      path with identities replaced the way the probe documents) and every final
      response's (stream, status). For each request whose raw path holds a SUPI, the
      event's supi_hash must equal HMAC-SHA256(key, SUPI) computed here.
  Privacy: no MSIN from any SUCI and no IMSI from any SBI path in the capture may
      appear anywhere in the output.
Exits non-zero on any mismatch.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
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

KEY = "crosscheck-key-not-secret-0123"
US = "\x1f"  # aggregator for SBI fields: paths may contain commas


def sanitize_path(raw: str) -> str:
    """The probe's documented rule: drop the query, replace identity segments."""
    out = []
    for seg in raw.split("?")[0].split("#")[0].split("/"):
        if seg.startswith("imsi-"):
            seg = "{supi}"
        elif seg.startswith("suci-"):
            seg = "{suci}"
        elif seg.startswith(("msisdn-", "extid-", "gpsi-")):
            seg = "{gpsi}"
        elif seg.startswith("nai-"):
            seg = "{nai}"
        out.append(seg)
    return "/".join(out)


def supi_hash(supi: str) -> str:
    return hmac.new(KEY.encode(), supi.encode(), hashlib.sha256).hexdigest()[:16]


def check_sbi(
    pcap: str, events: list[Event], out: str, bad: list[str]
) -> tuple[int, int]:
    fields = [
        "ip.src",
        "tcp.srcport",
        "http2.streamid",
        "http2.type",
        "http2.headers.method",
        "http2.headers.path",
        "http2.headers.status",
    ]
    cmd = [
        "tshark",
        "-r",
        pcap,
        "-d",
        "tcp.port==7777,http2",
        "-Y",
        "http2.type==1",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=a",
        "-E",
        f"aggregator={US}",
    ]
    for f in fields:
        cmd += ["-e", f]
    rows = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    t_req: Counter[tuple[str, ...]] = Counter()
    t_res: Counter[tuple[str, ...]] = Counter()
    want_hash: dict[tuple[str, ...], str] = {}
    imsis: set[str] = set()
    for line in rows.splitlines():
        src, port, sids, types, methods, paths, statuses = (
            line.split("\t") + [""] * 7
        )[:7]
        frame_sids = sids.split(US)
        header_sids = [
            s for s, t in zip(frame_sids, types.split(US), strict=False) if t == "1"
        ]
        ms = [m for m in methods.split(US) if m]
        ps = [p for p in paths.split(US) if p]
        ss = [x for x in statuses.split(US) if x]
        if ms:
            for sid, m, raw in zip(header_sids, ms, ps, strict=False):
                key = (src, port, sid, m, sanitize_path(raw))
                t_req[key] += 1
                for seg in raw.split("?")[0].split("/"):
                    if seg.startswith("imsi-") and seg[5:].isdigit():
                        imsis.add(seg[5:])
                        want_hash[(src, port, sid)] = supi_hash(seg)
        else:
            for sid, st in zip(header_sids, ss, strict=False):
                if not st.startswith("1"):
                    t_res[(src, port, sid, st)] += 1
    sbi = [e for e in events if e["interface"] == "SBI" and e["decode_status"] == "ok"]
    p_req: Counter[tuple[str, ...]] = Counter()
    p_res: Counter[tuple[str, ...]] = Counter()
    for e in sbi:
        b = e["sbi"]
        base = (e["src"]["ip"], str(e["src"]["port"]), str(e["sequence"]))
        if e["direction"] == "request":
            p_req[(*base, b.get("method", ""), b["path"])] += 1
            want = want_hash.get(base)
            got = e.get("ue", {}).get("supi_hash")
            if want and got != want:
                bad.append(f"SBI supi_hash {base}: expected {want}, got {got}")
        else:
            p_res[(*base, str(b["status"]))] += 1
    for name, t, p in (("request", t_req, p_req), ("response", t_res, p_res)):
        missing, extra = t - p, p - t
        if missing or extra:
            bad.append(
                f"SBI {name}s: {sum(missing.values())} only in tshark "
                f"(e.g. {next(iter(missing), None)}), {sum(extra.values())} only in "
                f"probe (e.g. {next(iter(extra), None)})"
            )
    errors = [
        e for e in events if e["interface"] == "SBI" and e["decode_status"] != "ok"
    ]
    if errors:
        bad.append(
            f"SBI: {len(errors)} undecodable connection(s): {errors[0].get('cause')}"
        )
    leaks = [i for i in imsis if i in out or i[5:] in out]
    if leaks:
        bad.append(
            f"PRIVACY: {len(leaks)} IMSI(s) from SBI paths found in probe output"
        )
    return sum(t_req.values()), sum(t_res.values())


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
    env = dict(os.environ, PRAHARI_SUPI_KEY=KEY)
    out = subprocess.run(
        [
            probe,
            "run",
            "--pcap",
            pcap,
            "--seed",
            "1",
            "--filter",
            "udp port 8805 or sctp or tcp port 7777",
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

    sbi_req, sbi_res = check_sbi(pcap, events, out, bad)

    msins = {m for row in ngap_rows for m in row["nas_5gs.mm.suci.msin"]}
    leaks = [m for m in msins if m in out]
    if leaks:
        bad.append(f"PRIVACY: {len(leaks)} MSIN(s) found verbatim in probe output")

    for m in bad[:20]:
        print("MISMATCH", m)
    status = "PASS" if not bad else "FAIL"
    print(
        f"{status} {pcap}: {len(n4)} PFCP + {n2_count} NGAP + {sbi_req}/{sbi_res} SBI "
        f"request/response messages compared ({len(ngap_rows)} N2 frames), "
        f"{len(msins)} SUCI MSINs checked for leaks, {len(bad)} mismatches"
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
