#!/usr/bin/env python3
"""Field-by-field cross-check of prahari-probe PFCP events against tshark.

    python3 probe/tools/crosscheck_tshark.py --probe build/release/prahari-probe capture.pcap

tshark is the oracle. For every PFCP message both tools see, compare: message type,
sequence number, source/destination, cause, Node ID, and how the header SEID / F-SEID
map onto the probe's CP/UP SEIDs. Exits non-zero on any mismatch.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys

FIELDS = ["frame.number", "ip.src", "ip.dst", "pfcp.msg_type", "pfcp.seqno", "pfcp.seid",
          "pfcp.cause", "pfcp.node_id_ipv4"]
CP_HEADER = {51, 53, 55, 56}   # header SEID is the SMF's (CP) SEID
UP_HEADER = {52, 54, 57}       # header SEID is the UPF's (UP) SEID


def tshark_rows(pcap: str) -> list[dict[str, str]]:
    cmd = ["tshark", "-r", pcap, "-Y", "pfcp", "-T", "fields", "-E", "separator=|",
           "-E", "occurrence=a", "-E", "aggregator=,"]
    for f in FIELDS:
        cmd += ["-e", f]
    out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    return [dict(zip(FIELDS, line.split("|"), strict=True)) for line in out.splitlines()]


def first(v: str) -> str:
    return v.split(",")[0] if v else ""


def check(row: dict[str, str], ev: dict, mismatches: list[str]) -> None:
    n = row["frame.number"]
    def bad(what: str, want: object, got: object) -> None:
        mismatches.append(f"frame {n} {ev['message']}: {what} tshark={want} probe={got}")

    t = int(row["pfcp.msg_type"])
    if ev["message_code"] != t:
        bad("type", t, ev["message_code"])
    if ev.get("sequence") != int(row["pfcp.seqno"]):
        bad("sequence", row["pfcp.seqno"], ev.get("sequence"))
    if ev["src"]["ip"] != row["ip.src"] or ev["dst"]["ip"] != row["ip.dst"]:
        bad("endpoints", (row["ip.src"], row["ip.dst"]), (ev["src"]["ip"], ev["dst"]["ip"]))
    p = ev.get("pfcp", {})
    cause = first(row["pfcp.cause"])
    if cause and p.get("cause_code") != int(cause):
        bad("cause", cause, p.get("cause_code"))
    node = first(row["pfcp.node_id_ipv4"])
    if node and p.get("node_id") != node:
        bad("node_id", node, p.get("node_id"))
    seids = [int(s, 16) for s in row["pfcp.seid"].split(",") if s]
    if t == 50 and len(seids) == 2 and p.get("cp_seid") != str(seids[1]):
        bad("cp_seid (F-SEID)", seids[1], p.get("cp_seid"))
    if t == 51 and len(seids) == 2 and p.get("up_seid") != str(seids[1]):
        bad("up_seid (F-SEID)", seids[1], p.get("up_seid"))
    if t in CP_HEADER and seids and p.get("cp_seid") != str(seids[0]):
        bad("cp_seid (header)", seids[0], p.get("cp_seid"))
    if t in UP_HEADER and seids and p.get("up_seid") != str(seids[0]):
        bad("up_seid (header)", seids[0], p.get("up_seid"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--probe", default="probe/build/release/prahari-probe")
    args = ap.parse_args()

    rows = tshark_rows(args.pcap)
    out = subprocess.run([args.probe, "run", "--pcap", args.pcap, "--filter", "udp port 8805",
                          "--seed", "1"], check=True, capture_output=True, text=True).stdout
    events = [json.loads(line) for line in out.splitlines()]
    if len(rows) != len(events):
        print(f"FAIL count: tshark={len(rows)} probe={len(events)}")
        return 1
    mismatches: list[str] = []
    for row, ev in zip(rows, events, strict=True):
        check(row, ev, mismatches)
    for m in mismatches[:20]:
        print("MISMATCH", m)
    status = "PASS" if not mismatches else "FAIL"
    print(f"{status}: {len(rows)} PFCP messages compared field by field, {len(mismatches)} mismatches")
    return 0 if not mismatches else 1


if __name__ == "__main__":
    sys.exit(main())
