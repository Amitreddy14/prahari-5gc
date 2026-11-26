"""Build a labelled Parquet dataset (and a dataset card) from labelled probe events.

Input is the JSON Lines that prahari_analytics.labels produces: one signalling event per
line with a `labels` block. This flattens each event's nested protocol views into a flat,
typed column set, writes Parquet, and emits a Markdown dataset card describing the schema,
provenance, class balance, and limitations.

    python -m prahari_analytics.dataset --events labelled.jsonl --out dataset.parquet \\
        --card dataset-card.md --campaign runs/campaign.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# (column, pyarrow type name, path into the event, one-line description).
# Path segments navigate nested objects; a missing object yields null.
FIELDS: tuple[tuple[str, str, tuple[str, ...], str], ...] = (
    ("event_id", "string", ("event_id",), "probe event UUID"),
    ("ts_ns", "int64", ("ts_ns",), "capture timestamp (ns since epoch)"),
    ("interface", "string", ("interface",), "N2 | N4 | SBI"),
    ("protocol", "string", ("protocol",), "NGAP | NAS-5GS | PFCP | HTTP2"),
    ("message", "string", ("message",), "decoded message name"),
    ("message_code", "int64", ("message_code",), "numeric message/procedure code"),
    ("direction", "string", ("direction",), "request | response | indication | unknown"),
    ("decode_status", "string", ("decode_status",), "ok | truncated | malformed | ..."),
    ("size_bytes", "int64", ("size_bytes",), "signalling payload size"),
    ("sequence", "int64", ("sequence",), "PFCP sequence number, if any"),
    ("cause", "string", ("cause",), "cause string, if any"),
    ("src_ip", "string", ("src", "ip"), "source address"),
    ("src_port", "int64", ("src", "port"), "source port"),
    ("src_nf", "string", ("src", "nf"), "source network function (inferred)"),
    ("dst_ip", "string", ("dst", "ip"), "destination address"),
    ("dst_port", "int64", ("dst", "port"), "destination port"),
    ("dst_nf", "string", ("dst", "nf"), "destination network function (inferred)"),
    ("ran_ue_ngap_id", "int64", ("ue", "ran_ue_ngap_id"), "RAN UE NGAP ID"),
    ("amf_ue_ngap_id", "int64", ("ue", "amf_ue_ngap_id"), "AMF UE NGAP ID"),
    ("supi_hash", "string", ("ue", "supi_hash"), "pseudonymised SUPI (keyed HMAC, 64-bit)"),
    ("seid", "string", ("ue", "seid"), "PFCP session endpoint id"),
    ("pdu_session_id", "int64", ("ue", "pdu_session_id"), "PDU session id"),
    ("sbi_method", "string", ("sbi", "method"), "HTTP method"),
    ("sbi_path", "string", ("sbi", "path"), "sanitised SBI path (identities masked)"),
    ("sbi_status", "int64", ("sbi", "status"), "HTTP status"),
    ("sbi_service", "string", ("sbi", "service"), "3GPP service operation"),
    ("pfcp_session_state", "string", ("pfcp", "session_state"), "establishing | active | deleted"),
    ("pfcp_cause_code", "int64", ("pfcp", "cause_code"), "PFCP cause"),
    ("pfcp_node_id", "string", ("pfcp", "node_id"), "PFCP node id"),
    ("ngap_pdu_type", "string", ("ngap", "pdu_type"), "initiating | successful | unsuccessful"),
    ("ngap_procedure_code", "int64", ("ngap", "procedure_code"), "NGAP procedure code"),
    ("ngap_gnb_id", "int64", ("ngap", "gnb_id"), "global gNB id"),
    ("ngap_ran_node_name", "string", ("ngap", "ran_node_name"), "RAN node name"),
    ("nas_message", "string", ("nas", "message"), "NAS message name"),
    ("nas_message_type", "int64", ("nas", "message_type"), "NAS message type"),
    ("nas_registration_type", "string", ("nas", "registration_type"), "registration type"),
    ("nas_suci_null_scheme", "bool", ("nas", "suci_null_scheme"), "SUCI used the null scheme"),
    ("is_attack", "bool", ("labels", "is_attack"), "ground-truth attack label"),
    ("attack_id", "string", ("labels", "attack_id"), "attack id if is_attack"),
    ("run_id", "string", ("labels", "run_id"), "attack run id if is_attack"),
)


def _dig(ev: dict[str, Any], path: tuple[str, ...]) -> Any:
    cur: Any = ev
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


def flatten(ev: dict[str, Any]) -> dict[str, Any]:
    return {col: _dig(ev, path) for col, _typ, path, _desc in FIELDS}


@dataclass
class Stats:
    rows: int = 0
    attack_rows: int = 0
    by_attack: Counter[str] = field(default_factory=Counter)
    by_interface: Counter[str] = field(default_factory=Counter)
    by_protocol: Counter[str] = field(default_factory=Counter)
    first_ts_ns: int | None = None
    last_ts_ns: int | None = None

    def add(self, ev: dict[str, Any]) -> None:
        self.rows += 1
        labels = ev.get("labels") or {}
        if labels.get("is_attack"):
            self.attack_rows += 1
            self.by_attack[str(labels.get("attack_id", "unknown"))] += 1
        else:
            self.by_attack["benign"] += 1
        self.by_interface[str(ev.get("interface", "?"))] += 1
        self.by_protocol[str(ev.get("protocol", "?"))] += 1
        ts = ev.get("ts_ns")
        if isinstance(ts, int):
            self.first_ts_ns = ts if self.first_ts_ns is None else min(self.first_ts_ns, ts)
            self.last_ts_ns = ts if self.last_ts_ns is None else max(self.last_ts_ns, ts)


def _iter_events(path: Path) -> Iterator[dict[str, Any]]:
    with path.open(encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if line.startswith("{") and line.endswith("}"):
                yield json.loads(line)


def build_table(events: Iterable[dict[str, Any]], stats: Stats) -> Any:
    import pyarrow as pa  # noqa: PLC0415 - optional dependency, only for the dataset build

    types = {"string": pa.string(), "int64": pa.int64(), "bool": pa.bool_()}
    columns: dict[str, list[Any]] = {col: [] for col, _t, _p, _d in FIELDS}
    for ev in events:
        stats.add(ev)
        row = flatten(ev)
        for col, values in columns.items():
            values.append(row[col])
    arrays = [pa.array(columns[col], type=types[typ]) for col, typ, _p, _d in FIELDS]
    schema = pa.schema([(col, types[typ]) for col, typ, _p, _d in FIELDS])
    return pa.Table.from_arrays(arrays, schema=schema)


def _ns_to_iso(ns: int | None) -> str:
    if ns is None:
        return "n/a"
    import datetime as dt  # noqa: PLC0415

    return dt.datetime.fromtimestamp(ns / 1e9, tz=dt.UTC).isoformat()


def dataset_card(
    stats: Stats, *, name: str, probe_version: str, campaign: dict[str, Any] | None
) -> str:
    bal = stats.attack_rows / stats.rows if stats.rows else 0.0
    lines = [
        f"# Prahari-5GC signalling dataset — {name}",
        "",
        "Labelled 5G core control-plane signalling, captured passively by the Prahari probe",
        "from a private Open5GS + UERANSIM testbed while scripted benign traffic and a timed",
        "sequence of attacks ran against it. One row per decoded signalling message.",
        "",
        "## Provenance",
        "",
        f"- Probe version: `{probe_version}`",
        "- Core: Open5GS v2.7.7; RAN: UERANSIM 3.2.8; PLMN 001/01 (test)",
        f"- Campaign: `{campaign.get('campaign') if campaign else 'n/a'}`",
        f"- Window: {_ns_to_iso(stats.first_ts_ns)} .. {_ns_to_iso(stats.last_ts_ns)}",
        "- Identities are pseudonymised at capture (keyed HMAC); no raw IMSI/SUPI is stored.",
        "",
        "## Labelling",
        "",
        "Ground truth comes from the injector's run manifests: an event is attack-labelled when",
        "it falls in a run's window and either involves the attacker address or carries one of",
        "the run's reserved PFCP sequence numbers (for spoofed N4). Everything else is benign —",
        "including benign-looking side effects of an attack, which stay benign on purpose.",
        "",
        "## Size and balance",
        "",
        f"- Rows: **{stats.rows}**",
        f"- Attack: **{stats.attack_rows}** ({bal:.1%}) · "
        f"Benign: **{stats.rows - stats.attack_rows}**",
        "",
        "### By class",
        "",
        "| class | rows |",
        "| --- | ---: |",
    ]
    for cls, n in sorted(stats.by_attack.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"| {cls} | {n} |")
    lines += ["", "### By interface", "", "| interface | rows |", "| --- | ---: |"]
    for iface, n in sorted(stats.by_interface.items()):
        lines.append(f"| {iface} | {n} |")
    lines += ["", "### By protocol", "", "| protocol | rows |", "| --- | ---: |"]
    for proto, n in sorted(stats.by_protocol.items()):
        lines.append(f"| {proto} | {n} |")
    lines += ["", "## Columns", "", "| column | type | description |", "| --- | --- | --- |"]
    for col, typ, _p, desc in FIELDS:
        lines.append(f"| `{col}` | {typ} | {desc} |")
    lines += [
        "",
        "## Intended use and limits",
        "",
        "- For training and evaluating passive signalling-anomaly detectors;"
        " labels are per-message.",
        "- `is_attack` is the binary target; `attack_id` is the multiclass target"
        " (benign + N2/N4/SBI).",
        "- Lab data from a single small PLMN and fixed NF versions: it captures the attacks and",
        "  the normal flows modelled here, not the full diversity of a production network. Do not",
        "  treat absence of an attack class as evidence it is undetectable.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build a labelled Parquet dataset from probe events.")
    ap.add_argument("--events", type=Path, required=True, help="labelled JSON Lines")
    ap.add_argument("--out", type=Path, required=True, help="output .parquet")
    ap.add_argument("--card", type=Path, help="write a Markdown dataset card here")
    ap.add_argument("--campaign", type=Path, help="campaign.json for provenance")
    ap.add_argument("--name", default="v1", help="dataset name for the card")
    ap.add_argument("--probe-version", default="unknown", help="probe version for provenance")
    args = ap.parse_args(argv)

    import pyarrow.parquet as pq  # noqa: PLC0415

    stats = Stats()
    table = build_table(_iter_events(args.events), stats)
    pq.write_table(table, args.out)
    campaign = json.loads(args.campaign.read_text(encoding="utf-8")) if args.campaign else None
    print(
        f"{stats.rows} rows -> {args.out} ({stats.attack_rows} attack, "
        f"{stats.rows - stats.attack_rows} benign)"
    )
    if args.card:
        card = dataset_card(
            stats, name=args.name, probe_version=args.probe_version, campaign=campaign
        )
        args.card.write_text(card, encoding="utf-8")
        print(f"dataset card -> {args.card}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
