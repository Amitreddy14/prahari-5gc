"""Ground-truth labelling: attacker address, PFCP sequence markers, run windows."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from prahari_analytics.events import SignallingEvent
from prahari_analytics.labels import (
    POST_MARGIN_NS,
    Run,
    label,
    label_stream,
    load_runs,
)

S = 1_000_000_000
ATTACKER = "172.22.0.40"


def ev(ts: int, src: str, dst: str, protocol: str = "PFCP", seq: int | None = 1) -> dict[str, Any]:
    e: dict[str, Any] = {
        "schema_version": 1,
        "event_id": "5c1d1b53-5f4c-4b7e-9d6f-1a2b3c4d5e6f",
        "ts_ns": ts,
        "interface": "N4" if protocol == "PFCP" else "SBI",
        "protocol": protocol,
        "message": "SessionDeletionRequest" if protocol == "PFCP" else "NFDiscover",
        "message_code": 54 if protocol == "PFCP" else 0,
        "direction": "request",
        "src": {"ip": src, "port": 8805, "nf": "SMF"},
        "dst": {"ip": dst, "port": 8805, "nf": "UPF"},
        "size_bytes": 16,
        "decode_status": "ok",
    }
    if seq is not None:
        e["sequence"] = seq
    return e


def run(rid: str, start: int, end: int, seqs: tuple[int, ...] = (), aid: str = "N4-01") -> Run:
    return Run(rid, aid, ATTACKER, start, end, frozenset(seqs))


def test_attacker_address_inside_window_is_attack() -> None:
    r = run("r1", 100 * S, 110 * S)
    assert label(ev(105 * S, ATTACKER, "172.22.0.8"), [r]) == {
        "is_attack": True,
        "attack_id": "N4-01",
        "run_id": "r1",
    }
    # Responses towards the attacker count too.
    assert label(ev(105 * S, "172.22.0.8", ATTACKER), [r])["is_attack"]


def test_outside_window_or_unrelated_traffic_is_benign() -> None:
    r = run("r1", 100 * S, 110 * S)
    assert not label(ev(105 * S, "172.22.0.7", "172.22.0.8", seq=7), [r])["is_attack"]
    late = 110 * S + POST_MARGIN_NS + 1
    assert not label(ev(late, ATTACKER, "172.22.0.8"), [r])["is_attack"]


def test_spoofed_pfcp_is_attributed_by_sequence_marker() -> None:
    r = run("r1", 100 * S, 110 * S, seqs=(0xA00001, 0xA00002))
    spoofed = ev(105 * S, "172.22.0.7", "172.22.0.8", seq=0xA00001)  # bears the SMF's IP
    answer = ev(105 * S, "172.22.0.8", "172.22.0.7", seq=0xA00001)  # UPF answers the real SMF
    assert label(spoofed, [r])["is_attack"]
    assert label(answer, [r])["is_attack"]
    # The same sequence number outside the run is the real SMF's business.
    assert not label(ev(200 * S, "172.22.0.7", "172.22.0.8", seq=0xA00001), [r])["is_attack"]
    # A sequence marker never applies to SBI events.
    assert not label(ev(105 * S, "172.22.0.5", "172.22.0.10", "HTTP2", 0xA00001), [r])["is_attack"]


def test_back_to_back_runs_do_not_steal_each_others_events() -> None:
    a = run("a", 100 * S, 110 * S, aid="N4-04")
    b = run("b", 112 * S, 120 * S, aid="N4-03")  # starts inside a's post-margin
    assert label(ev(113 * S, ATTACKER, "172.22.0.8"), [a, b])["run_id"] == "b"
    assert label(ev(111 * S, ATTACKER, "172.22.0.8"), [a, b])["run_id"] == "a"
    # A marker is unambiguous even when the windows say otherwise.
    c = run("c", 100 * S, 110 * S, seqs=(0xB00000,), aid="N4-02")
    e = ev(113 * S, "172.22.0.7", "172.22.0.8", seq=0xB00000)
    assert label(e, [b, c])["run_id"] == "c"


def test_dry_runs_are_skipped(tmp_path: Path) -> None:
    base = {"attack_id": "SBI-01", "attacker_ip": ATTACKER, "started_ns": S, "ended_ns": 2 * S}
    (tmp_path / "a.json").write_text(json.dumps({**base, "run_id": "real", "dry_run": False}))
    (tmp_path / "b.json").write_text(json.dumps({**base, "run_id": "dry", "dry_run": True}))
    assert [r.run_id for r in load_runs([tmp_path])] == ["real"]


def test_non_run_json_is_skipped(tmp_path: Path) -> None:
    # A campaign.json sits beside the run manifests; it has no run_id and must be ignored.
    base = {"attack_id": "SBI-01", "attacker_ip": ATTACKER, "started_ns": S, "ended_ns": 2 * S}
    (tmp_path / "run.json").write_text(json.dumps({**base, "run_id": "real"}))
    (tmp_path / "campaign.json").write_text(json.dumps({"campaign": "demo", "attacks": []}))
    assert [r.run_id for r in load_runs([tmp_path])] == ["real"]


def test_stream_skips_partial_lines_and_output_matches_the_model() -> None:
    r = run("r1", 100 * S, 110 * S)
    lines = [
        json.dumps(ev(105 * S, ATTACKER, "172.22.0.8")),
        '{"schema_version":1,"event_id":',  # a half-written tail line
        "",
        json.dumps(ev(300 * S, "172.22.0.7", "172.22.0.8")),
    ]
    out = list(label_stream(lines, [r]))
    assert [lab["is_attack"] for _, lab in out] == [True, False]
    for line, _ in out:
        SignallingEvent.from_json(line)


def test_size_bytes_accepts_large_sbi_messages() -> None:
    e = ev(1, "172.22.0.5", "172.22.0.10", "HTTP2", None)
    e["size_bytes"] = 70_073  # seen in SBI-04 fuzzing: 64 KiB is not a limit for SBI
    SignallingEvent.model_validate_json(json.dumps(e))
