"""Manifests and the CLI contract: exit codes, refusals, dry runs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from prahari_attacks.cli import EXIT_OK, EXIT_REFUSED, EXIT_USAGE, main
from prahari_attacks.manifest import PFCP_SEQ_BASE, PFCP_SEQ_LIMIT, Manifest
from prahari_attacks.scenarios import SCENARIOS


def test_pfcp_sequences_come_from_the_reserved_block_and_are_unique() -> None:
    m = Manifest("N4-01", "t", {}, "172.22.0.40", ["172.22.0.8"])
    m.start()
    seqs = [m.next_pfcp_seq() for _ in range(20_000)]
    assert all(PFCP_SEQ_BASE <= s <= PFCP_SEQ_LIMIT for s in seqs)
    assert len(set(seqs)) == len(seqs)
    assert seqs == m.pfcp_seqs


def test_run_id_fits_the_schema(tmp_path: Path) -> None:
    m = Manifest("SBI-04", "t", {"seed": 1}, "172.22.0.40", ["172.22.0.10"])
    m.start()
    m.count("fuzz:4xx", 3)
    m.finish()
    assert m.run_id.startswith("SBI-04-")
    assert len(m.run_id) <= 64
    doc = json.loads(m.write(tmp_path).read_text())
    assert doc["outcome"]["counts"] == {"fuzz:4xx": 3}
    assert doc["ended_ns"] >= doc["started_ns"] > 0
    assert "_counts" not in doc


def test_all_scenarios_are_registered_with_valid_ids() -> None:
    assert sorted(SCENARIOS) == [
        "N2-01",
        "N2-02",
        "N2-03",
        "N2-04",
        "N4-01",
        "N4-02",
        "N4-03",
        "N4-04",
        "SBI-01",
        "SBI-02",
        "SBI-03",
        "SBI-04",
    ]
    for aid, cls in SCENARIOS.items():
        assert cls.attack_id == aid
        assert cls.interface in ("N2", "N4", "SBI")
        for target in cls.targets(cls.defaults()):
            assert target.startswith("172.22.0.")


def test_list_and_describe(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["list"]) == EXIT_OK
    assert "N4-01" in capsys.readouterr().out
    assert main(["describe", "sbi-02"]) == EXIT_OK
    assert "heartbeats" in capsys.readouterr().out
    assert main(["describe", "N2-99"]) == EXIT_USAGE


def test_dry_run_writes_a_manifest_and_sends_nothing(tmp_path: Path) -> None:
    rc = main(["run", "N4-01", "--dry-run", "--out", str(tmp_path), "--param", "seid_count=8"])
    assert rc == EXIT_OK
    (path,) = tmp_path.glob("N4-01-*.json")
    doc = json.loads(path.read_text())
    assert doc["dry_run"] is True
    assert doc["params"]["seid_count"] == 8
    assert doc["spoofed_sources"] == ["172.22.0.7"]
    assert doc["pfcp_seqs"] == []


@pytest.mark.parametrize(
    "args",
    [
        ["--param", "upf=8.8.8.8"],  # target outside the testbed
        ["--param", "smf=192.0.2.7"],  # spoofed source outside the testbed
        ["--attacker-ip", "10.0.0.5"],
    ],
)
def test_out_of_lab_addresses_are_refused_even_in_dry_run(tmp_path: Path, args: list[str]) -> None:
    assert main(["run", "N4-01", "--dry-run", "--out", str(tmp_path), *args]) == EXIT_REFUSED
    assert not list(tmp_path.iterdir())


def test_real_run_needs_lab_confirmation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PRAHARI_LAB", raising=False)
    assert main(["run", "SBI-01", "--out", str(tmp_path)]) == EXIT_REFUSED


@pytest.mark.parametrize("bad", ["nope=1", "rate=fast", "spoof=maybe", "novalue"])
def test_bad_parameters_are_usage_errors(tmp_path: Path, bad: str) -> None:
    assert main(["run", "N4-01", "--dry-run", "--out", str(tmp_path), "--param", bad]) == EXIT_USAGE
