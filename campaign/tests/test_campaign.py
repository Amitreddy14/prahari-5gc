"""Campaign orchestration: spec parsing, ordered firing, and the campaign manifest."""

from __future__ import annotations

import json
from pathlib import Path

from prahari_campaign.campaign import Campaign, CampaignSpec, load_spec

SPEC = {
    "name": "t",
    "tail_seconds": 1,
    "benign": {"ue_count": 2, "rate": 0.0, "seed": 1},
    "steps": [
        {"at": 2, "id": "N2-02", "params": {"count": "1"}},
        {"at": 1, "id": "SBI-01"},
    ],
}


def test_spec_sorts_steps_and_computes_duration() -> None:
    spec = CampaignSpec.from_dict(SPEC)
    assert [s.attack_id for s in spec.steps] == ["SBI-01", "N2-02"]  # sorted by at
    assert spec.duration == 3.0  # last at (2) + tail (1)
    assert spec.benign is not None
    assert spec.benign.ue_count == 2


def test_load_spec_json(tmp_path: Path) -> None:
    p = tmp_path / "c.json"
    p.write_text(json.dumps(SPEC), encoding="utf-8")
    assert load_spec(p).name == "t"


def test_run_fires_attacks_in_order_and_writes_manifest(tmp_path: Path) -> None:
    fired: list[str] = []

    def attack_runner(attack_id: str, params: dict, out_dir: Path) -> dict:
        fired.append(attack_id)
        return {"status": "ok", "returncode": 0, "run_id": f"{attack_id}-x"}

    cli_calls: list[tuple[str, str]] = []
    clock = {"t": 0.0}

    spec = CampaignSpec.from_dict(SPEC)
    campaign = Campaign(
        spec,
        attack_runner=attack_runner,
        run_cli=lambda imsi, cmd: cli_calls.append((imsi, cmd)) or "",
        sleep=lambda dt: clock.__setitem__("t", clock["t"] + dt),
        clock=lambda: clock["t"],
    )
    manifest = campaign.run(tmp_path)

    assert fired == ["SBI-01", "N2-02"]  # fired in schedule order
    assert [a["attack_id"] for a in manifest["attacks"]] == ["SBI-01", "N2-02"]
    assert manifest["benign"]["enabled"] is True
    assert (tmp_path / "campaign.json").exists()
    on_disk = json.loads((tmp_path / "campaign.json").read_text())
    assert on_disk["campaign"] == "t"
    assert on_disk["ended_ns"] >= on_disk["started_ns"]


def test_no_benign_when_run_cli_is_none(tmp_path: Path) -> None:
    spec = CampaignSpec.from_dict(SPEC)
    campaign = Campaign(
        spec,
        attack_runner=lambda i, p, o: {"returncode": 0},
        run_cli=None,
        sleep=lambda dt: None,
        clock=lambda: 999.0,  # already past every deadline
    )
    manifest = campaign.run(tmp_path)
    assert manifest["benign"] == {"enabled": False}
    assert len(manifest["attacks"]) == 2
