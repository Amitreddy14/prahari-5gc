"""Cross-language contract test: real prahari-probe output must satisfy the Python models.

Runs only when PRAHARI_PROBE_BIN points at a built probe (CI's probe-contract job sets it):

    PRAHARI_PROBE_BIN=probe/build/release/prahari-probe pytest analytics/tests
"""

from __future__ import annotations

import json
import os
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from prahari_analytics.events import SignallingEvent

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "probe" / "tests" / "data" / "n4-lifecycle.pcap"
PROBE = os.environ.get("PRAHARI_PROBE_BIN")

pytestmark = pytest.mark.skipif(not PROBE, reason="set PRAHARI_PROBE_BIN to run")


@pytest.fixture(scope="module")
def lines() -> list[str]:
    assert PROBE is not None
    out = subprocess.run(
        [PROBE, "run", "--pcap", str(FIXTURE), "--seed", "1"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return out.splitlines()


def test_every_line_matches_schema_and_model(lines: list[str]) -> None:
    schema: dict[str, Any] = json.loads(
        (ROOT / "schemas" / "event.v1.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
    assert len(lines) == 24
    for line in lines:
        validator.validate(json.loads(line))
        SignallingEvent.from_json(line)


def test_lifecycle_counts_and_session_linking(lines: list[str]) -> None:
    events = [SignallingEvent.from_json(line) for line in lines]
    counts = Counter(e.message for e in events)
    assert counts["SessionEstablishmentRequest"] == 3
    assert counts["SessionDeletionResponse"] == 3
    deletions = [e for e in events if e.message == "SessionDeletionRequest"]
    for d in deletions:
        assert d.pfcp is not None
        assert d.pfcp.session_known is True
        assert d.pfcp.cp_seid is not None
        assert d.pfcp.up_seid is not None
        assert d.src.nf == "SMF"
        assert d.dst.nf == "UPF"


def test_seeded_output_is_reproducible(lines: list[str]) -> None:
    assert PROBE is not None
    again = subprocess.run(
        [PROBE, "run", "--pcap", str(FIXTURE), "--seed", "1"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    assert again == lines
