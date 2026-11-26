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

from prahari_analytics.events import SignallingEvent, supi_hash

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "probe" / "tests" / "data"
FIXTURE = DATA / "n4-lifecycle.pcap"
N2_FIXTURE = DATA / "n2-registration.pcap"
PROBE = os.environ.get("PRAHARI_PROBE_BIN")
# Test-only key; the N2 fixture's UE is IMSI 001010000000008.
SUPI_KEY = "prahari-test-key-0123456789abcdef"
FIXTURE_IMSI = "001010000000008"


def run_probe(pcap: Path, supi_key: str | None = None) -> list[str]:
    assert PROBE is not None
    env = {k: v for k, v in os.environ.items() if k != "PRAHARI_SUPI_KEY"}
    if supi_key is not None:
        env["PRAHARI_SUPI_KEY"] = supi_key
    return subprocess.run(
        [PROBE, "run", "--pcap", str(pcap), "--seed", "1"],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    ).stdout.splitlines()


pytestmark = pytest.mark.skipif(not PROBE, reason="set PRAHARI_PROBE_BIN to run")


@pytest.fixture(scope="module")
def lines() -> list[str]:
    return run_probe(FIXTURE)


@pytest.fixture(scope="module")
def n2_lines() -> list[str]:
    return run_probe(N2_FIXTURE, SUPI_KEY)


@pytest.mark.parametrize(("pcap", "expected"), [(FIXTURE, 24), (N2_FIXTURE, 23)])
def test_every_line_matches_schema_and_model(pcap: Path, expected: int) -> None:
    schema: dict[str, Any] = json.loads(
        (ROOT / "schemas" / "event.v1.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
    out = run_probe(pcap, SUPI_KEY)
    assert len(out) == expected
    for line in out:
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
    assert run_probe(FIXTURE) == lines


def test_registration_flow_on_n2(n2_lines: list[str]) -> None:
    events = [SignallingEvent.from_json(line) for line in n2_lines]
    assert all(e.interface == "N2" for e in events)
    setup = events[0]
    assert setup.message == "NGSetupRequest"
    assert setup.ngap is not None
    assert setup.ngap.plmn == "00101"
    assert setup.src.nf == "gNB"
    assert setup.dst.nf == "AMF"
    reg = next(e for e in events if e.nas is not None and e.nas.message == "RegistrationRequest")
    assert reg.nas is not None
    assert reg.nas.identity_type == "SUCI"
    assert reg.nas.suci_null_scheme is True
    # NEA0 is tracked from the Security Mode Command, so nothing stays opaque.
    assert all(e.nas.decoded for e in events if e.nas is not None)


def test_probe_and_python_agree_on_the_supi_pseudonym(n2_lines: list[str]) -> None:
    events = [SignallingEvent.from_json(line) for line in n2_lines]
    hashes = {e.ue.supi_hash for e in events if e.ue is not None and e.ue.supi_hash}
    assert hashes == {supi_hash(f"imsi-{FIXTURE_IMSI}", SUPI_KEY.encode())}
    # The raw identity never leaves the probe.
    assert not any(FIXTURE_IMSI[5:] in line for line in n2_lines)


def test_without_a_key_supis_are_dropped_not_leaked() -> None:
    out = run_probe(N2_FIXTURE)
    assert len(out) == 23
    for line in out:
        ue = SignallingEvent.from_json(line).ue
        assert ue is None or ue.supi_hash is None
    assert not any(FIXTURE_IMSI[5:] in line for line in out)
