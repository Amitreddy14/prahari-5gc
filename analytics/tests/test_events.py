"""Contract tests: the JSON Schema, the examples and the pydantic models must agree."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from prahari_analytics.events import SignallingEvent, supi_hash

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "schemas" / "event.v1.schema.json"
EXAMPLES = sorted((ROOT / "schemas" / "examples").glob("*.json"))


@pytest.fixture(scope="module")
def schema() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(data)
    return data


@pytest.fixture(scope="module")
def validator(schema: dict[str, Any]) -> Draft202012Validator:
    return Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)


def _example(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((ROOT / "schemas" / "examples" / name).read_text())
    return data


def test_examples_exist() -> None:
    assert len(EXAMPLES) >= 3


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_example_valid_against_schema_and_model(
    path: Path, validator: Draft202012Validator
) -> None:
    raw = path.read_text(encoding="utf-8")
    validator.validate(json.loads(raw))
    event = SignallingEvent.from_json(raw)
    assert event.schema_version == 1


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_round_trip_is_lossless(path: Path, validator: Draft202012Validator) -> None:
    event = SignallingEvent.from_json(path.read_text(encoding="utf-8"))
    dumped = json.loads(event.model_dump_json(exclude_none=True))
    validator.validate(dumped)
    assert SignallingEvent.model_validate_json(json.dumps(dumped)) == event


def test_model_fields_match_schema(schema: dict[str, Any]) -> None:
    """Drift guard: adding a field on one side only must fail CI."""
    assert set(SignallingEvent.model_fields) == set(schema["properties"])
    assert {n for n, f in SignallingEvent.model_fields.items() if f.is_required()} == set(
        schema["required"]
    )


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda e: e.update(extra_field=1), "unknown top-level field"),
        (lambda e: e.update(schema_version=2), "future schema version"),
        (lambda e: e.update(interface="N3"), "user plane is out of scope"),
        (lambda e: e["ue"].update(seid=42), "seid must be a decimal string"),
        (lambda e: e["ue"].update(supi="imsi-001010000000001"), "cleartext SUPI"),
        (lambda e: e.update(size_bytes=-1), "negative size"),
        (lambda e: e["src"].update(ip="999.1.1.1"), "invalid IP"),
    ],
)
def test_invalid_events_rejected_by_both(
    mutate: Any, reason: str, validator: Draft202012Validator
) -> None:
    event = _example("pfcp_session_establishment.json")
    mutate(event)
    assert list(validator.iter_errors(event)), f"schema accepted: {reason}"
    with pytest.raises(ValidationError):
        SignallingEvent.model_validate_json(json.dumps(event))


def test_supi_hash_is_keyed_stable_and_short() -> None:
    key = b"k" * 32
    h = supi_hash("imsi-001010000000001", key)
    assert len(h) == 16
    assert int(h, 16) >= 0
    assert h == supi_hash("imsi-001010000000001", key)
    assert h != supi_hash("imsi-001010000000001", b"x" * 32)
    assert h != supi_hash("imsi-001010000000002", key)


def test_supi_hash_rejects_weak_key() -> None:
    with pytest.raises(ValueError, match="at least 16 bytes"):
        supi_hash("imsi-001010000000001", b"short")
