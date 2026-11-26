"""Dataset builder: flattening, typed Parquet schema, stats, and the dataset card."""

from __future__ import annotations

from pathlib import Path

import pyarrow.parquet as pq

from prahari_analytics.dataset import FIELDS, Stats, build_table, dataset_card, flatten


def _event(**over: object) -> dict:
    ev = {
        "schema_version": 1,
        "event_id": "00000000-0000-0000-0000-000000000001",
        "ts_ns": 1_700_000_000_000_000_000,
        "interface": "N2",
        "protocol": "NGAP",
        "message": "InitialUEMessage",
        "message_code": 15,
        "direction": "indication",
        "src": {"ip": "172.22.0.40", "port": 38412, "nf": "gNB"},
        "dst": {"ip": "172.22.0.5", "port": 38412, "nf": "AMF"},
        "size_bytes": 77,
        "decode_status": "ok",
        "ue": {"ran_ue_ngap_id": 4242},
        "ngap": {"pdu_type": "initiating", "procedure_code": 15, "gnb_id": 2989},
        "labels": {"is_attack": True, "attack_id": "N2-01", "run_id": "N2-01-x"},
    }
    ev.update(over)
    return ev


def test_flatten_navigates_nested_objects_and_nulls_missing() -> None:
    row = flatten(_event())
    assert row["src_ip"] == "172.22.0.40"
    assert row["ran_ue_ngap_id"] == 4242
    assert row["ngap_gnb_id"] == 2989
    assert row["is_attack"] is True
    assert row["attack_id"] == "N2-01"
    assert row["sbi_method"] is None  # absent object -> null, no KeyError


def test_stats_count_classes_interfaces_and_window() -> None:
    stats = Stats()
    stats.add(_event())
    stats.add(_event(labels={"is_attack": False}, interface="N4", protocol="PFCP"))
    assert stats.rows == 2
    assert stats.attack_rows == 1
    assert stats.by_attack["N2-01"] == 1
    assert stats.by_attack["benign"] == 1
    assert stats.by_interface == {"N2": 1, "N4": 1}


def test_build_table_writes_typed_parquet(tmp_path: Path) -> None:
    stats = Stats()
    table = build_table([_event(), _event(labels={"is_attack": False})], stats)
    assert table.num_rows == 2
    assert set(table.column_names) == {col for col, _t, _p, _d in FIELDS}
    out = tmp_path / "d.parquet"
    pq.write_table(table, out)
    back = pq.read_table(out)
    assert back.num_rows == 2
    # types survive the round trip
    assert back.schema.field("ts_ns").type == table.schema.field("ts_ns").type
    assert back.schema.field("is_attack").type.equals(table.schema.field("is_attack").type)


def test_dataset_card_reports_balance_and_columns() -> None:
    stats = Stats()
    for _ in range(3):
        stats.add(_event())
    stats.add(_event(labels={"is_attack": False}))
    card = dataset_card(stats, name="v1", probe_version="0.6.0", campaign={"campaign": "demo"})
    assert "Rows: **4**" in card
    assert "N2-01" in card
    assert "`ran_ue_ngap_id`" in card
    assert "0.6.0" in card
    assert "demo" in card
