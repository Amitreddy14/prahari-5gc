"""PFCP encoder: structure, round trip, and (if available) the C++ probe as an oracle."""

from __future__ import annotations

import os
import struct
import subprocess

import pytest

from prahari_attacks import pfcp

PROBE = os.environ.get("PRAHARI_PROBE_BIN")


def all_messages() -> dict[str, tuple[bytes, int, int]]:
    return {
        "HeartbeatRequest": (pfcp.heartbeat_request(0xA00001), 1, 0xA00001),
        "HeartbeatResponse": (pfcp.heartbeat_response(0xA00002), 2, 0xA00002),
        "AssociationSetupRequest": (
            pfcp.association_setup_request(0xA00003, "172.22.0.40"),
            5,
            0xA00003,
        ),
        "AssociationReleaseRequest": (pfcp.association_release_request(7, "172.22.0.7"), 9, 7),
        "SessionEstablishmentRequest": (
            pfcp.session_establishment_request(0xA00004, "172.22.0.40", 0x1234, "10.45.200.1"),
            50,
            0xA00004,
        ),
        "SessionModificationRequest": (
            pfcp.session_modification_request(0xA00005, 172, 1, pfcp.ApplyAction.DROP),
            52,
            0xA00005,
        ),
        "SessionDeletionRequest": (pfcp.session_deletion_request(0xFFFFFF, 4096), 54, 0xFFFFFF),
    }


@pytest.mark.parametrize("name", list(all_messages()))
def test_header_length_and_round_trip(name: str) -> None:
    msg, mtype, seq = all_messages()[name]
    flags, t, length = struct.unpack("!BBH", msg[:4])
    assert flags >> 5 == 1  # version 1
    assert t == mtype
    assert length == len(msg) - 4
    r = pfcp.parse(msg)
    assert (r.msg_type, r.seq) == (mtype, seq)


def test_session_messages_carry_the_seid() -> None:
    assert pfcp.parse(pfcp.session_deletion_request(1, 4096)).seid == 4096
    assert pfcp.parse(pfcp.session_modification_request(1, 99, 1, 1)).seid == 99
    assert (
        pfcp.parse(pfcp.session_establishment_request(1, "172.22.0.40", 5, "10.45.0.9")).seid == 0
    )
    assert pfcp.parse(pfcp.heartbeat_request(1)).seid is None


def test_sequence_is_24_bits() -> None:
    with pytest.raises(ValueError, match="24 bits"):
        pfcp.message(1, 1 << 24, b"")


def test_parse_reads_cause_and_f_seid_of_a_response() -> None:
    body = pfcp.ie(pfcp.Ie.CAUSE, b"\x01") + pfcp.f_seid(3114, "172.22.0.8")
    r = pfcp.parse(pfcp.message(pfcp.MsgType.SESSION_ESTABLISHMENT_RESPONSE, 9, body, seid=7))
    assert (r.cause, r.cause_name, r.up_seid, r.seid) == (1, "RequestAccepted", 3114, 7)


@pytest.mark.parametrize(
    "bad",
    [b"", b"\x21\x01", b"\x41\x01\x00\x04\x00\x00\x00\x00", b"\x21\x01\xff\xff\x00\x00\x00\x00"],
)
def test_parse_rejects_malformed(bad: bytes) -> None:
    with pytest.raises(ValueError, match="PFCP"):
        pfcp.parse(bad)


@pytest.mark.skipif(not PROBE, reason="set PRAHARI_PROBE_BIN to cross-check with the C++ probe")
@pytest.mark.parametrize("name", list(all_messages()))
def test_cpp_probe_decodes_every_message(name: str) -> None:
    msg, _, seq = all_messages()[name]
    assert PROBE is not None
    out = subprocess.run(
        [PROBE, "decode-pfcp", msg.hex()], check=True, capture_output=True, text=True
    ).stdout
    assert f'"message":"{name}"' in out
    assert f'"sequence":{seq}' in out
