"""NGAP builders: pycrate as an oracle, the C++ probe as a second oracle, fuzz determinism.

The compatibility proof is test_pycrate_round_trips_real_testbed_traffic: pycrate's NGAP
release re-encodes this testbed's own UERANSIM/Open5GS PDUs byte-for-byte, so anything the
builders produce is wire-identical to what the AMF already accepts.
"""

from __future__ import annotations

import os
import random
import subprocess

import pytest

from prahari_attacks import ngap
from prahari_attacks.scenarios.n2 import fuzz_mutate

PROBE = os.environ.get("PRAHARI_PROBE_BIN")

# Real PDUs captured from testbed/probe/tests/data/n2-registration.pcap.
REAL = {
    "NGSetupRequest": bytes.fromhex(
        "0015003e000004001b00090000f1105000000001005240140880554552414e53494d2d"
        "676e622d312d312d310066000d00000000010000f110000000080015400140"
    ),
    "NGSetupResponse": bytes.fromhex(
        "201500320000040001000e0580707261686172692d616d663000600008000000f110020040"
        "00564001ff005000080000f11000000008"
    ),
    "InitialUEMessage": bytes.fromhex(
        "000f40480000050055000200010026001a197e004179000d0100f11000000000000000"
        "00802e04f0f0f0f0007900135000f110000000010000f110000001eeb17933005a40011"
        "80070400100"
    ),
    "DownlinkNASTransport": bytes.fromhex(
        "0004403e000003000a000200010055000200010026002b2a7e00560002000021dbf1092b6f"
        "bd975c2f5d4eb61e824f3b201018e6811ae63b800033d91cea911da306"
    ),
}


@pytest.mark.parametrize("name", list(REAL))
def test_pycrate_round_trips_real_testbed_traffic(name: str) -> None:
    # The whole N2 phase rests on this: decode + re-encode must be byte-identical.
    d = ngap.parse(REAL[name])
    assert d.message == name
    assert ngap._encode(ngap._decode(REAL[name])) == REAL[name]


def test_ng_setup_request_sets_identity() -> None:
    pdu = ngap.ng_setup_request(0xBAD, name="PRAHARI-rogue")
    d = ngap.parse(pdu)
    assert (d.pdu_type, d.procedure_code, d.message) == (
        "initiatingMessage",
        ngap.PROC_NG_SETUP,
        "NGSetupRequest",
    )


def test_initial_ue_message_sets_ran_ue_and_nas() -> None:
    custom = ngap.templated_nas()
    d = ngap.parse(ngap.initial_ue_message(4242, nas=custom))
    assert d.procedure_code == ngap.PROC_INITIAL_UE_MESSAGE
    assert d.ran_ue_ngap_id == 4242
    assert d.nas_pdus == [custom]


def test_ue_context_release_request_carries_both_ids() -> None:
    d = ngap.parse(ngap.ue_context_release_request(12345, 7))
    assert d.procedure_code == ngap.PROC_UE_CONTEXT_RELEASE_REQUEST
    assert (d.amf_ue_ngap_id, d.ran_ue_ngap_id) == (12345, 7)


def test_fuzz_mutate_is_deterministic_and_never_raises() -> None:
    tmpls = list(ngap.templates().values())
    a = [fuzz_mutate(random.Random(99), tmpls) for _ in range(50)]
    b = [fuzz_mutate(random.Random(99), tmpls) for _ in range(50)]
    assert a == b  # same seed -> same bytes (reproducible dataset runs)


@pytest.mark.skipif(not PROBE, reason="set PRAHARI_PROBE_BIN to cross-check with the C++ probe")
def test_cpp_probe_decodes_generated_ngap() -> None:
    assert PROBE is not None
    cases = {
        ngap.ng_setup_request(0xBAD, name="PRAHARI-rogue-0"): (
            '"message":"NGSetupRequest"',
            '"gnb_id":2989',
        ),
        ngap.initial_ue_message(4242): (
            '"message":"InitialUEMessage"',
            '"ran_ue_ngap_id":4242',
        ),
        ngap.ue_context_release_request(12345, 7): (
            '"message":"UEContextReleaseRequest"',
            '"amf_ue_ngap_id":12345',
        ),
    }
    for pdu, needles in cases.items():
        out = subprocess.run(
            [PROBE, "decode-ngap", pdu.hex()], check=True, capture_output=True, text=True
        ).stdout
        for needle in needles:
            assert needle in out, out
