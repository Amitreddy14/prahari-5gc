"""NGAP (N2) message building for the injector, via pycrate's NGAP ASN.1 (TS 38.413).

PFCP is simple TLV, so pfcp.py hand-rolls it. NGAP is ASN.1 Aligned PER, where a
hand-rolled encoder would be both large and a liability (an off-by-one bit is a PDU
the AMF silently drops). This module leans on pycrate instead, whose NGAP release
round-trips this testbed's own UERANSIM/Open5GS traffic byte-for-byte -- proven in
tests/test_ngap.py against the probe's n2-registration fixture, and documented in
docs/adr/0009-n2-injection-and-dataset.md.

Two messages (NG Setup Request, Initial UE Message) are templated from that real,
AMF-accepted capture and mutated; UE Context Release Request is built from scratch.
pycrate is imported lazily so the CLI, dry runs, and the N4/SBI attacks never pay
its import cost or need it installed.
"""

from __future__ import annotations

import threading
from copy import deepcopy
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

# Captured from testbed/probe/tests/data/n2-registration.pcap (UERANSIM gNB -> Open5GS
# AMF, PLMN 001/01). Lab fixtures, embedded so building needs no pcap at runtime.
_NG_SETUP_REQUEST = bytes.fromhex(
    "0015003e000004001b00090000f1105000000001005240140880554552414e53494d2d"
    "676e622d312d312d310066000d00000000010000f110000000080015400140"
)
_INITIAL_UE_MESSAGE = bytes.fromhex(
    "000f40480000050055000200010026001a197e004179000d0100f11000000000000000"
    "00802e04f0f0f0f0007900135000f110000000010000f110000001eeb17933005a40011"
    "80070400100"
)

# ProtocolIE ids and procedure codes we reference (TS 38.413).
_IE_AMF_UE_NGAP_ID = 10
_IE_CAUSE = 15
_IE_GLOBAL_RAN_NODE_ID = 27
_IE_NAS_PDU = 38
_IE_RAN_NODE_NAME = 82
_IE_RAN_UE_NGAP_ID = 85

PROC_NG_SETUP = 21
PROC_INITIAL_UE_MESSAGE = 15
PROC_UE_CONTEXT_RELEASE_REQUEST = 42

_lock = threading.Lock()


@lru_cache(maxsize=1)
def _pdu() -> Any:
    from pycrate_asn1dir import NGAP  # noqa: PLC0415

    return NGAP.NGAP_PDU_Descriptions.NGAP_PDU


def _encode(value: Any) -> bytes:
    with _lock:
        pdu = _pdu()
        pdu.set_val(value)
        return bytes(pdu.to_aper())


def _decode(data: bytes) -> Any:
    with _lock:
        pdu = _pdu()
        pdu.from_aper(data)
        return deepcopy(pdu.get_val())


def _template(raw: bytes) -> Any:
    return _decode(raw)


def _ies(value: Any) -> Any:  # pycrate's dynamic ProtocolIE-Container (a list of dicts)
    return value[1]["value"][1]["protocolIEs"]


@dataclass
class Decoded:
    """What the injector needs from an AMF response (NG Setup Response/Failure,
    Downlink NAS Transport). Everything else is left in `ies`."""

    pdu_type: str  # initiatingMessage | successfulOutcome | unsuccessfulOutcome
    procedure_code: int
    message: str
    cause: str | None = None
    amf_ue_ngap_id: int | None = None
    ran_ue_ngap_id: int | None = None
    nas_pdus: list[bytes] = field(default_factory=list)
    ies: list[int] = field(default_factory=list)


def ng_setup_request(gnb_id: int, *, name: str = "PRAHARI-gnb", gnb_id_bits: int = 32) -> bytes:
    """A gNB claiming identity `gnb_id` (keeps the testbed PLMN 001/01 and TAC)."""
    value = _template(_NG_SETUP_REQUEST)
    for ie in _ies(value):
        if ie["id"] == _IE_GLOBAL_RAN_NODE_ID:
            masked = gnb_id & ((1 << gnb_id_bits) - 1)
            ie["value"][1][1]["gNB-ID"] = ("gNB-ID", (masked, gnb_id_bits))
        elif ie["id"] == _IE_RAN_NODE_NAME:
            ie["value"] = ("RANNodeName", name)
    return _encode(value)


def initial_ue_message(ran_ue_ngap_id: int, nas: bytes | None = None) -> bytes:
    """Initial UE Message carrying a NAS Registration Request. A fresh RAN-UE-NGAP-ID
    makes the AMF allocate a new RAN UE context; `nas` overrides the templated NAS."""
    value = _template(_INITIAL_UE_MESSAGE)
    for ie in _ies(value):
        if ie["id"] == _IE_RAN_UE_NGAP_ID:
            ie["value"] = ("RAN-UE-NGAP-ID", ran_ue_ngap_id)
        elif ie["id"] == _IE_NAS_PDU and nas is not None:
            ie["value"] = ("NAS-PDU", nas)
    return _encode(value)


def templated_nas() -> bytes:
    """The real NAS Registration Request embedded in the Initial UE Message template."""
    for ie in _ies(_template(_INITIAL_UE_MESSAGE)):
        if ie["id"] == _IE_NAS_PDU:
            return bytes(ie["value"][1])
    raise RuntimeError("template has no NAS-PDU")  # pragma: no cover


def ue_context_release_request(
    amf_ue_ngap_id: int, ran_ue_ngap_id: int, cause: str = "user-inactivity"
) -> bytes:
    """gNB-initiated UE Context Release Request for one UE context."""
    value = (
        "initiatingMessage",
        {
            "procedureCode": PROC_UE_CONTEXT_RELEASE_REQUEST,
            "criticality": "ignore",
            "value": (
                "UEContextReleaseRequest",
                {
                    "protocolIEs": [
                        {
                            "id": _IE_AMF_UE_NGAP_ID,
                            "criticality": "reject",
                            "value": ("AMF-UE-NGAP-ID", amf_ue_ngap_id),
                        },
                        {
                            "id": _IE_RAN_UE_NGAP_ID,
                            "criticality": "reject",
                            "value": ("RAN-UE-NGAP-ID", ran_ue_ngap_id),
                        },
                        {
                            "id": _IE_CAUSE,
                            "criticality": "ignore",
                            "value": ("Cause", ("radioNetwork", cause)),
                        },
                    ]
                },
            ),
        },
    )
    return _encode(value)


def parse(data: bytes) -> Decoded:
    """Decode an NGAP PDU far enough to read a response. Raises on undecodable input."""
    value = _decode(data)
    pdu_type = value[0]
    body = value[1]
    msg_name = body["value"][0]
    out = Decoded(pdu_type=pdu_type, procedure_code=int(body["procedureCode"]), message=msg_name)
    for ie in body["value"][1]["protocolIEs"]:
        out.ies.append(int(ie["id"]))
        _name, val = ie["value"]
        if ie["id"] == _IE_AMF_UE_NGAP_ID:
            out.amf_ue_ngap_id = int(val)
        elif ie["id"] == _IE_RAN_UE_NGAP_ID:
            out.ran_ue_ngap_id = int(val)
        elif ie["id"] == _IE_NAS_PDU:
            out.nas_pdus.append(bytes(val))
        elif ie["id"] == _IE_CAUSE and isinstance(val, tuple):
            out.cause = f"{val[0]}:{val[1]}"
    return out


def templates() -> dict[str, bytes]:
    """The valid PDUs a fuzzer mutates, by name."""
    return {
        "NGSetupRequest": _NG_SETUP_REQUEST,
        "InitialUEMessage": _INITIAL_UE_MESSAGE,
        "UEContextReleaseRequest": ue_context_release_request(1, 1),
    }
