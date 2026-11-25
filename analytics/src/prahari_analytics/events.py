"""Event contract v1: the Python mirror of ``schemas/event.v1.schema.json``.

The C++ probe produces these as JSON Lines on Kafka topic ``prahari.events.v1``.
Models are strict and frozen: unknown fields are rejected so a schema change in the
probe can never be silently ignored here.
"""

from __future__ import annotations

import hashlib
import hmac
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

KAFKA_TOPIC = "prahari.events.v1"
SCHEMA_VERSION: Literal[1] = 1

Interface = Literal["N2", "N4", "SBI"]
Protocol = Literal["NGAP", "NAS-5GS", "PFCP", "HTTP2"]
Direction = Literal["request", "response", "indication", "unknown"]
DecodeStatus = Literal["ok", "truncated", "bad_version", "bad_length", "unsupported", "malformed"]
NetworkFunction = Literal[
    "gNB", "AMF", "SMF", "UPF", "NRF", "AUSF", "UDM", "UDR", "PCF", "NSSF", "BSF", "UE", "unknown"
]
HttpMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]

Port = Annotated[int, Field(ge=0, le=65535)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Endpoint(_Strict):
    ip: IPv4Address | IPv6Address
    port: Port
    nf: NetworkFunction | None = None


class UeContext(_Strict):
    ran_ue_ngap_id: Annotated[int, Field(ge=0, le=4_294_967_295)] | None = None
    amf_ue_ngap_id: Annotated[int, Field(ge=0, le=1_099_511_627_775)] | None = None
    supi_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{16}$")] | None = None
    seid: Annotated[str, Field(pattern=r"^[0-9]{1,20}$")] | None = None
    pdu_session_id: Annotated[int, Field(ge=0, le=255)] | None = None


class SbiInfo(_Strict):
    method: HttpMethod | None = None
    path: Annotated[str, Field(max_length=256)] | None = None
    status: Annotated[int, Field(ge=100, le=599)] | None = None
    service: Annotated[str, Field(max_length=32)] | None = None


class Labels(_Strict):
    is_attack: bool
    attack_id: Annotated[str, Field(pattern=r"^(N2|N4|SBI|UE)-[0-9]{2}$")] | None = None
    run_id: Annotated[str, Field(max_length=64)] | None = None


class SignallingEvent(_Strict):
    schema_version: Literal[1]
    event_id: UUID
    ts_ns: Annotated[int, Field(ge=0)]
    interface: Interface
    protocol: Protocol
    message: Annotated[str, Field(min_length=1, max_length=96)]
    message_code: Annotated[int, Field(ge=0, le=65535)]
    direction: Direction = "unknown"
    src: Endpoint
    dst: Endpoint
    size_bytes: Annotated[int, Field(ge=0, le=65535)]
    decode_status: DecodeStatus
    ue: UeContext | None = None
    sequence: Annotated[int, Field(ge=0, le=16_777_215)] | None = None
    cause: Annotated[str, Field(max_length=64)] | None = None
    sbi: SbiInfo | None = None
    labels: Labels | None = None

    @classmethod
    def from_json(cls, raw: str | bytes) -> SignallingEvent:
        return cls.model_validate_json(raw)


def supi_hash(supi: str, key: bytes) -> str:
    """Pseudonymise a SUPI/IMSI: first 64 bits of HMAC-SHA256(key, SUPI) as hex.

    The probe implements the same function in C++; both must agree byte-for-byte.
    A keyed hash (not a bare SHA-256) is required because the IMSI space is small
    enough to brute-force an unkeyed hash.
    """
    if len(key) < 16:
        raise ValueError("SUPI hash key must be at least 16 bytes")
    return hmac.new(key, supi.encode("ascii"), hashlib.sha256).hexdigest()[:16]
