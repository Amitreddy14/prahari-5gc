"""PFCP (TS 29.244) message builder for the N4 scenarios, plus a minimal response parser.

Only what the scenarios send is implemented: Heartbeat, Association Setup/Release,
Session Establishment/Modification/Deletion with the IEs those need. The probe's C++
decoder is the independent check: tests decode every built message with it.
"""

from __future__ import annotations

import ipaddress
import struct
import time
from dataclasses import dataclass

VERSION = 1
NTP_EPOCH_OFFSET = 2_208_988_800  # seconds from 1900-01-01 to 1970-01-01


class MsgType:
    HEARTBEAT_REQUEST = 1
    HEARTBEAT_RESPONSE = 2
    ASSOCIATION_SETUP_REQUEST = 5
    ASSOCIATION_SETUP_RESPONSE = 6
    ASSOCIATION_RELEASE_REQUEST = 9
    ASSOCIATION_RELEASE_RESPONSE = 10
    SESSION_ESTABLISHMENT_REQUEST = 50
    SESSION_ESTABLISHMENT_RESPONSE = 51
    SESSION_MODIFICATION_REQUEST = 52
    SESSION_MODIFICATION_RESPONSE = 53
    SESSION_DELETION_REQUEST = 54
    SESSION_DELETION_RESPONSE = 55


class Ie:
    CREATE_PDR = 1
    PDI = 2
    CREATE_FAR = 3
    UPDATE_FAR = 10
    CAUSE = 19
    SOURCE_INTERFACE = 20
    F_TEID = 21
    NETWORK_INSTANCE = 22
    PRECEDENCE = 29
    APPLY_ACTION = 44
    PDR_ID = 56
    F_SEID = 57
    NODE_ID = 60
    UE_IP_ADDRESS = 93
    PDN_TYPE = 113
    RECOVERY_TIME_STAMP = 96
    FAR_ID = 108


class ApplyAction:
    DROP = 0x01
    FORW = 0x02
    BUFF = 0x04


CAUSE_NAMES = {
    1: "RequestAccepted",
    64: "RequestRejected",
    65: "SessionContextNotFound",
    66: "MandatoryIeMissing",
    67: "ConditionalIeMissing",
    68: "InvalidLength",
    69: "MandatoryIeIncorrect",
    70: "InvalidForwardingPolicy",
    71: "InvalidFTeidAllocationOption",
    72: "NoEstablishedPfcpAssociation",
    73: "RuleCreationModificationFailure",
    74: "PfcpEntityInCongestion",
    75: "NoResourcesAvailable",
    76: "ServiceNotSupported",
    77: "SystemFailure",
}


def ie(t: int, value: bytes) -> bytes:
    return struct.pack("!HH", t, len(value)) + value


def node_id_ipv4(ip: str) -> bytes:
    return ie(Ie.NODE_ID, b"\x00" + ipaddress.IPv4Address(ip).packed)


def recovery_time_stamp(unix_seconds: float | None = None) -> bytes:
    t = int(unix_seconds if unix_seconds is not None else time.time()) + NTP_EPOCH_OFFSET
    return ie(Ie.RECOVERY_TIME_STAMP, struct.pack("!I", t & 0xFFFFFFFF))


def f_seid(seid: int, ip: str) -> bytes:
    return ie(Ie.F_SEID, b"\x02" + struct.pack("!Q", seid) + ipaddress.IPv4Address(ip).packed)


def far_id(n: int) -> bytes:
    return ie(Ie.FAR_ID, struct.pack("!I", n))


def apply_action(flags: int) -> bytes:
    return ie(Ie.APPLY_ACTION, bytes([flags]))


def create_pdr(pdr_id: int, far: int, ue_ip: str) -> bytes:
    pdi = (
        ie(Ie.SOURCE_INTERFACE, b"\x00")  # access
        + ie(Ie.F_TEID, b"\x05")  # V4 + CH: the UPF chooses the TEID
        + ie(Ie.NETWORK_INSTANCE, b"\x08internet")
        + ie(Ie.UE_IP_ADDRESS, b"\x02" + ipaddress.IPv4Address(ue_ip).packed)  # V4, source
    )
    body = (
        ie(Ie.PDR_ID, struct.pack("!H", pdr_id))
        + ie(Ie.PRECEDENCE, struct.pack("!I", 255))
        + ie(Ie.PDI, pdi)
        + far_id(far)
    )
    return ie(Ie.CREATE_PDR, body)


def create_far(far: int, action: int = ApplyAction.FORW) -> bytes:
    return ie(Ie.CREATE_FAR, far_id(far) + apply_action(action))


def update_far(far: int, action: int) -> bytes:
    return ie(Ie.UPDATE_FAR, far_id(far) + apply_action(action))


def message(msg_type: int, seq: int, body: bytes, seid: int | None = None) -> bytes:
    """Header (TS 29.244 7.2.2) + IEs. `seid` set => S flag and SEID field present."""
    if not 0 <= seq < 1 << 24:
        raise ValueError("PFCP sequence number is 24 bits")
    flags = VERSION << 5
    rest = b""
    if seid is not None:
        flags |= 0x01
        rest = struct.pack("!Q", seid)
    rest += struct.pack("!I", seq << 8)  # 3-byte sequence + spare
    rest += body
    return struct.pack("!BBH", flags, msg_type, len(rest)) + rest


# ----------------------------------------------------------------- messages


def heartbeat_request(seq: int) -> bytes:
    return message(MsgType.HEARTBEAT_REQUEST, seq, recovery_time_stamp())


def heartbeat_response(seq: int) -> bytes:
    return message(MsgType.HEARTBEAT_RESPONSE, seq, recovery_time_stamp())


def association_setup_request(seq: int, node_ip: str) -> bytes:
    return message(
        MsgType.ASSOCIATION_SETUP_REQUEST, seq, node_id_ipv4(node_ip) + recovery_time_stamp()
    )


def association_release_request(seq: int, node_ip: str) -> bytes:
    return message(MsgType.ASSOCIATION_RELEASE_REQUEST, seq, node_id_ipv4(node_ip))


def session_establishment_request(seq: int, node_ip: str, cp_seid: int, ue_ip: str) -> bytes:
    body = (
        node_id_ipv4(node_ip)
        + f_seid(cp_seid, node_ip)
        + create_pdr(1, 1, ue_ip)
        + create_far(1, ApplyAction.FORW)
        + ie(Ie.PDN_TYPE, b"\x01")  # IPv4
    )
    return message(MsgType.SESSION_ESTABLISHMENT_REQUEST, seq, body, seid=0)


def session_modification_request(seq: int, up_seid: int, far: int, action: int) -> bytes:
    return message(MsgType.SESSION_MODIFICATION_REQUEST, seq, update_far(far, action), seid=up_seid)


def session_deletion_request(seq: int, up_seid: int) -> bytes:
    return message(MsgType.SESSION_DELETION_REQUEST, seq, b"", seid=up_seid)


# ----------------------------------------------------------------- parsing


@dataclass(frozen=True)
class Response:
    msg_type: int
    seq: int
    seid: int | None
    cause: int | None
    up_seid: int | None  # from the F-SEID IE (Establishment Response)

    @property
    def cause_name(self) -> str:
        if self.cause is None:
            return "None"
        return CAUSE_NAMES.get(self.cause, f"Cause{self.cause}")


def parse(data: bytes) -> Response:
    """Header, Cause and F-SEID of one PFCP message. Raises ValueError if malformed."""
    if len(data) < 8:
        raise ValueError("short PFCP message")
    flags, msg_type, length = struct.unpack("!BBH", data[:4])
    if flags >> 5 != VERSION or length + 4 > len(data):
        raise ValueError("bad PFCP header")
    off = 4
    seid = None
    if flags & 0x01:
        (seid,) = struct.unpack("!Q", data[off : off + 8])
        off += 8
    seq = struct.unpack("!I", data[off : off + 4])[0] >> 8
    off += 4
    cause = None
    up_seid = None
    end = 4 + length
    while off + 4 <= end:
        t, ln = struct.unpack("!HH", data[off : off + 4])
        v = data[off + 4 : off + 4 + ln]
        if t == Ie.CAUSE and ln >= 1:
            cause = v[0]
        elif t == Ie.F_SEID and ln >= 9:
            (up_seid,) = struct.unpack("!Q", v[1:9])
        off += 4 + ln
    return Response(msg_type, seq, seid, cause, up_seid)
