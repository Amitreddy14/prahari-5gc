"""N2 scenario orchestration, with a fake SCTP association (the sandbox has no SCTP
stack; the live association is exercised on the testbed). Also the guard's N2 refusals."""

from __future__ import annotations

import time

import pytest

from prahari_attacks.guard import Guard, SctpAssociation, TargetNotAllowedError
from prahari_attacks.manifest import Manifest
from prahari_attacks.scenarios.base import Context
from prahari_attacks.scenarios.n2 import (
    _N2,
    ForgedUeRelease,
    NgapFuzz,
    RegistrationStorm,
    RogueGnb,
)

NG_SETUP_RESPONSE = bytes.fromhex(
    "201500320000040001000e0580707261686172692d616d663000600008000000f110020040"
    "00564001ff005000080000f11000000008"
)
DOWNLINK_NAS = bytes.fromhex(
    "0004403e000003000a000200010055000200010026002b2a7e00560002000021dbf1092b6f"
    "bd975c2f5d4eb61e824f3b201018e6811ae63b800033d91cea911da306"
)


class FakeSock:
    """Minimal pysctp one-to-one socket: records sends, replays canned replies."""

    def __init__(self, replies: list[bytes]) -> None:
        self.sent: list[bytes] = []
        self._replies = list(replies)

    def sctp_send(self, pdu: bytes, ppid: int = 60) -> None:
        self.sent.append(pdu)

    def sctp_recv(self, maxlen: int) -> tuple:
        if self._replies:
            return (("", 0), 0, self._replies.pop(0), None)
        raise TimeoutError

    def settimeout(self, t: float) -> None:
        pass

    def close(self) -> None:
        pass


def _run(scn: type[_N2], params: dict, replies: list[bytes]) -> tuple[Manifest, FakeSock]:
    guard = Guard.for_targets(scn.targets(params))
    sock = FakeSock(replies)
    assoc = SctpAssociation(guard, sock)
    guard.sctp_connect = lambda ip, port, **kw: assoc  # type: ignore[method-assign]
    m = Manifest(scn.attack_id, scn.title, params, "172.22.0.40", scn.targets(params))
    ctx = Context(guard, m, params, attacker_ip="172.22.0.40", stop_at=time.monotonic() + 30)
    m.start()
    scn().run(ctx)
    m.finish()
    return m, sock


def test_rogue_gnb_records_ng_setup_verdict() -> None:
    m, sock = _run(RogueGnb, RogueGnb.defaults(), [NG_SETUP_RESPONSE])
    assert m.outcome["accepted"] == 1
    assert m.outcome["setups"] == ["accepted"]
    assert len(sock.sent) == 1


def test_registration_storm_sends_setup_then_initial_ue_messages() -> None:
    p = RegistrationStorm.defaults() | {"count": 5, "rate": 0.0, "vary_suci": True}
    m, sock = _run(RegistrationStorm, p, [NG_SETUP_RESPONSE, DOWNLINK_NAS, DOWNLINK_NAS])
    assert m.outcome["association"] == "accepted"
    assert m.outcome["sent"] == 5
    assert len(sock.sent) == 6  # 1 NG Setup + 5 Initial UE Messages
    assert m._counts["sent:InitialUEMessage"] == 5
    assert m._counts["response:DownlinkNASTransport"] == 2


def test_registration_storm_without_suci_variation_reuses_template() -> None:
    p = RegistrationStorm.defaults() | {"count": 3, "rate": 0.0, "vary_suci": False}
    _m, sock = _run(RegistrationStorm, p, [NG_SETUP_RESPONSE])
    assert len({bytes(x) for x in sock.sent[1:]}) == 3  # distinct RAN-UE-NGAP-IDs


def test_forged_release_sweeps_amf_ue_ids() -> None:
    p = ForgedUeRelease.defaults() | {"amf_ue_count": 4, "rate": 0.0}
    m, sock = _run(ForgedUeRelease, p, [NG_SETUP_RESPONSE])
    assert m.outcome["swept"] == 4
    assert len(sock.sent) == 5  # 1 NG Setup + 4 releases
    assert m._counts["sent:UEContextReleaseRequest"] == 4


def test_fuzz_sends_count_and_is_reproducible() -> None:
    p = NgapFuzz.defaults() | {"count": 10, "rate": 0.0, "seed": 7}
    m1, s1 = _run(NgapFuzz, p, [NG_SETUP_RESPONSE])
    _m2, s2 = _run(NgapFuzz, p, [NG_SETUP_RESPONSE])
    assert m1.outcome["sent"] == 10
    assert s1.sent[1:] == s2.sent[1:]  # same seed -> identical fuzz payloads


@pytest.mark.parametrize("scn", [RegistrationStorm, RogueGnb, ForgedUeRelease, NgapFuzz])
def test_targets_are_the_amf_only(scn: type[_N2]) -> None:
    assert scn.targets(scn.defaults()) == ["172.22.0.5"]
    assert scn.spoofed_sources(scn.defaults()) == []  # N2 never spoofs the source IP


def test_guard_refuses_sctp_target_outside_testbed() -> None:
    guard = Guard.for_targets(["172.22.0.5"])
    with pytest.raises(TargetNotAllowedError):
        guard.sctp_connect("8.8.8.8", 38412)
