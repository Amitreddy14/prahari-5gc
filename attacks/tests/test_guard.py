"""The allowlist is the injector's most important property: test it hard."""

from __future__ import annotations

import socket
import struct

import pytest

from prahari_attacks import guard
from prahari_attacks.guard import (
    Guard,
    LabNotConfirmedError,
    TargetNotAllowedError,
    build_ipv4_udp,
    check_ip,
    require_lab,
)


@pytest.mark.parametrize("addr", ["172.22.0.8", "172.22.0.10", "172.22.0.40", "172.22.0.254"])
def test_testbed_addresses_are_allowed(addr: str) -> None:
    assert str(check_ip(addr)) == addr


@pytest.mark.parametrize(
    "addr",
    [
        "8.8.8.8",  # the internet
        "172.22.1.8",  # next subnet
        "172.23.0.10",  # the obs network (Kafka): monitoring is not a target
        "10.45.0.1",  # UE pool
        "127.0.0.1",
        "172.22.0.0",  # network address
        "172.22.0.255",  # broadcast
        "localhost",
        "",
        "172.22.0.8:8805",
    ],
)
def test_everything_else_is_refused(addr: str) -> None:
    with pytest.raises(TargetNotAllowedError):
        check_ip(addr)


def test_the_network_is_a_constant_not_a_setting() -> None:
    assert str(guard.TESTBED_NETWORK) == "172.22.0.0/24"
    assert str(guard.ATTACKER_IP) == "172.22.0.40"


def test_declared_targets_narrow_the_allowlist() -> None:
    g = Guard.for_targets(["172.22.0.8"])
    g.check("172.22.0.8")
    with pytest.raises(TargetNotAllowedError):
        g.check("172.22.0.10")  # in the testbed, but not this run's target


def test_refusal_happens_before_any_packet() -> None:
    g = Guard.for_targets(["172.22.0.8"])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with pytest.raises(TargetNotAllowedError):
            g.sendto(s, b"x", "8.8.8.8", 53)
    finally:
        s.close()
    assert g.sent_packets == 0


def test_spoofed_source_must_be_a_testbed_address() -> None:
    g = Guard.for_targets(["172.22.0.8"])
    with pytest.raises(TargetNotAllowedError):
        g.send_udp_spoofed("192.0.2.1", 8805, "172.22.0.8", 8805, b"x")
    assert g.sent_packets == 0


def test_lab_confirmation_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PRAHARI_LAB", raising=False)
    with pytest.raises(LabNotConfirmedError):
        require_lab()
    monkeypatch.setenv("PRAHARI_LAB", "yes")  # only exactly "1" counts
    with pytest.raises(LabNotConfirmedError):
        require_lab()
    monkeypatch.setenv("PRAHARI_LAB", "1")
    require_lab()


def _ones_complement_ok(data: bytes) -> bool:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF


def test_spoofed_ipv4_udp_packet_is_well_formed() -> None:
    payload = b"\x21\x01\x00\x0c" + b"\x00" * 12
    pkt = build_ipv4_udp("172.22.0.7", 8805, "172.22.0.8", 8805, payload)
    ip, udp = pkt[:20], pkt[20:]
    assert ip[0] == 0x45
    assert struct.unpack("!H", ip[2:4])[0] == len(pkt)
    assert ip[9] == socket.IPPROTO_UDP
    assert ip[12:16] == socket.inet_aton("172.22.0.7")
    assert _ones_complement_ok(ip)  # header checksum
    pseudo = ip[12:20] + struct.pack("!BBH", 0, 17, len(udp))
    assert _ones_complement_ok(pseudo + udp)  # UDP checksum
    assert udp[8:] == payload
