"""The only way the injector touches the network.

Every socket the scenarios use is created here, and every destination (and every
spoofed source address) is checked against the testbed network first. The network
is a module constant on purpose: there is no flag, environment variable or config
file that widens it. Narrowing is allowed (`Guard(targets=...)`).

A second check, `require_lab()`, refuses to run at all unless PRAHARI_LAB=1 is set,
which the attacker container does. It stops a stray `prahari-attack run` on a
laptop from sending anything.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import struct
from collections.abc import Iterable
from dataclasses import dataclass, field

TESTBED_NETWORK = ipaddress.IPv4Network("172.22.0.0/24")
ATTACKER_IP = ipaddress.IPv4Address("172.22.0.40")


class TargetNotAllowedError(PermissionError):
    """Raised before anything is sent to an address outside the testbed."""


class LabNotConfirmedError(PermissionError):
    """Raised when PRAHARI_LAB=1 is not set."""


def require_lab() -> None:
    if os.environ.get("PRAHARI_LAB") != "1":
        raise LabNotConfirmedError(
            "refusing to run: set PRAHARI_LAB=1 (the attacker container does). "
            "This tool only ever targets the Prahari testbed network 172.22.0.0/24."
        )


def check_ip(addr: str) -> ipaddress.IPv4Address:
    """Parses and checks one address. Network/broadcast addresses are refused too."""
    try:
        ip = ipaddress.IPv4Address(addr)
    except ValueError as e:
        raise TargetNotAllowedError(f"not an IPv4 address: {addr!r}") from e
    if ip not in TESTBED_NETWORK:
        raise TargetNotAllowedError(f"{ip} is outside the testbed network {TESTBED_NETWORK}")
    if ip in (TESTBED_NETWORK.network_address, TESTBED_NETWORK.broadcast_address):
        raise TargetNotAllowedError(f"{ip} is the network or broadcast address")
    return ip


@dataclass
class Guard:
    """Network access for one run. `targets` may narrow (never widen) the allowlist."""

    targets: frozenset[ipaddress.IPv4Address] | None = None
    sent_packets: int = 0
    sent_bytes: int = 0
    _sockets: list[socket.socket] = field(default_factory=list)

    @classmethod
    def for_targets(cls, addrs: Iterable[str]) -> Guard:
        return cls(targets=frozenset(check_ip(a) for a in addrs))

    def check(self, addr: str) -> ipaddress.IPv4Address:
        ip = check_ip(addr)
        if self.targets is not None and ip not in self.targets:
            raise TargetNotAllowedError(f"{ip} is not one of this run's declared targets")
        return ip

    # ------------------------------------------------------------------ UDP
    def udp_socket(
        self, bind_ip: str = "", bind_port: int = 0, timeout: float = 1.0
    ) -> socket.socket:
        if bind_ip:
            check_ip(bind_ip)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.bind((bind_ip, bind_port))
        self._sockets.append(s)
        return s

    def sendto(self, s: socket.socket, data: bytes, ip: str, port: int) -> None:
        self.check(ip)
        s.sendto(data, (ip, port))
        self.sent_packets += 1
        self.sent_bytes += len(data)

    def send_udp_spoofed(
        self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, payload: bytes
    ) -> None:
        """Raw IPv4/UDP with a forged source address (needs CAP_NET_RAW).

        The source must be a testbed address too: the injector impersonates testbed
        NFs (e.g. the SMF towards the UPF), never anything outside the lab.
        """
        check_ip(src_ip)
        self.check(dst_ip)
        packet = build_ipv4_udp(src_ip, src_port, dst_ip, dst_port, payload)
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.sendto(packet, (dst_ip, 0))
        finally:
            s.close()
        self.sent_packets += 1
        self.sent_bytes += len(payload)

    # ------------------------------------------------------------------ TCP
    def tcp_connect(
        self, ip: str, port: int, timeout: float = 3.0, source_ip: str = ""
    ) -> socket.socket:
        """Connects from `source_ip` (the attacker's testbed address) when given, so the
        traffic is attributable even where routing would pick another local address."""
        self.check(ip)
        if source_ip:
            check_ip(source_ip)
        src = (source_ip, 0) if source_ip else None
        s = socket.create_connection((ip, port), timeout=timeout, source_address=src)
        self._sockets.append(s)
        return s

    def count_sent(self, nbytes: int) -> None:
        self.sent_packets += 1
        self.sent_bytes += nbytes

    def close(self) -> None:
        for s in self._sockets:
            s.close()
        self._sockets.clear()


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    words: tuple[int, ...] = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def build_ipv4_udp(src_ip: str, src_port: int, dst_ip: str, dst_port: int, payload: bytes) -> bytes:
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    udp_len = 8 + len(payload)
    pseudo = src + dst + struct.pack("!BBH", 0, socket.IPPROTO_UDP, udp_len)
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    csum = _checksum(pseudo + udp_hdr + payload) or 0xFFFF
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, csum)
    total = 20 + udp_len
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, socket.IPPROTO_UDP, 0, src, dst
    )
    ip_hdr = ip_hdr[:10] + struct.pack("!H", _checksum(ip_hdr)) + ip_hdr[12:]
    return ip_hdr + udp_hdr + payload
