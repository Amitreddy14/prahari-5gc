"""prahari-attack: list, describe and run attack scenarios against the testbed.

    prahari-attack list
    prahari-attack describe N4-01
    prahari-attack run N4-01 --param seid_count=64 --param rate=100 [--dry-run]

Every run writes a manifest to --out (default: ./runs), even if it fails half-way:
the manifest is what labels the captured events.
"""

from __future__ import annotations

import argparse
import sys
import time
import traceback
from pathlib import Path
from typing import Any

from prahari_attacks import __version__
from prahari_attacks.guard import (
    ATTACKER_IP,
    Guard,
    LabNotConfirmedError,
    TargetNotAllowedError,
    check_ip,
    require_lab,
)
from prahari_attacks.manifest import Manifest
from prahari_attacks.scenarios import SCENARIOS
from prahari_attacks.scenarios.base import Context, Scenario

EXIT_OK = 0
EXIT_USAGE = 64
EXIT_REFUSED = 77  # EX_NOPERM
EXIT_FAILED = 70


def _parse_params(cls: type[Scenario], raw: list[str]) -> dict[str, Any]:
    known = {p.name: p for p in cls.params}
    params = cls.defaults()
    for item in raw:
        if "=" not in item:
            raise ValueError(f"--param needs name=value, got {item!r}")
        name, value = item.split("=", 1)
        if name not in known:
            raise ValueError(f"{cls.attack_id} has no parameter {name!r} (try: describe)")
        params[name] = known[name].parse(value)
    return params


def cmd_list() -> int:
    for aid, cls in SCENARIOS.items():
        print(f"{aid:7} {cls.interface:4} {cls.title}")
    return EXIT_OK


def cmd_describe(aid: str) -> int:
    cls = SCENARIOS.get(aid.upper())
    if cls is None:
        print(f"unknown attack {aid!r}; see: prahari-attack list", file=sys.stderr)
        return EXIT_USAGE
    print(f"{cls.attack_id}  {cls.title}  [{cls.interface}]\n\n{cls.mechanism}\n\nParameters:")
    for p in cls.params:
        print(f"  {p.name:12} default={p.default!r:22} {p.help}")
    return EXIT_OK


def _prepare(args: argparse.Namespace) -> tuple[type[Scenario], dict[str, Any], Guard, Manifest]:
    """Validates everything before any socket exists (dry runs included)."""
    cls = SCENARIOS.get(args.attack_id.upper())
    if cls is None:
        raise ValueError(f"unknown attack {args.attack_id!r}")
    params = _parse_params(cls, args.param)
    targets = cls.targets(params)
    spoofed = cls.spoofed_sources(params)
    guard = Guard.for_targets(targets)
    for s in spoofed:
        check_ip(s)
    attacker = str(check_ip(args.attacker_ip))
    m = Manifest(
        cls.attack_id,
        cls.title,
        params,
        attacker,
        targets,
        dry_run=args.dry_run,
        spoofed_sources=spoofed,
    )
    return cls, params, guard, m


def _execute(
    cls: type[Scenario], params: dict[str, Any], guard: Guard, m: Manifest, max_seconds: float
) -> int:
    ctx = Context(
        guard, m, params, attacker_ip=m.attacker_ip, stop_at=time.monotonic() + max_seconds
    )
    m.start()
    rc = EXIT_OK
    try:
        cls().run(ctx)
    except TargetNotAllowedError as e:
        m.notes.append(f"refused mid-run: {e}")
        print(f"refused: {e}", file=sys.stderr)
        rc = EXIT_REFUSED
    except Exception as e:  # the manifest must be written whatever happens
        m.notes.append(f"failed: {type(e).__name__}: {e}")
        traceback.print_exc()
        rc = EXIT_FAILED
    finally:
        guard.close()
        m.outcome["packets_sent"] = guard.sent_packets
        m.outcome["bytes_sent"] = guard.sent_bytes
        m.finish()
    return rc


def cmd_run(args: argparse.Namespace) -> int:
    try:
        cls, params, guard, m = _prepare(args)
    except TargetNotAllowedError as e:
        print(f"refused: {e}", file=sys.stderr)
        return EXIT_REFUSED
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_USAGE
    print(f"{cls.attack_id} {cls.title}")
    print(f"  targets {m.targets}  attacker {m.attacker_ip}  spoofing {m.spoofed_sources or 'no'}")
    print(f"  params  {params}")
    if args.dry_run:
        m.start()
        m.finish()
        m.notes.append("dry run: nothing was sent")
        print(f"  dry run: nothing sent; manifest {m.write(Path(args.out))}")
        return EXIT_OK
    try:
        require_lab()
    except LabNotConfirmedError as e:
        print(f"refused: {e}", file=sys.stderr)
        return EXIT_REFUSED
    rc = _execute(cls, params, guard, m, args.max_seconds)
    path = m.write(Path(args.out))
    print(f"  done in {(m.ended_ns - m.started_ns) / 1e9:.1f} s: {m.outcome}")
    print(f"  manifest {path}")
    return rc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="prahari-attack", description=__doc__.split("\n")[0])
    ap.add_argument("--version", action="version", version=f"prahari-attack {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list scenarios")
    d = sub.add_parser("describe", help="show a scenario's mechanism and parameters")
    d.add_argument("attack_id")
    r = sub.add_parser("run", help="run a scenario")
    r.add_argument("attack_id")
    r.add_argument("--param", action="append", default=[], metavar="NAME=VALUE")
    r.add_argument("--dry-run", action="store_true", help="validate and write a manifest only")
    r.add_argument("--out", default="runs", help="manifest directory (default: ./runs)")
    r.add_argument("--attacker-ip", default=str(ATTACKER_IP), help="this host's testbed address")
    r.add_argument("--max-seconds", type=float, default=600.0, help="hard time limit")
    args = ap.parse_args(argv)
    if args.cmd == "list":
        return cmd_list()
    if args.cmd == "describe":
        return cmd_describe(args.attack_id)
    return cmd_run(args)


if __name__ == "__main__":
    sys.exit(main())
