"""prahari-campaign: run a benign + attack campaign against the testbed.

    prahari-campaign run --spec campaign.json --out runs/demo

Benign UE churn is driven through `docker compose exec ue nr-cli`; attacks through
`docker compose exec attacker prahari-attack`. The attacker writes each run manifest to
its /runs mount (the host's testbed/runs), where the labeller later reads them.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from prahari_campaign.campaign import Campaign, load_spec

CONTAINER_RUNS = "/runs"  # ./runs mount inside the attacker container


def _compose(cmd: str) -> list[str]:
    return shlex.split(cmd)


def make_run_cli(compose: str, service: str = "ue") -> Callable[[str, str], str]:
    def run_cli(imsi: str, command: str) -> str:
        argv = [*_compose(compose), "exec", "-T", service, "nr-cli", f"imsi-{imsi}", "-e", command]
        # argv is the operator's own compose command and testbed IMSIs, not untrusted input.
        proc = subprocess.run(  # noqa: S603
            argv, capture_output=True, text=True, timeout=30, check=False
        )
        return proc.stdout

    return run_cli


def make_attack_runner(
    compose: str, container_out: str, service: str = "attacker"
) -> Callable[[str, dict[str, str], Path], dict[str, Any]]:
    def attack_runner(attack_id: str, params: dict[str, str], _out_dir: Path) -> dict[str, Any]:
        argv = [
            *_compose(compose),
            "exec",
            "-T",
            service,
            "prahari-attack",
            "run",
            attack_id,
            "--out",
            container_out,
        ]
        for k, v in params.items():
            argv += ["--param", f"{k}={v}"]
        # argv is the operator's compose command and spec-declared attack params.
        proc = subprocess.run(argv, capture_output=True, text=True, check=False)  # noqa: S603
        return {
            "status": "ok" if proc.returncode == 0 else f"exit {proc.returncode}",
            "returncode": proc.returncode,
        }

    return attack_runner


def cmd_run(args: argparse.Namespace) -> int:
    spec = load_spec(Path(args.spec))
    out = Path(args.out)
    if args.dry_run:
        plan = {
            "campaign": spec.name,
            "duration_s": spec.duration,
            "benign": None if spec.benign is None else vars(spec.benign),
            "steps": [{"at": s.at, "id": s.attack_id, "params": s.params} for s in spec.steps],
        }
        print(json.dumps(plan, indent=2, default=lambda o: list(o) if isinstance(o, tuple) else o))
        return 0
    run_cli = None if args.no_benign else make_run_cli(args.compose)
    attack_runner = make_attack_runner(args.compose, args.container_out)
    campaign = Campaign(spec, attack_runner=attack_runner, run_cli=run_cli)
    manifest = campaign.run(out)
    attacks = manifest["attacks"]
    n_ok = sum(1 for a in attacks if a.get("returncode") == 0)
    print(f"campaign {spec.name}: {n_ok}/{len(attacks)} attacks ok; manifest {out}/campaign.json")
    return 0 if n_ok == len(attacks) else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="prahari-campaign", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run a campaign spec")
    r.add_argument("--spec", required=True, help="campaign spec (.json or .yaml)")
    r.add_argument("--out", required=True, help="host manifest directory (the ./runs mount)")
    r.add_argument("--compose", default="docker compose", help="compose command prefix")
    r.add_argument("--container-out", default=CONTAINER_RUNS, help="attacker's --out path")
    r.add_argument("--no-benign", action="store_true", help="attacks only, no UE churn")
    r.add_argument("--dry-run", action="store_true", help="print the plan and exit")
    args = ap.parse_args(argv)
    return cmd_run(args)


if __name__ == "__main__":
    sys.exit(main())
