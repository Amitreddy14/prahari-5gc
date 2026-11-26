# prahari-campaign

Benign traffic + attack campaign runner for the Prahari-5GC testbed. It drives the
UERANSIM UEs through realistic churn (PDU session establish/release, status polls) while
firing attack scenarios at scheduled offsets, so attacks land inside normal traffic. The
output is a set of per-attack run manifests plus one `campaign.json`, which the labeller
and dataset builder turn into a labelled dataset.

This is a lab tool: it only orchestrates `docker compose exec` against the local testbed,
and every attack it fires inherits the injector's hard allowlist (targets inside
`172.22.0.0/24` only).

## Use

```bash
# from testbed/, with the stack and the attacker profile up
pip install ./campaign
prahari-campaign run --spec campaign/campaign.example.json --out testbed/runs/demo

# preview the plan without touching the testbed
prahari-campaign run --spec campaign/campaign.example.json --out /tmp/x --dry-run
```

Benign traffic goes through `docker compose exec ue nr-cli`; attacks through
`docker compose exec attacker prahari-attack`. Use `--no-benign` for an attacks-only
timeline, or `--compose "docker compose -f ..."` to point at a specific compose file.

## Spec

A campaign spec is JSON (or YAML, with the `yaml` extra):

```json
{
  "name": "prahari-dataset-v1",
  "benign": { "ue_count": 10, "rate": 3.0, "seed": 1 },
  "steps": [
    { "at": 15, "id": "SBI-01" },
    { "at": 45, "id": "N2-01", "params": { "count": "150" } }
  ]
}
```

`at` is seconds from the campaign start; `params` are passed straight to
`prahari-attack run <id> --param k=v`. `benign: null` disables the generator.
