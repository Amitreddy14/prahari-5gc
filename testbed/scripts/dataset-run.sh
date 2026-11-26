#!/usr/bin/env bash
# Build a labelled dataset: run a benign + attack campaign against the running testbed,
# then label the probe's events and pack them into Parquet with a dataset card.
#
#   cd testbed && bash scripts/smoke.sh && bash scripts/dataset-run.sh [SPEC]
#
# SPEC defaults to campaigns/quick.json (a ~25 s smoke campaign). Use campaigns/dataset.json
# for the full one. Outputs land in testbed/runs/<name>/: campaign.json, the per-attack
# manifests, labelled.jsonl, dataset.parquet and dataset-card.md.
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"

cd "$(dirname "$0")/.."
SPEC="${1:-campaigns/quick.json}"
NAME="$(sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${SPEC}" | head -1)"
NAME="${NAME:-dataset}"
dc() { docker compose "$@"; }
atk() { dc exec -T attacker "$@"; }

if ! docker info >/dev/null 2>&1; then
    echo "  [FAIL] this shell cannot reach Docker (on Windows use Git Bash)."; exit 2
fi

echo "Prahari-5GC dataset run: ${NAME} (spec ${SPEC})"
dc --profile attack up -d --build attacker >/dev/null 2>&1 || true
mkdir -p "runs/${NAME}"

# Fresh event log so the dataset holds only this campaign's traffic.
: > events/events.jsonl

# 1. Run the campaign (benign UE churn + scheduled attacks) from the host.
#    The campaign package needs no install: run it straight from the source tree.
PYTHONPATH=../campaign/src python3 -m prahari_campaign.cli run \
    --spec "${SPEC}" --out "runs/${NAME}" --container-out "/runs/${NAME}"
sleep 6   # let the probe flush the tail of the capture

PROBE_VER="$(dc exec -T probe prahari-probe --version 2>/dev/null | tr -d '\r' | awk '{print $2}')"

# 2. Label the probe's events with the run manifests (inside the attacker container).
atk python -m prahari_analytics.labels \
    --events /events/events.jsonl --runs "/runs/${NAME}" \
    --out "/runs/${NAME}/labelled.jsonl" --validate | sed 's/^/  /'

# 3. Pack into Parquet + dataset card.
atk python -m prahari_analytics.dataset \
    --events "/runs/${NAME}/labelled.jsonl" --out "/runs/${NAME}/dataset.parquet" \
    --card "/runs/${NAME}/dataset-card.md" --campaign "/runs/${NAME}/campaign.json" \
    --name "${NAME}" --probe-version "${PROBE_VER:-unknown}" | sed 's/^/  /'

echo "Dataset ready: testbed/runs/${NAME}/dataset.parquet (+ dataset-card.md)"
