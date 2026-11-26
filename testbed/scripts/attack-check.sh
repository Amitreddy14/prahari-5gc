#!/usr/bin/env bash
# Phase 4a check: the attack injector, the probe and the labeller working together.
#
#   cd testbed && bash scripts/smoke.sh && bash scripts/attack-check.sh
#
# Runs only NON-DESTRUCTIVE scenarios against the running testbed (recon, a rogue NF
# registration that is removed again, a small fuzz, a rogue PFCP association, an
# establishment flood that cleans up after itself). N4-01/N4-02 would tear down or
# black-hole the real UEs' sessions, so they are dataset runs, not part of a check.
#
# Then it labels the probe's events with the run manifests (inside the attacker
# container) and checks: every run produced attributed events, nothing was lost at
# capture, every labelled line validates, and the testbed is still healthy.
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"   # Git Bash: do not rewrite /paths

cd "$(dirname "$0")/.."
UE_COUNT="$(grep -E '^PRAHARI_UE_COUNT=' .env 2>/dev/null | cut -d= -f2 || true)"
UE_COUNT="${UE_COUNT:-10}"

pass=0
fail=0
ok()  { printf '  [ OK ] %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf '  [FAIL] %s\n         %s\n' "$1" "$2"; fail=$((fail + 1)); }
dc()  { docker compose "$@"; }
atk() { dc exec -T attacker "$@"; }

if ! docker info >/dev/null 2>&1; then
    echo "  [FAIL] this shell cannot reach Docker (on Windows use Git Bash)."
    exit 2
fi

echo "Prahari-5GC attack check (Phase 4a)"

# 1. Attacker container up, at its reserved address, with the guard armed.
# The container runs as root with every capability dropped except NET_RAW, which
# also drops CAP_DAC_OVERRIDE -- so unlike normal root it cannot write into a
# host directory it doesn't own. Make the mount world-writable; it holds nothing
# but disposable run manifests.
mkdir -p runs
chmod 777 runs
dc --profile attack up -d --build attacker >/dev/null 2>&1 || true
if [ "$(atk printenv PRAHARI_LAB 2>/dev/null | tr -d '\r')" = "1" ]; then
    ok "attacker container up at 172.22.0.40 ($(atk prahari-attack --version | tr -d '\r'))"
else
    bad "attacker" "container not running (docker compose --profile attack logs attacker)"
    echo; echo "Result: ${pass} passed, ${fail} failed"; exit 1
fi

# 2. The guard refuses anything outside the testbed, before sending (N4, SBI and N2).
if ! atk prahari-attack run SBI-01 --param nrf=8.8.8.8 --dry-run --out /tmp >/dev/null 2>&1 \
   && ! atk prahari-attack run N4-01 --param smf=192.0.2.7 --dry-run --out /tmp >/dev/null 2>&1 \
   && ! atk prahari-attack run N2-02 --param amf=192.0.2.5 --dry-run --out /tmp >/dev/null 2>&1; then
    ok "guard refuses targets and spoofed sources outside 172.22.0.0/24"
else
    bad "guard" "an out-of-lab address was accepted"
fi

# 3. Fire the non-destructive scenarios. Each writes a manifest to testbed/runs/.
batch="check-$(date +%Y%m%dT%H%M%S)"
atk mkdir -p "/runs/${batch}"
run() {
    local aid="$1"; shift
    local params=()
    for p in "$@"; do params+=(--param "$p"); done
    if atk prahari-attack run "${aid}" "${params[@]}" --out "/runs/${batch}" >/dev/null 2>&1; then
        printf '         ran %s\n' "${aid}"
    else
        bad "run ${aid}" "prahari-attack exited non-zero (see testbed/runs/${batch})"
    fi
}
run SBI-01 rate=50
run SBI-02 heartbeats=1 interval=1 deregister=true
run SBI-04 count=60 rate=30
run N4-04 mode=setup repeat=1
run N4-03 count=100 rate=100 cleanup=true
# N2 (NGAP/SCTP). Non-destructive only: a rogue gNB setup, a small registration storm
# (contexts the AMF times out), and a malformed-NGAP fuzz. N2-01/03 at scale and the
# forged UE-release are dataset runs, not part of this check.
run N2-02 count=2
run N2-01 count=30 rate=60 vary_suci=true
run N2-04 count=120 seed=1337 rate=120
sleep 6   # late responses + the probe's flush interval

# 4. Label the probe's events with these manifests and check attribution.
report="$(atk python -m prahari_analytics.labels --events /events/events.jsonl \
          --runs "/runs/${batch}" --out "/runs/${batch}/labelled.jsonl" --validate 2>&1 | tr -d '\r')" \
    || { bad "labeller" "${report}"; report=""; }
if [ -n "${report}" ]; then
    printf '%s\n' "${report}" | sed 's/^/         /'
    zero="$(printf '%s\n' "${report}" | awk '$1 ~ /^(N[0-9]|SBI)-/ && $3 == 0 {print $1}' | tr '\n' ' ')"
    nruns="$(printf '%s\n' "${report}" | awk '$1 ~ /^(N[0-9]|SBI)-/' | wc -l | tr -d ' ')"
    if [ "${nruns}" -ge 5 ] && [ -z "${zero}" ]; then
        ok "all ${nruns} runs captured and labelled (every line validates against the schema)"
    else
        bad "labelling" "runs with no attributed events: ${zero:-none} (${nruns} runs found)"
    fi
fi

# 5. Nothing lost at capture.
drops="$(dc exec -T probe bash -c 'exec 3<>/dev/tcp/127.0.0.1/9464 && printf "GET /metrics HTTP/1.0\r\n\r\n" >&3 && cat <&3' 2>/dev/null \
        | awk '$1 ~ /^prahari_probe_capture_dropped_total/ {s += $2} END {print s + 0}')"
if [ "${drops}" = "0" ]; then
    ok "probe capture: 0 packets dropped"
else
    bad "probe capture" "${drops} packets dropped before the probe saw them"
fi

# 6. The testbed survived the non-destructive attacks.
tunnels="$(dc exec -T ue sh -c 'ip -o link show | grep -c uesimtun || true' 2>/dev/null | tr -dc '0-9')"
upf_up="$(docker inspect -f '{{.State.Running}}' "$(dc ps -q upf)" 2>/dev/null || echo false)"
if [ "${tunnels:-0}" -ge "${UE_COUNT}" ] && [ "${upf_up}" = "true" ]; then
    ok "testbed still healthy: UPF running, ${tunnels}/${UE_COUNT} UE tunnels up"
else
    bad "testbed health" "UPF running=${upf_up}, UE tunnels ${tunnels:-0}/${UE_COUNT}"
fi

echo
echo "Manifests and labelled events: testbed/runs/${batch}/"
echo "Result: ${pass} passed, ${fail} failed"
[ "${fail}" -eq 0 ]
