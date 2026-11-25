#!/usr/bin/env bash
# End-to-end smoke test for the running testbed.
#
#   cd testbed && docker compose up -d --build && bash scripts/smoke.sh
#
# Checks, in order: every service healthy, subscribers provisioned, gNB connected
# to the AMF (NG Setup), every UE registered with a PDU session, user-plane ping
# through the UPF, and the capture sidecar recording N2, N4 and SBI traffic.
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"   # Git Bash: do not rewrite /paths

cd "$(dirname "$0")/.."
WAIT_SECONDS="${WAIT_SECONDS:-120}"
UE_COUNT="$(grep -E '^PRAHARI_UE_COUNT=' .env 2>/dev/null | cut -d= -f2 || true)"
UE_COUNT="${UE_COUNT:-10}"

pass=0
fail=0
ok()  { printf '  [ OK ] %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf '  [FAIL] %s\n         %s\n' "$1" "$2"; fail=$((fail + 1)); }
dc()  { docker compose "$@"; }
# Number of uesimtunN interfaces in the UE container (0 if none or not running).
# `grep -c` prints 0 AND exits 1 on no match, so `|| echo 0` would print "0" twice.
ue_tunnels() {
    local n
    n="$(docker compose exec -T ue sh -c 'ip -o link show | grep -c uesimtun || true' 2>/dev/null | tr -dc '0-9')"
    echo "${n:-0}"
}


# Poll a command until it succeeds or WAIT_SECONDS passes.
wait_for() {
    local deadline=$((SECONDS + WAIT_SECONDS))
    until "$@" >/dev/null 2>&1; do
        [ "${SECONDS}" -ge "${deadline}" ] && return 1
        sleep 2
    done
}

echo "Prahari-5GC testbed smoke test (expecting ${UE_COUNT} UEs)"

# Fail fast if this shell cannot reach Docker. On Windows, typing `bash` in
# PowerShell starts WSL's bash (no Docker integration), not Git Bash.
if ! docker info >/dev/null 2>&1; then
    echo "  [FAIL] this shell cannot reach Docker."
    echo "         On Windows run the script from Git Bash, or from PowerShell with:"
    printf '%s\n' '         & "C:\Program Files\Git\bin\bash.exe" scripts/smoke.sh'
    exit 2
fi
if [ -z "$(docker compose ps -q 2>/dev/null)" ]; then
    echo "  [FAIL] the testbed is not running: docker compose up -d"
    exit 2
fi

# 1. Health of long-running services.
services=(mongo nrf ausf udm udr pcf nssf bsf upf smf amf gnb ue)
all_healthy() {
    local s state
    for s in "${services[@]}"; do
        state="$(docker inspect -f '{{.State.Health.Status}}' "$(dc ps -q "$s")" 2>/dev/null || echo missing)"
        [ "${state}" = "healthy" ] || return 1
    done
}
if wait_for all_healthy; then
    ok "all ${#services[@]} services healthy"
else
    unhealthy=""
    for s in "${services[@]}"; do
        st="$(docker inspect -f '{{.State.Health.Status}}' "$(dc ps -q "$s")" 2>/dev/null || echo missing)"
        [ "${st}" = "healthy" ] || unhealthy+=" ${s}=${st}"
    done
    bad "service health" "not healthy:${unhealthy}  (see: docker compose logs <service>)"
fi

# 2. Provisioning finished cleanly.
prov_state="$(docker inspect -f '{{.State.ExitCode}}' "$(dc ps -a -q provision)" 2>/dev/null || echo missing)"
if [ "${prov_state}" = "0" ]; then
    ok "subscribers provisioned ($(dc logs --no-log-prefix provision 2>/dev/null | grep -o 'total in db: [0-9]*' | tail -1))"
else
    bad "provisioning" "provision exit code: ${prov_state}  (docker compose logs provision)"
fi

# 3. gNB <-> AMF NG Setup over SCTP (N2).
if wait_for sh -c "docker compose logs --no-log-prefix gnb 2>/dev/null | grep -q 'NG Setup procedure is successful'"; then
    ok "gNB completed NG Setup with the AMF (N2/SCTP up)"
else
    bad "NG Setup" "gNB never reported 'NG Setup procedure is successful' (docker compose logs gnb amf)"
fi

# 4. Every UE registered and got a PDU session (one uesimtunN interface each).
all_ues_up() { [ "$(ue_tunnels)" -ge "${UE_COUNT}" ]; }
if wait_for all_ues_up; then
    ok "${UE_COUNT}/${UE_COUNT} UEs registered with a PDU session"
else
    bad "UE registration" "$(ue_tunnels)/${UE_COUNT} uesimtun interfaces (docker compose logs ue amf smf)"
fi

# 5. User plane: ping the UPF's gateway address through the first UE's tunnel (N3 GTP-U).
if dc exec -T ue ping -c 3 -W 2 -I uesimtun0 10.45.0.1 >/dev/null 2>&1; then
    ok "user plane: UE -> gNB -> UPF ping to 10.45.0.1"
else
    bad "user-plane ping" "no reply from 10.45.0.1 via uesimtun0 (docker compose logs upf)"
fi

# 6. Optional: internet egress through the UPF's NAT. Warn only.
if dc exec -T ue ping -c 2 -W 3 -I uesimtun0 8.8.8.8 >/dev/null 2>&1; then
    echo "  [info] internet egress via UPF NAT works"
else
    echo "  [info] no internet egress from UEs (fine for this project; NAT or host network blocks it)"
fi

# 7. Capture sidecar is recording all three control-plane interfaces.
latest="$(find captures -maxdepth 1 -name 'core-*.pcap' -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2- || true)"
if [ -z "${latest}" ]; then
    bad "capture" "no captures/core-*.pcap yet (docker compose logs capture)"
else
    count_in() { dc exec -T capture tcpdump -nr "/captures/$(basename "${latest}")" "$1" 2>/dev/null | wc -l | tr -d ' '; }
    n2="$(count_in sctp)"; n4="$(count_in 'udp port 8805')"; sbi="$(count_in 'tcp port 7777')"
    if [ "${n2}" -gt 0 ] && [ "${n4}" -gt 0 ] && [ "${sbi}" -gt 0 ]; then
        ok "capture recording N2=${n2} N4=${n4} SBI=${sbi} packets in $(basename "${latest}")"
    else
        bad "capture coverage" "N2=${n2} N4=${n4} SBI=${sbi} in ${latest} (all three must be > 0)"
    fi
fi

echo
echo "Result: ${pass} passed, ${fail} failed"
[ "${fail}" -eq 0 ]
