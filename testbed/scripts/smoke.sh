#!/usr/bin/env bash
# End-to-end smoke test for the running testbed.
#
#   cd testbed && docker compose up -d --build && bash scripts/smoke.sh
#
# Checks, in order: every service healthy, subscribers provisioned, gNB connected
# to the AMF (NG Setup), every UE registered with a PDU session, user-plane ping
# through the UPF, the capture sidecar recording N2, N4 and SBI traffic, and the
# probe decoding N4 (session tracking), N2 (registrations, without leaking IMSIs) and
# SBI (HTTP/2, one pseudonym per UE across all three), Kafka receiving the events,
# and the probe's Prometheus metrics.
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
services=(mongo kafka nrf ausf udm udr pcf nssf bsf upf smf amf gnb ue)
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

# 8. Probe: live N4 events with every PDU session tracked to "active".
events="events/events.jsonl"
# Only complete JSON lines count: the probe may be appending while we read.
complete_events() { grep -E '^\{.*\}$' "${events}" 2>/dev/null || true; }
probe_sessions() {
    complete_events | grep '"message":"SessionEstablishmentResponse"' \
        | grep -c '"session_state":"active"' || true
}
all_sessions_seen() { [ "$(probe_sessions)" -ge "${UE_COUNT}" ]; }
if [ ! -s "${events}" ]; then
    bad "probe events" "no ${events} yet (docker compose logs probe)"
elif wait_for all_sessions_seen; then
    total="$(complete_events | grep -c '"interface":"N4"' || true)"
    bad_decodes="$(complete_events | grep '"interface":"N4"' | grep -vc '"decode_status":"ok"' || true)"
    if [ "${bad_decodes}" -eq 0 ]; then
        ok "probe: ${total} N4 events, $(probe_sessions) sessions active, 0 decode errors"
    else
        bad "probe decode" "${bad_decodes} of ${total} N4 events not decoded cleanly"
    fi
else
    bad "probe sessions" "$(probe_sessions)/${UE_COUNT} sessions seen as active in ${events}"
fi

# 9. Probe: N2 registrations decoded through NAS, and no IMSI in the output.
# Registrations can repeat after a restart, so "at least UE_COUNT" is the bar.
SUPI_KEY="$(grep -E '^PRAHARI_SUPI_KEY=' .env 2>/dev/null | cut -d= -f2- || true)"
IMSI_BASE="$(grep -E '^PRAHARI_IMSI_BASE=' .env 2>/dev/null | cut -d= -f2 || true)"
IMSI_BASE="${IMSI_BASE:-001010000000001}"
registrations() { complete_events | grep -c '"message":"RegistrationRequest"' || true; }
all_registered() { [ "$(registrations)" -ge "${UE_COUNT}" ]; }
if wait_for all_registered; then
    n2_bad="$(complete_events | grep '"interface":"N2"' | grep -vc '"decode_status":"ok"' || true)"
    opaque="$(complete_events | grep '"interface":"N2"' | grep -c '"decoded":false' || true)"
    leaked=0
    for i in $(seq 0 $((UE_COUNT - 1))); do
        imsi="$(printf '%015d' $((10#${IMSI_BASE} + i)))"
        if complete_events | grep -qF "${imsi}"; then leaked=$((leaked + 1)); fi
    done
    hashed="$(complete_events | grep '"message":"RegistrationRequest"' | grep -c '"supi_hash"' || true)"
    if [ "${n2_bad}" -ne 0 ] || [ "${opaque}" -ne 0 ]; then
        bad "probe N2 decode" "${n2_bad} N2 decode errors, ${opaque} NAS messages left opaque"
    elif [ "${leaked}" -ne 0 ]; then
        bad "probe privacy" "${leaked} raw IMSI(s) found in ${events}"
    elif [ -n "${SUPI_KEY}" ] && [ "${hashed}" -lt "${UE_COUNT}" ]; then
        bad "probe SUPI hashing" "only ${hashed} registrations carry supi_hash (key is set)"
    else
        ok "probe: $(registrations) N2 registrations decoded, ${hashed} SUPIs pseudonymised, 0 IMSIs leaked"
    fi
else
    bad "probe N2" "$(registrations)/${UE_COUNT} RegistrationRequests seen in ${events}"
fi

# 10. Probe: SBI (HTTP/2) decoded, identities replaced, same pseudonyms as N2.
# HPACK needs each connection from its first byte; the core keeps them open, so this
# only works if the probe started before the NFs (compose orders it that way).
sbi_registrations() {
    complete_events | grep '"interface":"SBI"' | grep '"direction":"request"' \
        | grep -c '"message":"Amf3GppAccessRegistration"' || true
}
sbi_all() { [ "$(sbi_registrations)" -ge "${UE_COUNT}" ]; }
if wait_for sbi_all; then
    sbi_total="$(complete_events | grep -c '"interface":"SBI"' || true)"
    sbi_bad="$(complete_events | grep '"interface":"SBI"' | grep -vc '"decode_status":"ok"' || true)"
    raw_ids="$(complete_events | grep '"interface":"SBI"' | grep -cE 'imsi-[0-9]|suci-[0-9]' || true)"
    n2_ues="$(complete_events | grep '"interface":"N2"' | grep -o '"supi_hash":"[0-9a-f]*"' | sort -u)"
    sbi_ues="$(complete_events | grep '"interface":"SBI"' | grep -o '"supi_hash":"[0-9a-f]*"' | sort -u)"
    shared="$(comm -12 <(printf '%s\n' "${n2_ues}") <(printf '%s\n' "${sbi_ues}") | grep -c . || true)"
    if [ "${sbi_bad}" -ne 0 ]; then
        bad "probe SBI decode" "${sbi_bad} of ${sbi_total} SBI events undecodable"
    elif [ "${raw_ids}" -ne 0 ]; then
        bad "probe SBI privacy" "${raw_ids} SBI events contain a raw imsi-/suci- identity"
    elif [ -n "${SUPI_KEY}" ] && [ "${shared}" -lt "${UE_COUNT}" ]; then
        bad "probe SBI correlation" "only ${shared}/${UE_COUNT} UE pseudonyms appear on both N2 and SBI"
    else
        ok "probe: ${sbi_total} SBI events, ${UE_COUNT} AMF registrations, ${shared} UEs linked N2<->SBI"
    fi
else
    bad "probe SBI" "$(sbi_registrations)/${UE_COUNT} Amf3GppAccessRegistration requests seen. If the probe was restarted after the core, its SBI connections are mid-stream: docker compose down && docker compose up -d"
fi

# 11. Kafka holds the events, and the probe's metrics endpoint answers.
kafka_events() {
    dc exec -T kafka /opt/kafka/bin/kafka-get-offsets.sh --bootstrap-server 172.23.0.10:9092 \
        --topic prahari.events.v1 2>/dev/null | awk -F: '{s += $3} END {print s + 0}'
}
metrics() {
    # The probe image has no curl; bash's /dev/tcp is enough for one GET.
    dc exec -T probe bash -c 'exec 3<>/dev/tcp/127.0.0.1/9464 && printf "GET /metrics HTTP/1.0\r\n\r\n" >&3 && cat <&3' 2>/dev/null || true
}
metric() { metrics | awk -v m="$1" '$1 == m {print $2; exit}'; }
in_kafka="$(kafka_events)"
delivered="$(metric 'prahari_probe_kafka_messages_total{outcome="delivered"}')"
dropped="$(metric 'prahari_probe_kafka_messages_total{outcome="dropped"}')"
failed="$(metric 'prahari_probe_kafka_messages_total{outcome="failed"}')"
if [ -z "${delivered}" ]; then
    bad "probe metrics" "no answer on :9464/metrics (docker compose logs probe)"
elif [ "${in_kafka:-0}" -le 0 ]; then
    bad "kafka" "topic prahari.events.v1 is empty (docker compose logs kafka probe)"
elif [ "${dropped:-0}" != "0" ] || [ "${failed:-0}" != "0" ]; then
    bad "kafka delivery" "dropped=${dropped} failed=${failed} (delivered=${delivered})"
else
    ok "kafka: ${in_kafka} events in prahari.events.v1; metrics: ${delivered} delivered, 0 dropped"
fi

echo
echo "Result: ${pass} passed, ${fail} failed"
[ "${fail}" -eq 0 ]
