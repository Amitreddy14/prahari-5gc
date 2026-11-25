#!/bin/sh
# Render the UE config from its template using environment variables, then start
# PRAHARI_UE_COUNT UEs with consecutive IMSIs (UERANSIM's -n flag).
# Subscriber keys come from the environment so they are never committed.
set -eu

: "${PRAHARI_UE_COUNT:=10}"
: "${PRAHARI_IMSI_BASE:=001010000000001}"
: "${SUBSCRIBER_K:?set SUBSCRIBER_K in testbed/.env}"
: "${SUBSCRIBER_OPC:?set SUBSCRIBER_OPC in testbed/.env}"

is_hex32() { printf '%s' "$1" | grep -Eq '^[0-9A-Fa-f]{32}$'; }
is_hex32 "${SUBSCRIBER_K}" || { echo "SUBSCRIBER_K must be 32 hex characters" >&2; exit 64; }
is_hex32 "${SUBSCRIBER_OPC}" || { echo "SUBSCRIBER_OPC must be 32 hex characters" >&2; exit 64; }
printf '%s' "${PRAHARI_IMSI_BASE}" | grep -Eq '^[0-9]{15}$' \
    || { echo "PRAHARI_IMSI_BASE must be 15 digits" >&2; exit 64; }
case "${PRAHARI_UE_COUNT}" in
    ''|*[!0-9]*) echo "PRAHARI_UE_COUNT must be a positive integer" >&2; exit 64 ;;
esac
if [ "${PRAHARI_UE_COUNT}" -lt 1 ] || [ "${PRAHARI_UE_COUNT}" -gt 1000 ]; then
    echo "PRAHARI_UE_COUNT must be 1..1000" >&2
    exit 64
fi

sed -e "s/@IMSI_BASE@/${PRAHARI_IMSI_BASE}/" \
    -e "s/@K@/${SUBSCRIBER_K}/" \
    -e "s/@OPC@/${SUBSCRIBER_OPC}/" \
    /etc/ueransim/ue.yaml.tmpl > /tmp/ue.yaml

echo "ue-entrypoint: starting ${PRAHARI_UE_COUNT} UE(s) from imsi-${PRAHARI_IMSI_BASE}"
exec nr-ue -c /tmp/ue.yaml -n "${PRAHARI_UE_COUNT}"
