#!/usr/bin/env bash
# Preflight: can this machine's Docker run a 5G core testbed?
#
# Open5GS and UERANSIM need three things from the Docker host kernel:
#   1. SCTP sockets   (NGAP on N2 runs over SCTP, port 38412)
#   2. /dev/net/tun   (the UPF and each simulated UE create TUN interfaces)
#   3. NET_ADMIN      (to configure those interfaces and routes)
# On Windows this is the Docker Desktop WSL2 VM kernel, not Windows itself.
# Run from Git Bash, WSL, or the dev container (with the Docker socket mounted).
set -euo pipefail

# Git Bash (MSYS) rewrites Unix-looking arguments such as /dev/net/tun into
# Windows paths before Docker sees them. Turn that off for this script.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

IMAGE="python:3.12-slim"
pass=0
fail=0

ok()   { printf '  [ OK ] %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf '  [FAIL] %s\n         %s\n' "$1" "$2"; fail=$((fail + 1)); }

echo "Prahari-5GC host preflight"

if ! command -v docker >/dev/null 2>&1; then
    bad "docker CLI" "Install Docker Desktop (WSL2 backend) and make sure 'docker' is on PATH."
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    bad "docker daemon" "Docker Desktop is not running. Start it and re-run."
    exit 1
fi
ok "docker daemon reachable ($(docker version --format '{{.Server.Version}}' 2>/dev/null || echo '?'))"

echo "  pulling ${IMAGE} for kernel checks (first run only)..."
docker pull -q "${IMAGE}" >/dev/null

if docker run --rm "${IMAGE}" python -c \
    "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP); s.close()" \
    >/dev/null 2>&1; then
    ok "SCTP sockets available in the Docker kernel"
else
    bad "SCTP sockets" \
        "Docker's kernel lacks SCTP. Fallback: run the testbed in a WSL2 Ubuntu distro with Docker Engine, or an Ubuntu VM (see docs/adr/0005-host-runtime.md)."
fi

if docker run --rm --cap-add NET_ADMIN --device /dev/net/tun "${IMAGE}" \
    sh -c 'test -c /dev/net/tun' >/dev/null 2>&1; then
    ok "/dev/net/tun can be passed into containers"
else
    bad "/dev/net/tun" "TUN device unavailable; the UPF and UE simulator cannot start."
fi

if docker run --rm --cap-add NET_ADMIN "${IMAGE}" \
    python -c "import fcntl, socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).close()" \
    >/dev/null 2>&1; then
    ok "containers start with NET_ADMIN"
else
    bad "NET_ADMIN" "Docker refused --cap-add NET_ADMIN."
fi

mem_kb=$(docker run --rm "${IMAGE}" sh -c "awk '/MemTotal/ {print \$2}' /proc/meminfo")
mem_gb=$((mem_kb / 1024 / 1024))
if [ "${mem_gb}" -ge 6 ]; then
    ok "Docker VM memory: ${mem_gb} GiB (need >= 6)"
else
    bad "Docker VM memory: ${mem_gb} GiB" \
        "Give WSL2 more memory in %UserProfile%\\.wslconfig ([wsl2] memory=8GB), then 'wsl --shutdown'."
fi

echo
echo "Result: ${pass} passed, ${fail} failed"
[ "${fail}" -eq 0 ]
