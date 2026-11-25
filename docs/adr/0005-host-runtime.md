# ADR-0005: Run on Docker Desktop (WSL2) with a preflight check

- Status: Accepted (to be confirmed by the Phase 1 preflight on the dev laptop)
- Date: 2026-11-25

## Context
The dev machine is a Windows laptop (16 GB RAM). The 5G testbed needs SCTP, TUN
and NET_ADMIN from the Docker host kernel, which on Windows is the Docker Desktop
WSL2 VM, not Windows.

## Decision
Primary runtime: Docker Desktop with the WSL2 backend. `scripts/check-host.sh`
verifies SCTP, TUN, NET_ADMIN and memory before Phase 1 work starts.

Fallback, in order, if a check fails:
1. A WSL2 Ubuntu 24.04 distro running Docker Engine directly (its own kernel config).
2. An Ubuntu 24.04 VM (Hyper-V), which has a full kernel with SCTP and TUN.

Development (build/test) happens in the VS Code dev container either way, so the
toolchain matches CI exactly.

## Consequences
- WSL2 memory should be capped at about 8 GB in `.wslconfig`, leaving room for Windows.
- Line endings are forced to LF via `.gitattributes`.
