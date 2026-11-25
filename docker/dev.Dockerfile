# Development image: everything needed to build and test the probe and analytics.
# Used by .devcontainer (VS Code) and mirrors the CI toolchain.
FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential g++ clang-18 clang-tidy-18 clang-format-18 libclang-rt-18-dev \
        cmake ninja-build gdb git ca-certificates curl \
        libgtest-dev libpcap-dev libnghttp2-dev librdkafka-dev libssl-dev \
        tcpdump tshark iproute2 iputils-ping \
        python3 python3-venv python3-pip \
        shellcheck docker.io \
    && update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-18 100 \
    && update-alternatives --install /usr/bin/clang clang /usr/bin/clang-18 100 \
    && update-alternatives --install /usr/bin/clang-tidy clang-tidy /usr/bin/clang-tidy-18 100 \
    && update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-18 100 \
    && rm -rf /var/lib/apt/lists/*

# Non-root user matching the default VS Code dev container UID.
RUN useradd -m -s /bin/bash -u 1001 dev || true
USER dev
WORKDIR /workspaces/prahari-5gc
