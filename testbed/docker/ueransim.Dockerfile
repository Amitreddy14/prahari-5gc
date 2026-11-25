# UERANSIM gNB + UE simulator, built from a pinned release tag and verified commit.
ARG UBUNTU=ubuntu:22.04

FROM ${UBUNTU} AS build
ARG DEBIAN_FRONTEND=noninteractive
ARG UERANSIM_VERSION=v3.2.8
ARG UERANSIM_COMMIT=ca1a66fffe282767bb08618af9f848e3b68ea47b
# Parallel compile jobs. Kept modest so the build fits in WSL2 memory.
ARG BUILD_JOBS=4

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git cmake make g++ libsctp-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 --branch "${UERANSIM_VERSION}" https://github.com/aligungr/UERANSIM.git . \
    && test "$(git rev-parse HEAD)" = "${UERANSIM_COMMIT}" \
    || { echo "UERANSIM ${UERANSIM_VERSION} does not match pinned commit ${UERANSIM_COMMIT}"; exit 1; }

# Call CMake directly: the upstream makefile uses the CodeBlocks generator,
# which newer CMake releases have dropped.
RUN cmake -DCMAKE_BUILD_TYPE=Release -G "Unix Makefiles" -S . -B build \
    && cmake --build build -j"${BUILD_JOBS}" --target nr-gnb nr-ue nr-cli devbnd

FROM ${UBUNTU} AS runtime
ARG DEBIAN_FRONTEND=noninteractive
LABEL org.opencontainers.image.title="prahari-ueransim" \
      org.opencontainers.image.description="UERANSIM v3.2.8 for the Prahari-5GC testbed" \
      org.opencontainers.image.source="https://github.com/Amitreddy14/prahari-5gc"

RUN apt-get update && apt-get install -y --no-install-recommends \
        libsctp1 iproute2 iputils-ping procps \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/build/nr-gnb /src/build/nr-ue /src/build/nr-cli /usr/local/bin/
COPY --from=build /src/build/libdevbnd.so /usr/local/lib/
RUN ! { ldd /usr/local/bin/nr-gnb /usr/local/bin/nr-ue | grep "not found"; }

COPY ue-entrypoint.sh /usr/local/bin/ue-entrypoint.sh
RUN chmod 0755 /usr/local/bin/ue-entrypoint.sh
