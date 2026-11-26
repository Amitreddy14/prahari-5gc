# prahari-probe: passive 5G core signalling probe.
FROM ubuntu:24.04 AS build
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        g++ cmake ninja-build pkg-config libpcap-dev libssl-dev libnghttp2-dev librdkafka-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake -S . -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release \
        -DPRAHARI_BUILD_TESTS=OFF -DPRAHARI_WERROR=ON \
    && cmake --build /build --target prahari-probe

FROM ubuntu:24.04 AS runtime
ARG DEBIAN_FRONTEND=noninteractive
LABEL org.opencontainers.image.title="prahari-probe" \
      org.opencontainers.image.description="Passive 5G core signalling probe (PFCP, NGAP/NAS, HTTP/2 SBI)" \
      org.opencontainers.image.source="https://github.com/Amitreddy14/prahari-5gc"
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8t64 libssl3t64 libnghttp2-14 librdkafka1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/prahari-probe /usr/local/bin/prahari-probe
# The SUPI HMAC key arrives at run time via PRAHARI_SUPI_KEY; nothing secret is baked in.
RUN ! { ldd /usr/local/bin/prahari-probe | grep "not found"; } \
    && prahari-probe --version
ENTRYPOINT ["prahari-probe"]
