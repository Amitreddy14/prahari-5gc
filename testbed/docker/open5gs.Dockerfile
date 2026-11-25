# Open5GS 5G core, built from a pinned release tag and verified commit.
# One image holds every network function; compose picks the binary per service.
ARG UBUNTU=ubuntu:22.04

FROM ${UBUNTU} AS build
ARG DEBIAN_FRONTEND=noninteractive
ARG OPEN5GS_VERSION=v2.7.7
ARG OPEN5GS_COMMIT=318eeb49a7dcdff733dec60e02d9c60aefca2fb9
# Parallel compile jobs. Kept modest so the build fits in WSL2 memory.
ARG BUILD_JOBS=4

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git meson ninja-build build-essential cmake flex bison pkg-config \
        python3-setuptools python3-wheel \
        libsctp-dev libgnutls28-dev libgcrypt-dev libssl-dev libmongoc-dev libbson-dev \
        libyaml-dev libnghttp2-dev libmicrohttpd-dev libcurl4-gnutls-dev libtins-dev \
        libtalloc-dev libidn-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 --branch "${OPEN5GS_VERSION}" https://github.com/open5gs/open5gs.git . \
    && test "$(git rev-parse HEAD)" = "${OPEN5GS_COMMIT}" \
    || { echo "Open5GS ${OPEN5GS_VERSION} does not match pinned commit ${OPEN5GS_COMMIT}"; exit 1; }

RUN meson setup build --prefix=/opt/open5gs --buildtype=release \
    && ninja -C build -j"${BUILD_JOBS}" install

FROM ${UBUNTU} AS runtime
ARG DEBIAN_FRONTEND=noninteractive
LABEL org.opencontainers.image.title="prahari-open5gs" \
      org.opencontainers.image.description="Open5GS v2.7.7 for the Prahari-5GC testbed" \
      org.opencontainers.image.source="https://github.com/Amitreddy14/prahari-5gc"

RUN apt-get update && apt-get install -y --no-install-recommends \
        libsctp1 libgnutls30 libgcrypt20 libssl3 libmongoc-1.0-0 libbson-1.0-0 libyaml-0-2 \
        libnghttp2-14 libmicrohttpd12 libcurl3-gnutls libtins4.0 libtalloc2 libidn12 \
        iproute2 iptables netcat-openbsd procps ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /opt/open5gs /opt/open5gs
ENV PATH=/opt/open5gs/bin:${PATH}

# Register Open5GS's own libraries with the loader. The binaries carry a RUNPATH,
# but the libraries do not, so they need this to find each other.
RUN echo /opt/open5gs/lib/x86_64-linux-gnu > /etc/ld.so.conf.d/open5gs.conf && ldconfig

# Fail the build (not the first run) if any shared library is missing.
RUN ! { ldd /opt/open5gs/bin/open5gs-*d /opt/open5gs/lib/x86_64-linux-gnu/*.so* 2>/dev/null | grep "not found"; }

COPY upf-entrypoint.sh /usr/local/bin/upf-entrypoint.sh
RUN chmod 0755 /usr/local/bin/upf-entrypoint.sh \
    && useradd --system --no-create-home --shell /usr/sbin/nologin open5gs

# Every NF except the UPF runs unprivileged (compose overrides user for the UPF).
USER open5gs
