# Prahari lab tools: the attack injector (prahari-attack), the labeller
# (python -m prahari_analytics.labels) and the dataset builder
# (python -m prahari_analytics.dataset). Build context is the repository root.
FROM python:3.12-slim
LABEL org.opencontainers.image.title="prahari-attacker" \
      org.opencontainers.image.description="Prahari-5GC attack injector + labeller (testbed only: refuses targets outside 172.22.0.0/24)" \
      org.opencontainers.image.source="https://github.com/Amitreddy14/prahari-5gc"
WORKDIR /opt/prahari
COPY attacks/ attacks/
COPY analytics/ analytics/
# libsctp: N2 (NGAP over SCTP) attacks. gcc + libsctp-dev build the pysctp extension;
# only libsctp1 is kept at runtime (one layer, so the toolchain leaves no image weight).
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libsctp-dev libsctp1 \
    && pip install --no-cache-dir ./attacks "./analytics[dataset]" \
    && apt-get purge -y gcc libsctp-dev && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* \
    && prahari-attack --version
# The second safety interlock (the first is the address allowlist in code).
ENV PRAHARI_LAB=1
WORKDIR /runs
CMD ["sleep", "infinity"]
