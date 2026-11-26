# Prahari lab tools: the attack injector (prahari-attack) and the labeller
# (python -m prahari_analytics.labels). Build context is the repository root.
FROM python:3.12-slim
LABEL org.opencontainers.image.title="prahari-attacker" \
      org.opencontainers.image.description="Prahari-5GC attack injector + labeller (testbed only: refuses targets outside 172.22.0.0/24)" \
      org.opencontainers.image.source="https://github.com/Amitreddy14/prahari-5gc"
WORKDIR /opt/prahari
COPY attacks/ attacks/
COPY analytics/ analytics/
RUN pip install --no-cache-dir ./attacks ./analytics \
    && prahari-attack --version
# The second safety interlock (the first is the address allowlist in code).
ENV PRAHARI_LAB=1
WORKDIR /runs
CMD ["sleep", "infinity"]
