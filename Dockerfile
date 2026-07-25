# cyber-posture — portable exposure + host integrity scanner
# Multi-arch: linux/amd64, linux/arm64
ARG BASE=ubuntu:24.04
FROM ${BASE}

LABEL org.opencontainers.image.title="cyber-posture" \
      org.opencontainers.image.description="Linux cyber exposure + host integrity / malware IoC scanner" \
      org.opencontainers.image.source="https://github.com/marctheshark3/cyber-posture" \
      org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CYBER_STATE_DIR=/var/lib/cyber-posture \
    CYBER_REPORT_DIR=/var/lib/cyber-posture/reports \
    CYBER_CONFIG_DIR=/etc/cyber-posture \
    PATH="/opt/cyber-posture/bin:${PATH}"

# Runtime deps: python, ss/iproute, clam/rkh tools (docker_ps needs host docker CLI or socket+cli)
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 \
      python3-yaml \
      ca-certificates \
      curl \
      iproute2 \
      procps \
      util-linux \
      cron \
      clamav \
      clamav-freshclam \
      rkhunter \
      chkrootkit \
      debsums \
      lynis \
    && rm -rf /var/lib/apt/lists/* \
    && (freshclam || true) \
    && mkdir -p /var/lib/cyber-posture/reports /var/lib/cyber-posture/host-integrity /etc/cyber-posture

WORKDIR /opt/cyber-posture

COPY bin/ ./bin/
COPY lib/ ./lib/
COPY config/ ./config/
COPY scripts/ ./scripts/
COPY VERSION ./VERSION
COPY LICENSE NOTICE.md ./

RUN chmod +x bin/cyber-posture scripts/*.sh \
    && ln -sf /opt/cyber-posture/bin/cyber-posture /usr/local/bin/cyber-posture \
    && cp config/default.yaml /etc/cyber-posture/config.yaml

# Non-root default; host scans often need --user root + host ns
RUN useradd -m -u 10001 -s /bin/bash cyber \
    && chown -R cyber:cyber /var/lib/cyber-posture
USER cyber

VOLUME ["/var/lib/cyber-posture", "/etc/cyber-posture"]

ENTRYPOINT ["cyber-posture"]
CMD ["scan"]
