# =============================================================================
# Post-Quantum VPN Router - WireGuard + PSK (Open Source)
# =============================================================================
# Production-ready with Kyber-encapsulated PSK
# MIT License | Enterprise support: grant@abejar.net
# =============================================================================

FROM linuxserver/wireguard:latest

LABEL maintainer="Abejar <grant@abejar.net>"
LABEL description="Post-Quantum VPN Router with PSK + Kyber (Open Source)"
LABEL license="MIT"

# Install dependencies
RUN apk add --no-cache \
    curl \
    jq \
    openssl \
    python3 \
    py3-pip \
    bash

# Create directories
RUN mkdir -p /opt/pqc/bin /opt/pqc/lib /config/pqc-keys

# Copy scripts (FULL SOURCE)
COPY pqc-lib/psk-kyber-wrapper.sh /opt/pqc/bin/
COPY config/routing/setup-routes.sh /opt/pqc/bin/
COPY entrypoint-psk.sh /opt/pqc/bin/
COPY healthcheck.sh /healthcheck.sh

# Set permissions
RUN chmod +x /opt/pqc/bin/* /healthcheck.sh

ENV PQC_ENABLED=true
ENV PQC_ALGORITHM=wireguard-psk

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD /healthcheck.sh

ENTRYPOINT ["/init"]
