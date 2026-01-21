#!/bin/bash
# =============================================================================
# PSK + Kyber VPN Router Entrypoint (Open Source)
# =============================================================================

set -e

echo "=============================================="
echo "  Post-Quantum VPN Router (PSK + Kyber)"
echo "=============================================="

# Initialize PSK if not exists
if [ ! -f "/config/pqc-keys/wireguard.psk" ]; then
    echo "Generating Kyber-protected PSK..."
    /opt/pqc/bin/psk-kyber-wrapper.sh generate
fi

# Setup routing
/opt/pqc/bin/setup-routes.sh

echo "VPN Router ready"
exec "$@"
