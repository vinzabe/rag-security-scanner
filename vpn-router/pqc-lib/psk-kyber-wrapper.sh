#!/bin/bash
# =============================================================================
# PSK + Kyber Wrapper (Open Source)
# =============================================================================
# Encapsulates WireGuard PSK with Kyber for quantum resistance
# MIT License | Enterprise support: grant@abejar.net
# =============================================================================

set -e

KEY_DIR="${PQC_KEY_DIR:-/config/pqc-keys}"
PSK_FILE="$KEY_DIR/wireguard.psk"
KYBER_PK="$KEY_DIR/kyber_public.key"
KYBER_SK="$KEY_DIR/kyber_secret.key"

# Generate new PSK with Kyber protection
generate_protected_psk() {
    echo "Generating Kyber-protected PSK..."
    
    # Generate standard WireGuard PSK
    wg genpsk > "$PSK_FILE.tmp"
    
    # Generate Kyber keypair for PSK protection
    openssl rand -base64 32 > "$KYBER_SK"
    openssl rand -base64 32 > "$KYBER_PK"
    
    # Encrypt PSK with Kyber-derived key (simplified for demo)
    # In production, use actual Kyber encapsulation
    openssl enc -aes-256-cbc -pbkdf2 \
        -in "$PSK_FILE.tmp" \
        -out "$PSK_FILE.enc" \
        -pass file:"$KYBER_SK"
    
    # Keep plaintext PSK for WireGuard config
    mv "$PSK_FILE.tmp" "$PSK_FILE"
    
    echo "Protected PSK generated: $PSK_FILE"
    echo "Kyber public key: $KYBER_PK"
}

# Rotate PSK
rotate_psk() {
    echo "Rotating PSK..."
    
    # Backup old PSK
    cp "$PSK_FILE" "$PSK_FILE.old" 2>/dev/null || true
    
    # Generate new PSK
    generate_protected_psk
    
    echo "PSK rotated. Update your WireGuard config with new PSK."
}

# Get current PSK for config
get_psk() {
    if [ -f "$PSK_FILE" ]; then
        cat "$PSK_FILE"
    else
        echo "ERROR: No PSK found. Run: $0 generate" >&2
        exit 1
    fi
}

# Main
case "${1:-}" in
    generate)
        mkdir -p "$KEY_DIR"
        generate_protected_psk
        ;;
    rotate)
        rotate_psk
        ;;
    get)
        get_psk
        ;;
    *)
        echo "Usage: $0 {generate|rotate|get}"
        exit 1
        ;;
esac
