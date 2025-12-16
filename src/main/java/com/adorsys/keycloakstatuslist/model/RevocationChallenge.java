package com.adorsys.keycloakstatuslist.model;

import java.time.Instant;

/**
 * Represents a nonce challenge issued for credential revocation.
 * Used to prevent replay attacks by ensuring each revocation request uses a fresh, one-time nonce.
 */
public record RevocationChallenge(
    String nonce,
    String audience,
    String credentialId,
    Instant expiresAt
) {
    /**
     * Checks if this challenge has expired.
     * @return true if the challenge is past its expiration time
     */
    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }
}
