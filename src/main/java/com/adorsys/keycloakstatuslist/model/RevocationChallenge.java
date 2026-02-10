package com.adorsys.keycloakstatuslist.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.keycloak.util.JsonSerialization;

import java.time.Instant;

/**
 * Response model for the revocation challenge endpoint.
 * Contains the nonce, audience, and expiration time for the wallet to use in
 * the revocation request.
 */
public class RevocationChallenge {

    @JsonProperty("nonce")
    private String nonce;

    @JsonProperty("aud")
    private String audience;

    @JsonProperty("exp")
    private long expiresAt;

    public RevocationChallenge() {
    }

    public RevocationChallenge(String nonce, String audience, int expiresIn) {
        this.nonce = nonce;
        this.audience = audience;
        this.expiresAt = Instant.now().plusSeconds(expiresIn).getEpochSecond();
    }

    /**
     * Checks if the challenge has expired based on its expiration time.
     */
    public boolean isExpired() {
        return Instant.now().isAfter(Instant.ofEpochSecond(expiresAt));
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public long getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(long expiresAt) {
        this.expiresAt = expiresAt;
    }

    @Override
    public String toString() {
        return JsonSerialization.valueAsString(this);
    }
}
