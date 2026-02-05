package com.adorsys.keycloakstatuslist.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/**
 * Response model for the revocation challenge endpoint.
 * Contains the nonce, audience, and expiration time for the wallet to use in the revocation request.
 */
public class RevocationChallenge {
    
    @JsonProperty("nonce")
    private String nonce;
    
    @JsonProperty("aud")
    private String audience;
    
    @JsonProperty("expires_at")
    private long expiresAt;
    
    public RevocationChallenge() {
        // Default constructor for JSON serialization
    }
    
    public RevocationChallenge(String nonce, String audience, long expiresAt) {
        this.nonce = nonce;
        this.audience = audience;
        this.expiresAt = expiresAt;
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

    public void setExpiresAt(int expiresAt) {
        this.expiresAt = expiresAt;
    }

    public boolean isExpired() {
        return Instant.now().isAfter(Instant.ofEpochSecond(expiresAt));
    }
}
