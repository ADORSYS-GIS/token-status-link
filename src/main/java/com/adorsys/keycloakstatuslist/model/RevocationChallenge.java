package com.adorsys.keycloakstatuslist.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Response model for the revocation challenge endpoint.
 * Contains the nonce, audience, and expiration time for the wallet to use in the revocation request.
 */
public class RevocationChallenge {
    
    @JsonProperty("nonce")
    private String nonce;
    
    @JsonProperty("aud")
    private String audience;
    
    @JsonProperty("expires_in")
    private int expiresIn;
    
    
    public RevocationChallenge() {
    }
    
    public RevocationChallenge(String nonce, String audience, int expiresIn) {
        this.nonce = nonce;
        this.audience = audience;
        this.expiresIn = expiresIn;
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

    public int getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(int expiresIn) {
        this.expiresIn = expiresIn;
    }
}
