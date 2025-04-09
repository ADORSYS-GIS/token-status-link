package com.adorsys.keycloakstatuslist.model;

import java.time.Instant;

/**
 * Represents a token's status information to be published to the statuslist server.
 */
public class TokenStatus {
    private String tokenId;
    private String userId;
    private String status; // "ACTIVE", "REVOKED", "EXPIRED"
    private Instant issuedAt;
    private Instant expiresAt;
    private Instant revokedAt;
    private String issuer;
    private String clientId;

    // Constructor with essential fields
    public TokenStatus(String tokenId, String userId, String status, String issuer, String clientId) {
        this.tokenId = tokenId;
        this.userId = userId;
        this.status = status;
        this.issuer = issuer;
        this.clientId = clientId;
        this.issuedAt = Instant.now();
    }

    public TokenStatus() {

    }

    public void setTokenId(String tokenId) {
        this.tokenId = tokenId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public void setIssuedAt(Instant issuedAt) {
        this.issuedAt = issuedAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }


    public void setRevokedAt(Instant revokedAt) {
        this.revokedAt = revokedAt;
    }


    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }


    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    @Override
    public String toString() {
        return "TokenStatus{" +
                "tokenId='" + tokenId + '\'' +
                ", userId='" + userId + '\'' +
                ", status='" + status + '\'' +
                ", issuedAt=" + issuedAt +
                ", expiresAt=" + expiresAt +
                ", revokedAt=" + revokedAt +
                ", issuer='" + issuer + '\'' +
                ", clientId='" + clientId + '\'' +
                '}';
    }
}