package com.adorsys.keycloakstatuslist.model;

import java.time.Instant;

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

    // Proper getters and setters
    public String getTokenId() {
        return tokenId;
    }

    public void setTokenId(String tokenId) {
        this.tokenId = tokenId;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Instant getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(Instant issuedAt) {
        this.issuedAt = issuedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }

    public void setRevokedAt(Instant revokedAt) {
        this.revokedAt = revokedAt;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getClientId() {
        return clientId;
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