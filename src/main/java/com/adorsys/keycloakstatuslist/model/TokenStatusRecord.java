package com.adorsys.keycloakstatuslist.model;

import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;

public class TokenStatusRecord {
    @JsonProperty("credential_id")
    private String credentialId;

    @JsonProperty("iss")
    private String issuerId;

    @JsonProperty("status")
    private TokenStatus status;

    @JsonProperty("iat")
    private Instant issuedAt;

    @JsonProperty("exp")
    private Instant expiresAt;

    @JsonProperty("revoked_at")
    private Instant revokedAt;

    @JsonProperty("credential_type")
    private String credentialType;

    @JsonProperty("status_reason")
    private String statusReason;

    // Getters and setters
    public String getCredentialId() { return credentialId; }
    public void setCredentialId(String credentialId) { this.credentialId = credentialId; }

    public String getIssuerId() { return issuerId; }
    public void setIssuerId(String issuerId) { this.issuerId = issuerId; }

    public TokenStatus getStatus() { return status; }
    public void setStatus(TokenStatus status) { this.status = status; }

    public Instant getIssuedAt() { return issuedAt; }
    public void setIssuedAt(Instant issuedAt) { this.issuedAt = issuedAt; }

    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }

    public Instant getRevokedAt() { return revokedAt; }
    public void setRevokedAt(Instant revokedAt) { this.revokedAt = revokedAt; }

    public String getCredentialType() { return credentialType; }
    public void setCredentialType(String credentialType) { this.credentialType = credentialType; }

    public String getStatusReason() { return statusReason; }
    public void setStatusReason(String statusReason) { this.statusReason = statusReason; }
}

