package com.adorsys.keycloakstatuslist.model;

import java.time.Instant;

/**
 * Represents a token status record that follows the SD-JWT Status List specification.
 * This is the model that will be sent to the status list server.
 */
public class TokenStatusRecord {
    // The unique identifier for the SD-JWT credential
    private String credentialId;

    // The ID of the issuer of the credential
    private String issuerId;

    // The current status of the credential
    private TokenStatus status;

    // When the credential was issued
    private Instant issuedAt;

    // When the credential expires
    private Instant expiresAt;

    // When the credential was revoked (if applicable)
    private Instant revokedAt;

    // Optional reason for status change (especially for revocation)
    private String statusReason;

    // Optional type of the credential (e.g., "VerifiableCredential")
    private String credentialType;

    public TokenStatusRecord() {
    }


    // Getters and setters
    public String getCredentialId() {
        return credentialId;
    }

    public void setCredentialId(String credentialId) {
        this.credentialId = credentialId;
    }

    public String getIssuerId() {
        return issuerId;
    }

    public void setIssuerId(String issuerId) {
        this.issuerId = issuerId;
    }

    public TokenStatus getStatus() {
        return status;
    }

    public void setStatus(TokenStatus status) {
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

    public String getStatusReason() {
        return statusReason;
    }

    public void setStatusReason(String statusReason) {
        this.statusReason = statusReason;
    }

    public String getCredentialType() {
        return credentialType;
    }

    public void setCredentialType(String credentialType) {
        this.credentialType = credentialType;
    }

    @Override
    public String toString() {
        return "TokenStatusRecord{" +
                "credentialId='" + credentialId + '\'' +
                ", issuerId='" + issuerId + '\'' +
                ", status=" + status +
                ", issuedAt=" + issuedAt +
                ", expiresAt=" + expiresAt +
                ", revokedAt=" + revokedAt +
                ", statusReason='" + statusReason + '\'' +
                ", credentialType='" + credentialType + '\'' +
                '}';
    }
}