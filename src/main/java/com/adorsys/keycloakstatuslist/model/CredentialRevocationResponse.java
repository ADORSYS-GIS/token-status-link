package com.adorsys.keycloakstatuslist.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/**
 * Response model for credential revocation. Contains the result of the revocation operation.
 */
public class CredentialRevocationResponse {

    @JsonProperty("success")
    private boolean success;

    @JsonProperty("credential_id")
    private String credentialId;

    @JsonProperty("revoked_at")
    private Instant revokedAt;

    @JsonProperty("revocation_reason")
    private String revocationReason;

    @JsonProperty("message")
    private String message;

    public CredentialRevocationResponse() {
        // Default constructor for JSON serialization
    }

    public CredentialRevocationResponse(
            boolean success,
            String credentialId,
            Instant revokedAt,
            String revocationReason,
            String message) {
        this.success = success;
        this.credentialId = credentialId;
        this.revokedAt = revokedAt;
        this.revocationReason = revocationReason;
        this.message = message;
    }

    public static CredentialRevocationResponse success(
            String credentialId, Instant revokedAt, String revocationReason) {
        return new CredentialRevocationResponse(
                true, credentialId, revokedAt, revocationReason, "Credential revoked successfully");
    }

    public static CredentialRevocationResponse error(String message) {
        return new CredentialRevocationResponse(false, null, null, null, message);
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public String getCredentialId() {
        return credentialId;
    }

    public void setCredentialId(String credentialId) {
        this.credentialId = credentialId;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }

    public void setRevokedAt(Instant revokedAt) {
        this.revokedAt = revokedAt;
    }

    public String getRevocationReason() {
        return revocationReason;
    }

    public void setRevocationReason(String revocationReason) {
        this.revocationReason = revocationReason;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
