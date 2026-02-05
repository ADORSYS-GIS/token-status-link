package com.adorsys.keycloakstatuslist.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Request model for credential revocation. Contains the credential to revoke and optional
 * revocation reason. Note: SD-JWT VP token should be passed as Bearer token in Authorization
 * header.
 */
public class CredentialRevocationRequest {

    public static final String REVOCATION_MODE_KEY = "mode";
    public static final String REVOCATION_REASON_KEY = "reason";

    public static final String CREDENTIAL_REVOCATION_MODE = "credential_revocation";

    @JsonProperty(REVOCATION_MODE_KEY)
    private String revocationMode;

    @JsonProperty(REVOCATION_REASON_KEY)
    private String revocationReason;

    public CredentialRevocationRequest() {
        // Default constructor for JSON deserialization
    }

    public CredentialRevocationRequest(String revocationMode, String revocationReason) {
        this.revocationMode = revocationMode;
        this.revocationReason = revocationReason;
    }

    public String getRevocationMode() {
        return revocationMode;
    }

    public void setRevocationMode(String revocationMode) {
        this.revocationMode = revocationMode;
    }

    public String getRevocationReason() {
        return revocationReason;
    }

    public void setRevocationReason(String revocationReason) {
        this.revocationReason = revocationReason;
    }
}
