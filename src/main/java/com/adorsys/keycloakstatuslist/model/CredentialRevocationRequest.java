package com.adorsys.keycloakstatuslist.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Request model for issued credential revocation. Contains the Keycloak-issued credential id and
 * optional revocation reason. The authenticated user's access token must be passed as Bearer token
 * in the Authorization header.
 */
public class CredentialRevocationRequest {

    public static final String REVOCATION_MODE_KEY = "mode";
    public static final String REVOCATION_REASON_KEY = "reason";
    public static final String CREDENTIAL_ID_KEY = "credential_id";

    public static final String ISSUED_CREDENTIAL_REVOCATION_MODE = "issued_credential_revocation";

    @JsonProperty(REVOCATION_MODE_KEY)
    private String revocationMode;

    @JsonProperty(REVOCATION_REASON_KEY)
    private String revocationReason;

    @JsonProperty(CREDENTIAL_ID_KEY)
    private String credentialId;

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

    public String getCredentialId() {
        return credentialId;
    }

    public void setCredentialId(String credentialId) {
        this.credentialId = credentialId;
    }
}
