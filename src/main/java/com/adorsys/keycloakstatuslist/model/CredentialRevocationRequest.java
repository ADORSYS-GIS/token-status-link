package com.adorsys.keycloakstatuslist.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Request model for credential revocation.
 * Contains the credential to revoke and optional revocation reason.
 * Note: SD-JWT VP token should be passed as Bearer token in Authorization header.
 */
public class CredentialRevocationRequest {
    
    @JsonProperty("credential_id")
    private String credentialId;
    
    @JsonProperty("revocation_reason")
    private String revocationReason;
    
    public CredentialRevocationRequest() {
        // Default constructor for JSON deserialization
    }
    
    public CredentialRevocationRequest(String credentialId, String revocationReason) {
        this.credentialId = credentialId;
        this.revocationReason = revocationReason;
    }
    
    public String getCredentialId() {
        return credentialId;
    }
    
    public void setCredentialId(String credentialId) {
        this.credentialId = credentialId;
    }
    
    public String getRevocationReason() {
        return revocationReason;
    }
    
    public void setRevocationReason(String revocationReason) {
        this.revocationReason = revocationReason;
    }
} 
