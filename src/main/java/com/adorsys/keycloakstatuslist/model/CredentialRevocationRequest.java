package com.adorsys.keycloakstatuslist.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Request model for credential revocation.
 * Contains the SD-JWT VP token proving ownership and the credential to revoke.
 */
public class CredentialRevocationRequest {
    
    @JsonProperty("sd_jwt_vp")
    private String sdJwtVp;
    
    @JsonProperty("credential_id")
    private String credentialId;
    
    @JsonProperty("revocation_reason")
    private String revocationReason;
    
    public CredentialRevocationRequest() {
        // Default constructor for JSON deserialization
    }
    
    public CredentialRevocationRequest(String sdJwtVp, String credentialId, String revocationReason) {
        this.sdJwtVp = sdJwtVp;
        this.credentialId = credentialId;
        this.revocationReason = revocationReason;
    }
    
    public String getSdJwtVp() {
        return sdJwtVp;
    }
    
    public void setSdJwtVp(String sdJwtVp) {
        this.sdJwtVp = sdJwtVp;
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
