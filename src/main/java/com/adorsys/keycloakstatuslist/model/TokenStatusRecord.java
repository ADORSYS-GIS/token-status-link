package com.adorsys.keycloakstatuslist.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.time.Instant;

import org.keycloak.jose.jwk.JWK;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class TokenStatusRecord {

    // Static mapper for toString() to avoid creating it every time
    private static final ObjectMapper MAPPER =
            new ObjectMapper()
                    .registerModule(new JavaTimeModule())
                    .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    @JsonProperty("sub")
    private String credentialId;

    @JsonProperty("iss")
    private String issuerId;

    @JsonProperty("issuer")
    private String issuer;

    @JsonProperty("public_key")
    private JWK publicKey;

    @JsonProperty("status")
    private int status;

    @JsonProperty("iat")
    private long issuedAt;

    @JsonProperty("exp")
    private long expiresAt;

    @JsonProperty("idx")
    private Long index;

    @JsonProperty("type")
    private String credentialType;

    @JsonProperty("revoked_at")
    private Long revokedAt;

    @JsonProperty("status_reason")
    private String statusReason;

    @JsonProperty("list_id")
    private String listId;

    @JsonProperty("status_list")
    private StatusList statusList;

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
        this.issuer = issuerId;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public JWK getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(JWK publicKey) {
        this.publicKey = publicKey;
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(TokenStatus status) {
        this.status = status.getValue();
    }

    public Instant getIssuedAt() {
        return Instant.ofEpochSecond(issuedAt);
    }

    public void setIssuedAt(Instant issuedAt) {
        this.issuedAt = issuedAt.getEpochSecond();
    }

    public Instant getExpiresAt() {
        return Instant.ofEpochSecond(expiresAt);
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt.getEpochSecond();
    }

    public Long getIndex() {
        return index;
    }

    public void setIndex(Long index) {
        this.index = index;
    }

    public String getCredentialType() {
        return credentialType;
    }

    public void setCredentialType(String credentialType) {
        this.credentialType = credentialType;
    }

    public Instant getRevokedAt() {
        return revokedAt != null ? Instant.ofEpochSecond(revokedAt) : null;
    }

    public void setRevokedAt(Instant revokedAt) {
        this.revokedAt = revokedAt != null ? revokedAt.getEpochSecond() : null;
    }

    public String getStatusReason() {
        return statusReason;
    }

    public void setStatusReason(String statusReason) {
        this.statusReason = statusReason;
    }

    @Override
    public String toString() {
        try {
            return MAPPER.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            // Fallback in unlikely event of serialization failure
            return "TokenStatusRecord{credentialId='" + credentialId + "', status=" + status + "}";
        }
    }

    public static class StatusList {
        @JsonProperty("lst")
        private String lst;

        @JsonProperty("status_size")
        private int statusSize;
    }
}
