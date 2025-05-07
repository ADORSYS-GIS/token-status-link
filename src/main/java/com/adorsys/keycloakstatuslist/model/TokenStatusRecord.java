package com.adorsys.keycloakstatuslist.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;

public class TokenStatusRecord {
    @JsonProperty("sub")
    private String credentialId;

    @JsonProperty("iss")
    private String issuerId;

    @JsonProperty("status")
    private int status;

    @JsonProperty("iat")
    private long issuedAt;

    @JsonProperty("exp")
    private long expiresAt;

    @JsonProperty("idx")
    private Long index;

    @JsonProperty("credential_type")
    private String credentialType;

    @JsonProperty("revoked_at")
    private Long revokedAt;

    @JsonProperty("status_reason")
    private String statusReason;

    @JsonProperty("list_id")
    private String listId;

    @JsonProperty("status_list")
    private StatusList statusList;

    public static class StatusList {
        @JsonProperty("lst")
        private String lst;

        @JsonProperty("status_size")
        private int statusSize;

        public String getLst() {
            return lst;
        }

        public void setLst(String lst) {
            this.lst = lst;
        }

        public int getStatusSize() {
            return statusSize;
        }

        public void setStatusSize(int statusSize) {
            this.statusSize = statusSize;
        }
    }

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

    public String getListId() {
        return listId;
    }

    public void setListId(String listId) {
        this.listId = listId;
    }

    public StatusList getStatusList() {
        return statusList;
    }

    public void setStatusList(StatusList statusList) {
        this.statusList = statusList;
    }

    @Override
    public String toString() {
        return "TokenStatusRecord{" +
                "credentialId='" + credentialId + '\'' +
                ", issuerId='" + issuerId + '\'' +
                ", status=" + status +
                ", issuedAt=" + issuedAt +
                ", expiresAt=" + expiresAt +
                ", index=" + index +
                ", credentialType='" + credentialType + '\'' +
                ", revokedAt=" + revokedAt +
                ", statusReason='" + statusReason + '\'' +
                ", listId='" + listId + '\'' +
                ", statusList=" + statusList +
                '}';
    }
}