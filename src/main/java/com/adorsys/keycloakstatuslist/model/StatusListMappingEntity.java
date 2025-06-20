package com.adorsys.keycloakstatuslist.model;

import jakarta.persistence.*;
import java.util.Objects;

@Entity
@Table(name = "status_list_mapping")
public class StatusListMappingEntity {

    @Id
    @Column(name = "idx", nullable = false)
    private long idx;

    // You can't have two primary keys on the same resource
    @Column(name = "status_list_id", nullable = false)
    private String statusListId;

    @Column(name = "user_id")
    private String userId;

    @Column(name = "token_id")
    private String tokenId;

    @Column(name = "realm_id")
    private String realmId;

    public String getStatusListId() {
        return statusListId;
    }

    public void setStatusListId(String statusListId) {
        this.statusListId = statusListId;
    }

    public long getIdx() {
        return idx;
    }

    public void setIdx(long idx) {
        this.idx = idx;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getTokenId() {
        return tokenId;
    }

    public void setTokenId(String tokenId) {
        this.tokenId = tokenId;
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(String realmId) {
        this.realmId = realmId;
    }

    public static class StatusListMappingId implements java.io.Serializable {
        private String statusListId;
        private long idx;

        public StatusListMappingId() {
        }

        public StatusListMappingId(String statusListId, long idx) {
            this.statusListId = statusListId;
            this.idx = idx;
        }

        public String getStatusListId() {
            return statusListId;
        }

        public void setStatusListId(String statusListId) {
            this.statusListId = statusListId;
        }

        public long getIdx() {
            return idx;
        }

        public void setIdx(long idx) {
            this.idx = idx;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o)
                return true;
            if (!(o instanceof StatusListMappingId))
                return false;
            StatusListMappingId that = (StatusListMappingId) o;
            return idx == that.idx && Objects.equals(statusListId, that.statusListId);
        }

        @Override
        public int hashCode() {
            return Objects.hash(statusListId, idx);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (!(o instanceof StatusListMappingEntity))
            return false;
        StatusListMappingEntity that = (StatusListMappingEntity) o;
        return idx == that.idx && Objects.equals(statusListId, that.statusListId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(statusListId, idx);
    }
}