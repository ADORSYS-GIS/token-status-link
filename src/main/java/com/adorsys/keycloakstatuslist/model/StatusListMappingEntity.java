package com.adorsys.keycloakstatuslist.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "status_list_mapping")
public class StatusListMappingEntity {
    @Id
    @Column(name = "idx")
    private long idx;

    @Column(name = "user_id")
    private String userId;

    @Column(name = "token_id")
    private String tokenId;

    @Column(name = "realm_id")
    private String realmId;

    // Getters and setters
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
}