package com.adorsys.keycloakstatuslist.jpa.entity;

import jakarta.persistence.Access;
import jakarta.persistence.AccessType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.keycloak.common.util.Time;

import java.util.Objects;

@Entity
@Access(AccessType.FIELD)
@Table(name = "status_list_mapping")
public class StatusListMappingEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", length = 36)
    private String id;

    // The index of the mapped token in the status list
    @Column(name = "idx", nullable = false)
    private Long idx;

    @Column(name = "status_list_id", nullable = false)
    private String statusListId;

    @Column(name = "user_id")
    private String userId;

    @Column(name = "token_id")
    private String tokenId;

    @Column(name = "realm_id")
    private String realmId;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private MappingStatus status = MappingStatus.INIT;

    @Column(name = "created_timestamp", nullable = false, updatable = false)
    private final Long createdTimestamp = Time.currentTimeMillis();

    // --- Getters and Setters ---

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Long getIdx() {
        return idx;
    }

    public void setIdx(Long idx) {
        this.idx = idx;
    }

    public String getStatusListId() {
        return statusListId;
    }

    public void setStatusListId(String statusListId) {
        this.statusListId = statusListId;
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

    public MappingStatus getStatus() {
        return status;
    }

    public StatusListMappingEntity setStatus(MappingStatus status) {
        this.status = status;
        return this;
    }

    public Long getCreatedTimestamp() {
        return createdTimestamp;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        StatusListMappingEntity that = (StatusListMappingEntity) o;
        return Objects.equals(getId(), that.getId()) && Objects.equals(getIdx(), that.getIdx()) && Objects.equals(getStatusListId(), that.getStatusListId()) && Objects.equals(getUserId(), that.getUserId()) && Objects.equals(getTokenId(), that.getTokenId()) && Objects.equals(getRealmId(), that.getRealmId()) && getStatus() == that.getStatus() && Objects.equals(getCreatedTimestamp(), that.getCreatedTimestamp());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getId(), getIdx(), getStatusListId(), getUserId(), getTokenId(), getRealmId(), getStatus(), getCreatedTimestamp());
    }

    public enum MappingStatus {
        INIT, SUCCESS, FAILURE
    }
}
