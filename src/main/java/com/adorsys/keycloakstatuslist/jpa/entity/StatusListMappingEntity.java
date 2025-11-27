package com.adorsys.keycloakstatuslist.jpa.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.GenericGenerator;
import java.util.Objects;

@Entity
@Table(name = "status_list_mapping", indexes = {
    @Index(name = "idx_status_list_token", columnList = "token_id")
})
public class StatusListMappingEntity {

    // CHANGED: Added a UUID Primary Key.
    // We use String ID with UUID generation for broad Keycloak compatibility.
    @Id
    @GeneratedValue(generator = "uuid2")
    @GenericGenerator(name = "uuid2", strategy = "uuid2")
    @Column(name = "id", length = 36)
    private String id;

    // CHANGED: 'idx' is no longer @Id. It is a generated sequence value.
    // We define the sequence generator here instead of in a separate file.
    @Column(name = "idx", nullable = false)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "status_list_seq_gen")
    @SequenceGenerator(name = "status_list_seq_gen", sequenceName = "status_list_counter_seq", allocationSize = 1)
    private Long idx;

    @Column(name = "status_list_id", nullable = false)
    private String statusListId;

    @Column(name = "user_id")
    private String userId;

    @Column(name = "token_id")
    private String tokenId;

    @Column(name = "realm_id")
    private String realmId;

    // Getters and Setters
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        StatusListMappingEntity that = (StatusListMappingEntity) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
