package io.github.adorsysgis.keycloakstatuslist.jpa.entity;

import jakarta.persistence.Access;
import jakarta.persistence.AccessType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.util.Objects;

/**
 * Per-(realm, holder, credential type) row used to serialize quota check + index reservation.
 */
@Entity
@Access(AccessType.FIELD)
@Table(name = "status_list_quota_lock")
@IdClass(StatusListQuotaLockEntity.QuotaLockId.class)
public class StatusListQuotaLockEntity {

    @Id
    @Column(name = "realm_id", nullable = false)
    private String realmId;

    @Id
    @Column(name = "user_id", nullable = false)
    private String userId;

    @Id
    @Column(name = "credential_configuration_id", nullable = false)
    private String credentialConfigurationId;

    public StatusListQuotaLockEntity() {}

    public StatusListQuotaLockEntity(String realmId, String userId, String credentialConfigurationId) {
        this.realmId = realmId;
        this.userId = userId;
        this.credentialConfigurationId = credentialConfigurationId;
    }

    public String getRealmId() {
        return realmId;
    }

    public String getUserId() {
        return userId;
    }

    public String getCredentialConfigurationId() {
        return credentialConfigurationId;
    }

    public static final class QuotaLockId implements Serializable {

        private String realmId;
        private String userId;
        private String credentialConfigurationId;

        public QuotaLockId() {}

        public QuotaLockId(String realmId, String userId, String credentialConfigurationId) {
            this.realmId = realmId;
            this.userId = userId;
            this.credentialConfigurationId = credentialConfigurationId;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            QuotaLockId that = (QuotaLockId) o;
            return Objects.equals(realmId, that.realmId)
                    && Objects.equals(userId, that.userId)
                    && Objects.equals(credentialConfigurationId, that.credentialConfigurationId);
        }

        @Override
        public int hashCode() {
            return Objects.hash(realmId, userId, credentialConfigurationId);
        }
    }
}
