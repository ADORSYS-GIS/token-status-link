package io.github.adorsysgis.keycloakstatuslist.service;

import static io.github.adorsysgis.keycloakstatuslist.model.IssuedCredentialStatusResponse.OVERFLOW_POLICY_REJECT;

import io.github.adorsysgis.keycloakstatuslist.StatusListProtocolMapper;
import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import io.github.adorsysgis.keycloakstatuslist.exception.CredentialIssuanceQuotaException;
import io.github.adorsysgis.keycloakstatuslist.jpa.repository.StatusListRepository;
import io.github.adorsysgis.keycloakstatuslist.model.IssuedCredentialStatusResponse.IssuedCredentialLimit;
import jakarta.persistence.EntityManager;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.oid4vci.CredentialScopeModel;
import org.keycloak.protocol.oid4vc.OID4VCLoginProtocolFactory;
import org.keycloak.utils.StringUtil;

/**
 * Enforces and reports the maximum number of non-revoked credentials per holder and credential type.
 */
public class CredentialIssuanceQuotaService {

    private static final Logger logger = Logger.getLogger(CredentialIssuanceQuotaService.class);

    public static final String MAX_CREDENTIALS_PER_USER_CONFIG = StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER;

    public static final String LIMIT_REACHED_MESSAGE =
            "Issued credential limit reached for this user and credential type";
    public static final String FAIL_CLOSED_MESSAGE =
            "Issued credential limit is configured but holder or credential type could not be resolved";

    private final StatusListRepository statusListRepository;

    public CredentialIssuanceQuotaService(StatusListRepository statusListRepository) {
        this.statusListRepository = statusListRepository;
    }

    /**
     * Resolves the configured maximum. Mapper / client-scope config wins when present (including
     * {@code 0} for unlimited). Blank or missing mapper values inherit the optional realm fallback.
     */
    public int resolveMax(ProtocolMapperModel mapperModel, RealmModel realm) {
        Optional<String> mapperValue = mapperConfigValue(mapperModel, MAX_CREDENTIALS_PER_USER_CONFIG);
        if (mapperValue.isPresent()) {
            return StatusListConfig.parseMaxCredentialsPerUser(mapperValue.get());
        }

        return realm == null ? 0 : new StatusListConfig(realm).getMaxCredentialsPerUser();
    }

    /**
     * Validates that holder and credential type are present when a limit is configured. Call before
     * reserving a status-list index; the count check runs later inside the reservation transaction
     * via {@link #enforceWithinReservationTransaction}.
     */
    public void requireHolderAndTypeWhenLimited(String userId, String credentialConfigurationId, int max) {
        if (max <= 0) {
            return;
        }
        if (StringUtil.isBlank(userId) || StringUtil.isBlank(credentialConfigurationId)) {
            logger.error(FAIL_CLOSED_MESSAGE);
            throw CredentialIssuanceQuotaException.failClosed(FAIL_CLOSED_MESSAGE);
        }
    }

    /**
     * Acquires the per-holder/type quota lock and rejects issuance when occupying mappings
     * ({@code INIT} or {@code SUCCESS}, not {@code INVALID}) already meet {@code max}. Must run in
     * the same transaction that persists the new {@code INIT} mapping.
     */
    public void enforceWithinReservationTransaction(
            EntityManager em, String realmId, String userId, String credentialConfigurationId, int max) {
        if (max <= 0) {
            return;
        }
        requireHolderAndTypeWhenLimited(userId, credentialConfigurationId, max);

        statusListRepository.acquireQuotaLock(em, realmId, userId, credentialConfigurationId);
        long occupyingCount =
                statusListRepository.countOccupyingMappings(em, realmId, userId, credentialConfigurationId);
        if (occupyingCount >= max) {
            logger.warnf(
                    "Rejecting issuance: userId=%s, credentialConfigurationId=%s, occupyingCount=%d, max=%d",
                    userId, credentialConfigurationId, occupyingCount, max);
            throw CredentialIssuanceQuotaException.limitReached(LIMIT_REACHED_MESSAGE);
        }
    }

    public void ensureQuotaLockExists(String realmId, String userId, String credentialConfigurationId, int max) {
        if (max <= 0) {
            return;
        }
        statusListRepository.ensureQuotaLockExists(realmId, userId, credentialConfigurationId);
    }

    /**
     * Returns quota metadata for OID4VC credential types that have a configured (non-zero) limit.
     */
    public List<IssuedCredentialLimit> listLimits(RealmModel realm, String userId) {
        if (realm == null || StringUtil.isBlank(userId)) {
            return List.of();
        }

        Map<String, Long> activeCounts =
                statusListRepository.countSuccessfulNonRevokedMappingsByType(realm.getId(), userId);
        Map<String, IssuedCredentialLimit> limits = new LinkedHashMap<>();

        realm.getClientScopesStream()
                .filter(scope -> OID4VCLoginProtocolFactory.PROTOCOL_ID.equals(scope.getProtocol()))
                .map(scope -> toLimit(scope, realm, activeCounts))
                .flatMap(Optional::stream)
                .forEach(limit -> limits.putIfAbsent(limit.credentialConfigurationId(), limit));

        return new ArrayList<>(limits.values());
    }

    private Optional<IssuedCredentialLimit> toLimit(
            ClientScopeModel scope, RealmModel realm, Map<String, Long> activeCounts) {
        ProtocolMapperModel mapper = findStatusListMapper(scope);
        if (mapper == null) {
            return Optional.empty();
        }

        int max = resolveMax(mapper, realm);
        if (max <= 0) {
            return Optional.empty();
        }

        String credentialConfigurationId = new CredentialScopeModel(scope).getCredentialConfigurationId();
        if (StringUtil.isBlank(credentialConfigurationId)) {
            return Optional.empty();
        }

        long activeCount = activeCounts.getOrDefault(credentialConfigurationId, 0L);
        return Optional.of(new IssuedCredentialLimit(
                credentialConfigurationId, max, activeCount, Math.max(0L, max - activeCount), OVERFLOW_POLICY_REJECT));
    }

    private static ProtocolMapperModel findStatusListMapper(ClientScopeModel scope) {
        return scope.getProtocolMappersStream()
                .filter(mapper -> StatusListProtocolMapper.Constants.MAPPER_ID.equals(mapper.getProtocolMapper()))
                .findFirst()
                .orElse(null);
    }

    private static Optional<String> mapperConfigValue(ProtocolMapperModel mapperModel, String key) {
        if (mapperModel == null || mapperModel.getConfig() == null) {
            return Optional.empty();
        }

        String value = mapperModel.getConfig().get(key);
        return StringUtil.isBlank(value) ? Optional.empty() : Optional.of(value);
    }
}
