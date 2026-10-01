package io.github.adorsysgis.keycloakstatuslist.service;

import static io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER;

import io.github.adorsysgis.keycloakstatuslist.StatusListProtocolMapper;
import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import io.github.adorsysgis.keycloakstatuslist.exception.CredentialIssuanceQuotaException;
import io.github.adorsysgis.keycloakstatuslist.exception.StatusListException;
import io.github.adorsysgis.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import io.github.adorsysgis.keycloakstatuslist.jpa.repository.StatusListRepository;
import io.github.adorsysgis.keycloakstatuslist.model.IssuedCredentialStatusResponse.IssuedCredentialLimit;
import io.github.adorsysgis.keycloakstatuslist.model.TokenStatus;
import jakarta.persistence.EntityManager;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.IssuedVerifiableCredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.oid4vci.CredentialScopeModel;
import org.keycloak.protocol.oid4vc.OID4VCLoginProtocolFactory;
import org.keycloak.utils.StringUtil;

/**
 * Enforces and reports the maximum number of non-revoked credentials per holder and credential type.
 *
 * <p>The two-argument constructor is for read-only quota reporting ({@link #listLimits}). Enforcement
 * with {@code REVOKE_OLDEST} requires the three-argument form that supplies a
 * {@link CredentialRevocationService}.
 */
public class CredentialIssuanceQuotaService {

    private static final Logger logger = Logger.getLogger(CredentialIssuanceQuotaService.class);

    private static final Comparator<StatusListMappingEntity> OLDEST_OCCUPYING_MAPPING = Comparator.comparing(
                    StatusListMappingEntity::getCreatedTimestamp, Comparator.nullsLast(Long::compareTo))
            .thenComparing(StatusListMappingEntity::getId, Comparator.nullsLast(String::compareTo));

    public static final String LIMIT_REACHED_MESSAGE =
            "Issued credential limit reached for this user and credential type";
    public static final String FAIL_CLOSED_MESSAGE =
            "Issued credential limit is configured but holder or credential type could not be resolved";
    public static final String OVERFLOW_POLICY_REJECT = "REJECT";
    public static final String OVERFLOW_POLICY_REVOKE_OLDEST = "REVOKE_OLDEST";
    public static final String REVOKE_OLDEST_FAILED_MESSAGE =
            "Failed to revoke the oldest credential to free an issuance slot";
    public static final String REVOKE_OLDEST_UNAVAILABLE_MESSAGE =
            "Overflow policy REVOKE_OLDEST requires revocation support";

    private final KeycloakSession session;
    private final StatusListRepository statusListRepository;
    private final CredentialRevocationService credentialRevocationService;

    /** Read-only use (listing). {@code REVOKE_OLDEST} enforcement needs the overload below. */
    public CredentialIssuanceQuotaService(KeycloakSession session, StatusListRepository statusListRepository) {
        this(session, statusListRepository, null);
    }

    public CredentialIssuanceQuotaService(
            KeycloakSession session,
            StatusListRepository statusListRepository,
            CredentialRevocationService credentialRevocationService) {
        this.session = session;
        this.statusListRepository = statusListRepository;
        this.credentialRevocationService = credentialRevocationService;
    }

    /**
     * Resolves the configured maximum. Mapper / client-scope config wins when present (including
     * {@code 0} for unlimited). Blank or missing mapper values inherit the optional realm fallback.
     */
    public int resolveMax(ProtocolMapperModel mapperModel, RealmModel realm) {
        Optional<String> mapperValue = mapperConfigValue(mapperModel, STATUS_LIST_MAX_CREDENTIALS_PER_USER);
        if (mapperValue.isPresent()) {
            return StatusListConfig.parseMaxCredentialsPerUser(mapperValue.get());
        }

        return realm == null ? 0 : new StatusListConfig(realm).getMaxCredentialsPerUser();
    }

    /**
     * Resolves the overflow policy. A mapper / client-scope value wins when present. If the mapper
     * omits the key, the optional realm attribute is used. Defaults to {@code REJECT}.
     */
    public String resolveOverflowPolicy(ProtocolMapperModel mapperModel, RealmModel realm) {
        Optional<String> mapperValue = mapperConfigValue(mapperModel, StatusListConfig.STATUS_LIST_OVERFLOW_POLICY);
        if (mapperValue.isPresent()) {
            return StatusListConfig.parseOverflowPolicy(mapperValue.get());
        }

        return realm == null
                ? StatusListConfig.DEFAULT_OVERFLOW_POLICY
                : new StatusListConfig(realm).getOverflowPolicy();
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
     * Rejects issuance when {@code activeCount} (same algorithm as {@link #listLimits}) plus in-flight
     * {@code INIT} rows already meet {@code max}. {@code INIT} is extra so concurrent reservation
     * cannot overshoot; it is not part of displayed {@code activeCount}.
     *
     * <p>For {@code REVOKE_OLDEST}, marks the oldest occupying slot {@code INVALID} locally and
     * returns a {@code SUCCESS} mapping that still needs a status-list publish after this transaction
     * commits ({@link #publishOverflowRevocation}). {@code FAILURE} rows are freed locally only
     * (return {@code null}). A completed local free is kept even if a later issuance step fails.
     *
     * @return mapping that must be published remotely after commit, or {@code null} when no remote
     *     publish is required
     */
    public StatusListMappingEntity enforceWithinReservationTransaction(
            EntityManager em,
            String realmId,
            String userId,
            String credentialConfigurationId,
            int max,
            String overflowPolicy) {
        if (max <= 0) {
            return null;
        }
        requireHolderAndTypeWhenLimited(userId, credentialConfigurationId, max);

        Set<String> issuedIds = new LinkedHashSet<>(issuedCredentialIds(userId));
        long activeCount = countIssuedNonRevoked(
                statusListRepository.findNonRevokedMappings(em, realmId, userId, credentialConfigurationId), issuedIds);
        long inFlight = statusListRepository.countInFlightMappings(em, realmId, userId, credentialConfigurationId);
        long countTowardLimit = activeCount + inFlight;
        if (countTowardLimit < max) {
            return null;
        }

        String policy = StatusListConfig.parseOverflowPolicy(overflowPolicy);
        if (OVERFLOW_POLICY_REVOKE_OLDEST.equals(policy)) {
            return freeOldestOccupyingSlot(
                    em, realmId, userId, credentialConfigurationId, max, countTowardLimit, issuedIds);
        }

        logger.warnf(
                "Rejecting issuance: userId=%s, credentialConfigurationId=%s, countTowardLimit=%d, max=%d",
                userId, credentialConfigurationId, countTowardLimit, max);
        throw CredentialIssuanceQuotaException.limitReached(LIMIT_REACHED_MESSAGE);
    }

    /**
     * Publishes {@code INVALID} for a mapping freed locally by {@code REVOKE_OLDEST}. Call only after
     * the reservation transaction that marked it {@code INVALID} has committed. On failure, restore
     * the local row to {@code VALID} so fail-closed leaves no half-applied revoke.
     */
    public void publishOverflowRevocation(StatusListMappingEntity mapping) {
        if (mapping == null) {
            return;
        }
        if (credentialRevocationService == null) {
            logger.error(REVOKE_OLDEST_UNAVAILABLE_MESSAGE);
            restoreTokenStatus(mapping, TokenStatus.VALID);
            throw CredentialIssuanceQuotaException.failClosed(REVOKE_OLDEST_UNAVAILABLE_MESSAGE);
        }

        try {
            credentialRevocationService.publishRevocation(mapping);
        } catch (StatusListException | RuntimeException e) {
            logger.errorf(
                    e,
                    "Failed to publish overflow revocation: mappingId=%s, tokenId=%s",
                    mapping.getId(),
                    mapping.getTokenId());
            restoreTokenStatus(mapping, TokenStatus.VALID);
            throw CredentialIssuanceQuotaException.failClosed(REVOKE_OLDEST_FAILED_MESSAGE);
        }
    }

    /**
     * Frees one occupying slot or throws. Prefers the oldest {@code SUCCESS} mapping (local
     * {@code INVALID}, remote publish deferred); otherwise frees the oldest {@code FAILURE} locally.
     *
     * @return {@code SUCCESS} mapping awaiting remote publish, or {@code null} when only a local free
     *     was required
     */
    private StatusListMappingEntity freeOldestOccupyingSlot(
            EntityManager em,
            String realmId,
            String userId,
            String credentialConfigurationId,
            int max,
            long countTowardLimit,
            Set<String> issuedIds) {
        List<StatusListMappingEntity> occupying =
                statusListRepository.findNonRevokedMappings(em, realmId, userId, credentialConfigurationId).stream()
                        .filter(mapping -> occupiesIssuedSlot(mapping, issuedIds))
                        .toList();

        StatusListMappingEntity oldestSuccess = occupying.stream()
                .filter(mapping -> mapping.getStatus() == StatusListMappingEntity.MappingStatus.SUCCESS)
                .min(OLDEST_OCCUPYING_MAPPING)
                .orElse(null);
        if (oldestSuccess != null) {
            return markSuccessfulMappingInvalidLocally(
                    em, oldestSuccess, userId, credentialConfigurationId, max, countTowardLimit);
        }

        StatusListMappingEntity oldestFailure = occupying.stream()
                .filter(mapping -> mapping.getStatus() == StatusListMappingEntity.MappingStatus.FAILURE)
                .min(OLDEST_OCCUPYING_MAPPING)
                .orElse(null);
        if (oldestFailure != null) {
            // FAILURE still occupies quota (Keycloak issued the credential; status publish may never
            // have reached the server), so free it locally without a status-list call.
            freeFailedMappingLocally(em, oldestFailure, userId, credentialConfigurationId, max, countTowardLimit);
            return null;
        }

        logger.warnf(
                "No oldest mapping found to revoke despite countTowardLimit=%d: userId=%s, credentialConfigurationId=%s",
                countTowardLimit, userId, credentialConfigurationId);
        throw CredentialIssuanceQuotaException.limitReached(LIMIT_REACHED_MESSAGE);
    }

    private StatusListMappingEntity markSuccessfulMappingInvalidLocally(
            EntityManager em,
            StatusListMappingEntity oldest,
            String userId,
            String credentialConfigurationId,
            int max,
            long countTowardLimit) {
        if (credentialRevocationService == null) {
            logger.error(REVOKE_OLDEST_UNAVAILABLE_MESSAGE);
            throw CredentialIssuanceQuotaException.failClosed(REVOKE_OLDEST_UNAVAILABLE_MESSAGE);
        }

        logger.infof(
                "Marking oldest credential INVALID locally for overflow: userId=%s, credentialConfigurationId=%s, mappingId=%s, tokenId=%s, countTowardLimit=%d, max=%d",
                userId, credentialConfigurationId, oldest.getId(), oldest.getTokenId(), countTowardLimit, max);

        credentialRevocationService.revokeMappingInTransaction(em, oldest);
        return oldest;
    }

    private void restoreTokenStatus(StatusListMappingEntity mapping, TokenStatus tokenStatus) {
        try {
            statusListRepository.withEntityManagerInTransaction(em -> {
                StatusListMappingEntity managed =
                        mapping.getId() == null ? null : em.find(StatusListMappingEntity.class, mapping.getId());
                if (managed == null) {
                    mapping.setTokenStatus(tokenStatus);
                    em.merge(mapping);
                    return;
                }
                managed.setTokenStatus(tokenStatus);
            });
        } catch (RuntimeException e) {
            logger.errorf(
                    e,
                    "Failed to restore token status after overflow publish failure: mappingId=%s, tokenStatus=%s",
                    mapping.getId(),
                    tokenStatus);
        }
    }

    private void freeFailedMappingLocally(
            EntityManager em,
            StatusListMappingEntity oldest,
            String userId,
            String credentialConfigurationId,
            int max,
            long countTowardLimit) {
        logger.infof(
                "Freeing FAILURE slot without status-list revoke: userId=%s, credentialConfigurationId=%s, mappingId=%s, tokenId=%s, countTowardLimit=%d, max=%d",
                userId, credentialConfigurationId, oldest.getId(), oldest.getTokenId(), countTowardLimit, max);

        oldest.setTokenStatus(TokenStatus.INVALID);
        if (!em.contains(oldest)) {
            em.merge(oldest);
        }
    }

    /**
     * Returns quota metadata for OID4VC credential types that have a configured (non-zero) limit.
     * {@code activeCount} uses the same issued-credential join as issuance: {@code SUCCESS} and
     * {@code FAILURE} mappings that still have an issued credential. In-flight {@code INIT} rows
     * are omitted.
     */
    public List<IssuedCredentialLimit> listLimits(
            RealmModel realm, String userId, Collection<String> issuedCredentialIds) {
        if (realm == null || StringUtil.isBlank(userId)) {
            return List.of();
        }

        Set<String> issuedIds = issuedCredentialIds == null
                ? Set.of()
                : issuedCredentialIds.stream()
                        .filter(StringUtil::isNotBlank)
                        .collect(Collectors.toCollection(LinkedHashSet::new));
        Map<String, Long> activeCounts = countIssuedNonRevokedByType(
                statusListRepository.findNonRevokedMappings(realm.getId(), userId), issuedIds);
        Map<String, IssuedCredentialLimit> limits = new LinkedHashMap<>();

        realm.getClientScopesStream()
                .filter(scope -> OID4VCLoginProtocolFactory.PROTOCOL_ID.equals(scope.getProtocol()))
                .map(scope -> toLimit(scope, realm, activeCounts))
                .flatMap(Optional::stream)
                // Two OID4VC client scopes can share a credentialConfigurationId. Keep the first
                // limit so the response has one entry per type instead of later scopes overwriting it.
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
        String overflowPolicy = resolveOverflowPolicy(mapper, realm);
        return Optional.of(new IssuedCredentialLimit(
                credentialConfigurationId, max, activeCount, Math.max(0L, max - activeCount), overflowPolicy));
    }

    private Set<String> issuedCredentialIds(String userId) {
        if (session == null || StringUtil.isBlank(userId)) {
            return Set.of();
        }

        UserProvider users = session.users();
        if (users == null) {
            return Set.of();
        }

        var stream = users.getIssuedVerifiableCredentialsStreamByUser(userId);
        if (stream == null) {
            return Set.of();
        }

        return stream.map(IssuedVerifiableCredentialModel::getId)
                .filter(StringUtil::isNotBlank)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private static long countIssuedNonRevoked(List<StatusListMappingEntity> mappings, Set<String> issuedCredentialIds) {
        if (mappings == null) {
            return 0L;
        }
        return mappings.stream()
                .filter(mapping -> occupiesIssuedSlot(mapping, issuedCredentialIds))
                .count();
    }

    private static Map<String, Long> countIssuedNonRevokedByType(
            List<StatusListMappingEntity> mappings, Set<String> issuedCredentialIds) {
        Map<String, Long> counts = new LinkedHashMap<>();
        if (mappings == null) {
            return counts;
        }
        for (StatusListMappingEntity mapping : mappings) {
            String type = mapping.getCredentialConfigurationId();
            if (StringUtil.isBlank(type) || !occupiesIssuedSlot(mapping, issuedCredentialIds)) {
                continue;
            }
            counts.merge(type, 1L, Long::sum);
        }
        return counts;
    }

    private static boolean occupiesIssuedSlot(StatusListMappingEntity mapping, Set<String> issuedCredentialIds) {
        String tokenId = mapping.getTokenId();
        return StringUtil.isNotBlank(tokenId) && issuedCredentialIds.contains(tokenId);
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
