package io.github.adorsysgis.keycloakstatuslist.service;

import static io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER;

import io.github.adorsysgis.keycloakstatuslist.StatusListProtocolMapper;
import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import io.github.adorsysgis.keycloakstatuslist.exception.CredentialIssuanceQuotaException;
import io.github.adorsysgis.keycloakstatuslist.exception.StatusListException;
import io.github.adorsysgis.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import io.github.adorsysgis.keycloakstatuslist.jpa.entity.StatusListMappingEntity.MappingStatus;
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
import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.IssuedVerifiableCredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.UserVerifiableCredentialModel;
import org.keycloak.models.oid4vci.CredentialScopeModel;
import org.keycloak.protocol.oid4vc.OID4VCLoginProtocolFactory;
import org.keycloak.utils.StringUtil;

/**
 * Enforces and reports the maximum number of occupying credentials per holder and credential type.
 * Occupancy is issued credentials with no mapping or a {@code SUCCESS}/{@code FAILURE} mapping that
 * is not {@code INVALID}; {@code INIT} mappings are omitted. Reservation also adds recent
 * in-flight {@code INIT} rows so parallel issuance cannot overshoot {@code max}.
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
    static final long MIN_IN_FLIGHT_INIT_WINDOW_MS = 60_000L;

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
     * An issued credential occupies a quota slot when it has no mapping, or a {@code SUCCESS} /
     * {@code FAILURE} mapping that is not {@code INVALID}. {@code INIT} mappings and legacy mappings
     * without a credential type are omitted.
     */
    public static boolean occupiesQuota(StatusListMappingEntity mapping) {
        if (mapping == null) {
            return true;
        }
        if (StringUtil.isBlank(mapping.getCredentialConfigurationId())) {
            return false;
        }
        if (mapping.getStatus() == MappingStatus.INIT) {
            return false;
        }
        if (mapping.getTokenStatus() == TokenStatus.INVALID) {
            return false;
        }
        return mapping.getStatus() == MappingStatus.SUCCESS || mapping.getStatus() == MappingStatus.FAILURE;
    }

    /**
     * Rejects issuance when occupying credentials plus concurrent in-flight {@code INIT} rows
     * already meet {@code max}. An {@code INIT} row is in flight while it is younger than
     * {@link #inFlightInitWindowMs}; older ones are leftovers and are omitted, matching displayed
     * {@code activeCount}. In-flight {@code INIT} is counted only so parallel reservation cannot
     * overshoot.
     *
     * <p>{@code currentTokenId} is excluded so this request cannot fill the slot against itself.
     * Unmapped issued credentials occupy only when they predate this issuance ({@code issuedAt}), so
     * a leftover from a finished attempt still blocks while a concurrent Keycloak row does not
     * deadlock both requests. Displayed {@code activeCount} still counts every unmapped leftover.
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
            String overflowPolicy,
            String currentTokenId) {
        if (max <= 0) {
            return null;
        }
        requireHolderAndTypeWhenLimited(userId, credentialConfigurationId, max);

        List<IssuedVerifiableCredentialModel> issued = loadIssuedCredentials(userId);
        List<StatusListMappingEntity> holderMappings = statusListRepository.findMappingsByUser(em, realmId, userId);
        RealmModel realm = currentRealm();
        long activeCount = countOccupying(
                issued, latestByTokenId(holderMappings), credentialConfigurationId, realm, currentTokenId);
        long inFlightSince = Time.currentTimeMillis() - inFlightInitWindowMs(realm);
        long inFlight = countInFlight(holderMappings, credentialConfigurationId, currentTokenId, inFlightSince);
        long countTowardLimit = activeCount + inFlight;
        if (countTowardLimit < max) {
            return null;
        }

        String policy = StatusListConfig.parseOverflowPolicy(overflowPolicy);
        if (OVERFLOW_POLICY_REVOKE_OLDEST.equals(policy)) {
            return freeOldestOccupyingSlot(
                    em,
                    realmId,
                    userId,
                    credentialConfigurationId,
                    max,
                    countTowardLimit,
                    inFlight,
                    currentTokenId,
                    issued,
                    holderMappings,
                    realm);
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
     * Unmapped leftovers occupy quota but cannot be freed here (no status-list mapping to revoke).
     * When the limit is held only by such leftovers (no in-flight {@code INIT}), allow issuance so
     * {@code REVOKE_OLDEST} cannot get stuck after a fail-closed overflow attempt.
     *
     * @return {@code SUCCESS} mapping awaiting remote publish, or {@code null} when only a local free
     *     was required / when unmapped leftovers alone remain
     */
    private StatusListMappingEntity freeOldestOccupyingSlot(
            EntityManager em,
            String realmId,
            String userId,
            String credentialConfigurationId,
            int max,
            long countTowardLimit,
            long inFlight,
            String currentTokenId,
            List<IssuedVerifiableCredentialModel> issued,
            List<StatusListMappingEntity> holderMappings,
            RealmModel realm) {
        Map<String, StatusListMappingEntity> byTokenId = latestByTokenId(holderMappings);
        List<StatusListMappingEntity> occupying = new ArrayList<>();
        for (IssuedVerifiableCredentialModel credential : issued) {
            if (credential == null || StringUtil.isBlank(credential.getId())) {
                continue;
            }
            if (credential.getId().equals(currentTokenId)) {
                continue;
            }
            StatusListMappingEntity mapping = byTokenId.get(credential.getId());
            if (mapping == null) {
                continue;
            }
            if (!credentialConfigurationId.equals(credentialTypeOf(credential, mapping, realm))) {
                continue;
            }
            if (occupiesQuota(mapping)) {
                occupying.add(mapping);
            }
        }

        StatusListMappingEntity oldestSuccess = occupying.stream()
                .filter(mapping -> mapping.getStatus() == MappingStatus.SUCCESS)
                .min(OLDEST_OCCUPYING_MAPPING)
                .orElse(null);
        if (oldestSuccess != null) {
            return markSuccessfulMappingInvalidLocally(
                    em, oldestSuccess, userId, credentialConfigurationId, max, countTowardLimit);
        }

        StatusListMappingEntity oldestFailure = occupying.stream()
                .filter(mapping -> mapping.getStatus() == MappingStatus.FAILURE)
                .min(OLDEST_OCCUPYING_MAPPING)
                .orElse(null);
        if (oldestFailure != null) {
            // FAILURE still occupies quota (Keycloak issued the credential; status publish may never
            // have reached the server), so free it locally without a status-list call.
            freeFailedMappingLocally(em, oldestFailure, userId, credentialConfigurationId, max, countTowardLimit);
            return null;
        }

        if (inFlight > 0) {
            logger.warnf(
                    "No oldest mapping found to revoke despite countTowardLimit=%d (inFlight=%d): userId=%s, credentialConfigurationId=%s, realmId=%s",
                    countTowardLimit, inFlight, userId, credentialConfigurationId, realmId);
            throw CredentialIssuanceQuotaException.limitReached(LIMIT_REACHED_MESSAGE);
        }

        // Unmapped leftovers occupy quota but cannot be revoked through the status list. Allow this
        // issuance rather than fail-closed permanently under REVOKE_OLDEST (listing may already show
        // activeCount above max when leftovers remain).
        logger.infof(
                "No revocable mapping under REVOKE_OLDEST; allowing issuance despite unmapped leftovers: userId=%s, credentialConfigurationId=%s, countTowardLimit=%d, max=%d",
                userId, credentialConfigurationId, countTowardLimit, max);
        return null;
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
     * {@code activeCount} is issued credentials of that type with no mapping or a {@code SUCCESS} /
     * {@code FAILURE} mapping that is not {@code INVALID}. Leftover {@code INIT} mappings are omitted.
     */
    public List<IssuedCredentialLimit> listLimits(
            RealmModel realm, String userId, Collection<IssuedVerifiableCredentialModel> issuedCredentials) {
        if (realm == null || StringUtil.isBlank(userId)) {
            return List.of();
        }

        List<IssuedVerifiableCredentialModel> issued = issuedCredentials == null
                ? List.of()
                : issuedCredentials.stream()
                        .filter(credential -> credential != null && StringUtil.isNotBlank(credential.getId()))
                        .toList();
        Map<String, StatusListMappingEntity> mappings =
                statusListRepository.findMappingsByTokenIds(realm.getId(), userId, idsOf(issued));
        Map<String, Long> activeCounts = countOccupyingByType(issued, mappings, realm);
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

    private List<IssuedVerifiableCredentialModel> loadIssuedCredentials(String userId) {
        if (session == null || StringUtil.isBlank(userId)) {
            return List.of();
        }

        UserProvider users = session.users();
        if (users == null) {
            return List.of();
        }

        var stream = users.getIssuedVerifiableCredentialsStreamByUser(userId);
        if (stream == null) {
            return List.of();
        }

        return stream.filter(credential -> credential != null && StringUtil.isNotBlank(credential.getId()))
                .toList();
    }

    private static Set<String> idsOf(Collection<IssuedVerifiableCredentialModel> issuedCredentials) {
        Set<String> ids = new LinkedHashSet<>();
        if (issuedCredentials == null) {
            return ids;
        }
        for (IssuedVerifiableCredentialModel credential : issuedCredentials) {
            if (credential != null && StringUtil.isNotBlank(credential.getId())) {
                ids.add(credential.getId());
            }
        }
        return ids;
    }

    private long countOccupying(
            Collection<IssuedVerifiableCredentialModel> issuedCredentials,
            Map<String, StatusListMappingEntity> mappings,
            String credentialConfigurationId,
            RealmModel realm,
            String currentTokenId) {
        if (issuedCredentials == null || StringUtil.isBlank(credentialConfigurationId)) {
            return 0L;
        }
        IssuedVerifiableCredentialModel current = findIssued(issuedCredentials, currentTokenId);
        long count = 0L;
        for (IssuedVerifiableCredentialModel credential : issuedCredentials) {
            if (credential == null || StringUtil.isBlank(credential.getId())) {
                continue;
            }
            if (credential.getId().equals(currentTokenId)) {
                continue;
            }
            StatusListMappingEntity mapping = mappingOf(mappings, credential.getId());
            if (!credentialConfigurationId.equals(credentialTypeOf(credential, mapping, realm))) {
                continue;
            }
            if (occupiesQuota(mapping) && (mapping != null || isPriorLeftover(credential, current))) {
                count++;
            }
        }
        return count;
    }

    private Map<String, Long> countOccupyingByType(
            Collection<IssuedVerifiableCredentialModel> issuedCredentials,
            Map<String, StatusListMappingEntity> mappings,
            RealmModel realm) {
        Map<String, Long> counts = new LinkedHashMap<>();
        if (issuedCredentials == null) {
            return counts;
        }
        for (IssuedVerifiableCredentialModel credential : issuedCredentials) {
            if (credential == null || StringUtil.isBlank(credential.getId())) {
                continue;
            }
            StatusListMappingEntity mapping = mappingOf(mappings, credential.getId());
            String type = credentialTypeOf(credential, mapping, realm);
            if (StringUtil.isBlank(type) || !occupiesQuota(mapping)) {
                continue;
            }
            counts.merge(type, 1L, Long::sum);
        }
        return counts;
    }

    private static Map<String, StatusListMappingEntity> latestByTokenId(List<StatusListMappingEntity> newestFirst) {
        Map<String, StatusListMappingEntity> byTokenId = new LinkedHashMap<>();
        for (StatusListMappingEntity mapping : newestFirst) {
            if (StringUtil.isNotBlank(mapping.getTokenId())) {
                byTokenId.putIfAbsent(mapping.getTokenId(), mapping);
            }
        }
        return byTokenId;
    }

    private static long countInFlight(
            List<StatusListMappingEntity> mappings,
            String credentialConfigurationId,
            String currentTokenId,
            long createdSince) {
        return mappings.stream()
                .filter(mapping -> mapping.getStatus() == MappingStatus.INIT)
                .filter(mapping -> mapping.getTokenStatus() != TokenStatus.INVALID)
                .filter(mapping -> credentialConfigurationId.equals(mapping.getCredentialConfigurationId()))
                .filter(mapping -> currentTokenId == null || !currentTokenId.equals(mapping.getTokenId()))
                .filter(mapping ->
                        mapping.getCreatedTimestamp() != null && mapping.getCreatedTimestamp() >= createdSince)
                .count();
    }

    private static StatusListMappingEntity mappingOf(Map<String, StatusListMappingEntity> mappings, String tokenId) {
        return mappings == null ? null : mappings.get(tokenId);
    }

    private static IssuedVerifiableCredentialModel findIssued(
            Collection<IssuedVerifiableCredentialModel> issuedCredentials, String tokenId) {
        if (issuedCredentials == null || StringUtil.isBlank(tokenId)) {
            return null;
        }
        for (IssuedVerifiableCredentialModel credential : issuedCredentials) {
            if (credential != null && tokenId.equals(credential.getId())) {
                return credential;
            }
        }
        return null;
    }

    /**
     * How long an {@code INIT} mapping is treated as a concurrent in-flight reservation. One attempt
     * spans reservation, the status-list publish call (bounded by the issuance timeout), and the
     * completion write, so the window is a multiple of that timeout with a floor for no-timeout setups.
     */
    static long inFlightInitWindowMs(RealmModel realm) {
        int issuanceTimeout = realm == null ? 0 : new StatusListConfig(realm).getIssuanceTimeout();
        return Math.max(MIN_IN_FLIGHT_INIT_WINDOW_MS, 3L * issuanceTimeout);
    }

    /**
     * A leftover from an earlier finished attempt has an earlier {@code issuedAt} than the
     * credential being issued. Concurrent Keycloak rows created for the same wave are not older.
     */
    private static boolean isPriorLeftover(
            IssuedVerifiableCredentialModel leftover, IssuedVerifiableCredentialModel current) {
        if (current == null) {
            return true;
        }
        Long leftoverIssuedAt = leftover.getIssuedAt();
        Long currentIssuedAt = current.getIssuedAt();
        return leftoverIssuedAt != null && currentIssuedAt != null && leftoverIssuedAt < currentIssuedAt;
    }

    private String credentialTypeOf(
            IssuedVerifiableCredentialModel credential, StatusListMappingEntity mapping, RealmModel realm) {
        if (mapping != null) {
            return mapping.getCredentialConfigurationId();
        }
        return resolveCredentialConfigurationId(credential, realm);
    }

    private String resolveCredentialConfigurationId(IssuedVerifiableCredentialModel credential, RealmModel realm) {
        if (credential == null || realm == null || session == null) {
            return null;
        }

        String verifiableCredentialId = credential.getVerifiableCredentialId();
        if (StringUtil.isBlank(verifiableCredentialId)) {
            return null;
        }

        UserProvider users = session.users();
        if (users == null) {
            return null;
        }

        UserVerifiableCredentialModel verifiableCredential = users.getVerifiableCredentialById(verifiableCredentialId);
        if (verifiableCredential == null || StringUtil.isBlank(verifiableCredential.getClientScopeId())) {
            return null;
        }

        ClientScopeModel scope = realm.getClientScopeById(verifiableCredential.getClientScopeId());
        if (scope == null || !OID4VCLoginProtocolFactory.PROTOCOL_ID.equals(scope.getProtocol())) {
            return null;
        }

        String credentialConfigurationId = new CredentialScopeModel(scope).getCredentialConfigurationId();
        return StringUtil.isBlank(credentialConfigurationId) ? null : credentialConfigurationId;
    }

    private RealmModel currentRealm() {
        if (session == null || session.getContext() == null) {
            return null;
        }
        return session.getContext().getRealm();
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
