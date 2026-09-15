package io.github.adorsysgis.keycloakstatuslist.jpa.repository;

import io.github.adorsysgis.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import io.github.adorsysgis.keycloakstatuslist.jpa.entity.StatusListQuotaLockEntity;
import io.github.adorsysgis.keycloakstatuslist.model.TokenStatus;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.TypedQuery;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.utils.StringUtil;

public class StatusListRepository {

    private static final Logger logger = Logger.getLogger(StatusListRepository.class);

    private final KeycloakSession session;

    public StatusListRepository(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Utility method to run a block of code with an EntityManager within a transaction.
     * This ensures that the EntityManager is properly managed and that the transaction is correctly handled.
     *
     * @param action the block of code to execute, which receives an EntityManager as a parameter
     */
    public void withEntityManagerInTransaction(Consumer<EntityManager> action) {
        KeycloakModelUtils.runJobInTransaction(session.getKeycloakSessionFactory(), s -> {
            EntityManager em = s.getProvider(JpaConnectionProvider.class).getEntityManager();
            if (em == null) {
                logger.error("EntityManager is null for JpaConnectionProvider");
                s.getTransactionManager().setRollbackOnly();
                return;
            }
            action.accept(em);
        });
    }

    /**
     * Get the next available index for the given status list ID, using a pessimistic lock to
     * prevent race conditions. Must be run within a transaction.
     */
    public Long getNextIndex(EntityManager em, String statusListId) {
        String q = """
                SELECT m FROM StatusListMappingEntity m
                WHERE m.statusListId = :listId ORDER BY m.idx DESC
                """;

        TypedQuery<StatusListMappingEntity> query = em.createQuery(q, StatusListMappingEntity.class);
        query.setParameter("listId", statusListId);
        query.setMaxResults(1);
        query.setLockMode(LockModeType.PESSIMISTIC_WRITE);

        List<StatusListMappingEntity> max = query.getResultList();
        return (max.isEmpty()) ? 0 : max.get(0).getIdx() + 1;
    }

    /**
     * Identify the next status list ID. Reuse the latest one if it has not reached the maximum number
     * of entries allowed per list, otherwise generate a new one.
     */
    public String getNextStatusListId(String realmId, int maxEntries) {
        StatusListMappingEntity latest = getLatestMapping(realmId);
        logger.debug(latest);
        if (latest == null || latest.getIdx() + 1 >= maxEntries) {
            logger.debugf("Running status list has reached max entries (%d), generating new list ID", maxEntries);
            return KeycloakModelUtils.generateId();
        }

        return latest.getStatusListId();
    }

    /**
     * Get the latest mapping recorded for the given realm.
     */
    public StatusListMappingEntity getLatestMapping(String realmId) {
        AtomicReference<StatusListMappingEntity> result = new AtomicReference<>();

        withEntityManagerInTransaction(em -> {
            String q = """
                        SELECT m FROM StatusListMappingEntity m
                        WHERE m.realmId = :realmId
                        ORDER BY m.createdTimestamp DESC
                    """;

            TypedQuery<StatusListMappingEntity> query = em.createQuery(q, StatusListMappingEntity.class);
            query.setParameter("realmId", realmId);
            query.setMaxResults(1);

            result.set(query.getResultStream().findFirst().orElse(null));
        });

        return result.get();
    }

    /**
     * Finds the successful status-list mapping for the Keycloak issued credential id stored during issuance.
     */
    public Optional<StatusListMappingEntity> findSuccessfulMappingByTokenId(
            String realmId, String userId, String tokenId) {
        if (StringUtil.isBlank(userId)) {
            return Optional.empty();
        }
        return findSuccessfulMappingByTokenIdInternal(realmId, userId, tokenId);
    }

    /**
     * Finds the successful status-list mapping for an issued credential id in the realm, regardless of holder.
     */
    public Optional<StatusListMappingEntity> findSuccessfulMappingByTokenId(String realmId, String tokenId) {
        return findSuccessfulMappingByTokenIdInternal(realmId, null, tokenId);
    }

    /**
     * Shared lookup for a successful mapping by token id. When {@code userId} is non-blank, the holder is enforced.
     */
    private Optional<StatusListMappingEntity> findSuccessfulMappingByTokenIdInternal(
            String realmId, String userId, String tokenId) {
        if (StringUtil.isBlank(tokenId)) {
            return Optional.empty();
        }

        boolean enforceUser = StringUtil.isNotBlank(userId);
        AtomicReference<StatusListMappingEntity> result = new AtomicReference<>();

        withEntityManagerInTransaction(em -> {
            String q = enforceUser ? """
                                SELECT m FROM StatusListMappingEntity m
                                WHERE m.realmId = :realmId
                                  AND m.userId = :userId
                                  AND m.tokenId = :tokenId
                                  AND m.status = :status
                                ORDER BY m.createdTimestamp DESC
                            """ : """
                                SELECT m FROM StatusListMappingEntity m
                                WHERE m.realmId = :realmId
                                  AND m.tokenId = :tokenId
                                  AND m.status = :status
                                ORDER BY m.createdTimestamp DESC
                            """;

            TypedQuery<StatusListMappingEntity> query = em.createQuery(q, StatusListMappingEntity.class);
            query.setParameter("realmId", realmId);
            if (enforceUser) {
                query.setParameter("userId", userId);
            }
            query.setParameter("tokenId", tokenId);
            query.setParameter("status", StatusListMappingEntity.MappingStatus.SUCCESS);
            query.setMaxResults(1);

            result.set(query.getResultStream().findFirst().orElse(null));
        });

        return Optional.ofNullable(result.get());
    }

    /**
     * Finds successful mappings for Keycloak issued credential ids owned by the given user.
     */
    public Map<String, StatusListMappingEntity> findSuccessfulMappingsByTokenIds(
            String realmId, String userId, Collection<String> tokenIds) {
        List<String> normalizedTokenIds = tokenIds == null
                ? List.of()
                : tokenIds.stream()
                        .filter(tokenId -> tokenId != null && !tokenId.isBlank())
                        .distinct()
                        .toList();
        if (normalizedTokenIds.isEmpty()) {
            return Map.of();
        }

        AtomicReference<List<StatusListMappingEntity>> result = new AtomicReference<>(List.of());

        withEntityManagerInTransaction(em -> {
            String q = """
                        SELECT m FROM StatusListMappingEntity m
                        WHERE m.realmId = :realmId
                          AND m.userId = :userId
                          AND m.tokenId IN :tokenIds
                          AND m.status = :status
                        ORDER BY m.createdTimestamp DESC
                    """;

            TypedQuery<StatusListMappingEntity> query = em.createQuery(q, StatusListMappingEntity.class);
            query.setParameter("realmId", realmId);
            query.setParameter("userId", userId);
            query.setParameter("tokenIds", normalizedTokenIds);
            query.setParameter("status", StatusListMappingEntity.MappingStatus.SUCCESS);

            result.set(query.getResultList());
        });

        return result.get().stream()
                .collect(Collectors.toMap(
                        StatusListMappingEntity::getTokenId, Function.identity(), (first, ignored) -> first));
    }

    private static final String SUCCESSFUL_NON_REVOKED_BASE_PREDICATE = """
            m.realmId = :realmId
              AND m.userId = :userId
              AND m.status = :status
              AND m.tokenStatus <> :invalid
            """;

    /**
     * Finds the oldest successful mapping for the holder and credential type whose token status is not
     * INVALID. Used by the {@code REVOKE_OLDEST} overflow policy.
     */
    public Optional<StatusListMappingEntity> findOldestSuccessfulNonRevokedMapping(
            String realmId, String userId, String credentialConfigurationId) {
        if (isBlank(userId) || isBlank(credentialConfigurationId)) {
            return Optional.empty();
        }

        AtomicReference<StatusListMappingEntity> result = new AtomicReference<>();

        withEntityManagerInTransaction(em -> {
            String q = """
                        SELECT m FROM StatusListMappingEntity m
                        WHERE m.realmId = :realmId
                          AND m.userId = :userId
                          AND m.credentialConfigurationId = :credentialConfigurationId
                          AND m.status = :status
                          AND m.tokenStatus <> :invalid
                        ORDER BY m.createdTimestamp ASC
                    """;

            TypedQuery<StatusListMappingEntity> query = em.createQuery(q, StatusListMappingEntity.class);
            query.setParameter("realmId", realmId);
            query.setParameter("userId", userId);
            query.setParameter("credentialConfigurationId", credentialConfigurationId);
            query.setParameter("status", StatusListMappingEntity.MappingStatus.SUCCESS);
            query.setParameter("invalid", TokenStatus.INVALID);
            query.setMaxResults(1);

            result.set(query.getResultStream().findFirst().orElse(null));
        });

        return Optional.ofNullable(result.get());
    }

    /**
     * Counts successful mappings for the holder and credential type whose token status is not INVALID.
     */
    public long countSuccessfulNonRevokedMappings(String realmId, String userId, String credentialConfigurationId) {
        if (isBlank(userId) || isBlank(credentialConfigurationId)) {
            return 0L;
        }

        AtomicReference<Long> result = new AtomicReference<>(0L);

        withEntityManagerInTransaction(em -> {
            result.set(countSuccessfulNonRevokedMappings(em, realmId, userId, credentialConfigurationId));
        });

        return result.get();
    }

    /**
     * Counts successful non-revoked mappings. Must run inside an open transaction.
     */
    public long countSuccessfulNonRevokedMappings(
            EntityManager em, String realmId, String userId, String credentialConfigurationId) {
        String q = """
                    SELECT COUNT(m) FROM StatusListMappingEntity m
                    WHERE %s
                      AND m.credentialConfigurationId = :credentialConfigurationId
                """.formatted(SUCCESSFUL_NON_REVOKED_BASE_PREDICATE);

        TypedQuery<Long> query = em.createQuery(q, Long.class);
        bindSuccessfulNonRevokedParams(query, realmId, userId);
        query.setParameter("credentialConfigurationId", credentialConfigurationId);

        return query.getSingleResult();
    }

    /**
     * Counts mappings that currently occupy a quota slot ({@code INIT} or {@code SUCCESS}, not
     * {@code INVALID}). Must run inside an open transaction, typically after {@link #acquireQuotaLock}.
     */
    public long countOccupyingMappings(
            EntityManager em, String realmId, String userId, String credentialConfigurationId) {
        String q = """
                    SELECT COUNT(m) FROM StatusListMappingEntity m
                    WHERE m.realmId = :realmId
                      AND m.userId = :userId
                      AND m.credentialConfigurationId = :credentialConfigurationId
                      AND m.status IN :statuses
                      AND m.tokenStatus <> :invalid
                """;

        TypedQuery<Long> query = em.createQuery(q, Long.class);
        query.setParameter("realmId", realmId);
        query.setParameter("userId", userId);
        query.setParameter("credentialConfigurationId", credentialConfigurationId);
        query.setParameter(
                "statuses",
                List.of(StatusListMappingEntity.MappingStatus.INIT, StatusListMappingEntity.MappingStatus.SUCCESS));
        query.setParameter("invalid", TokenStatus.INVALID);

        return query.getSingleResult();
    }

    /**
     * Ensures a quota-lock row exists for the holder and credential type. Safe to call concurrently;
     * insert races are ignored. Run before {@link #acquireQuotaLock}.
     */
    public void ensureQuotaLockExists(String realmId, String userId, String credentialConfigurationId) {
        StatusListQuotaLockEntity.QuotaLockId id =
                new StatusListQuotaLockEntity.QuotaLockId(realmId, userId, credentialConfigurationId);
        if (quotaLockExists(id)) {
            return;
        }

        try {
            withEntityManagerInTransaction(
                    em -> em.persist(new StatusListQuotaLockEntity(realmId, userId, credentialConfigurationId)));
        } catch (RuntimeException e) {
            if (quotaLockExists(id)) {
                logger.debugf(
                        e,
                        "Quota lock already exists for realmId=%s userId=%s credentialConfigurationId=%s",
                        realmId,
                        userId,
                        credentialConfigurationId);
                return;
            }
            throw e;
        }
    }

    private boolean quotaLockExists(StatusListQuotaLockEntity.QuotaLockId id) {
        AtomicReference<Boolean> exists = new AtomicReference<>(false);
        withEntityManagerInTransaction(em -> exists.set(em.find(StatusListQuotaLockEntity.class, id) != null));
        return Boolean.TRUE.equals(exists.get());
    }

    /**
     * Serializes quota check + reservation for one holder and credential type by locking the dedicated
     * row. Call {@link #ensureQuotaLockExists} first. Must run inside an open transaction.
     */
    public void acquireQuotaLock(EntityManager em, String realmId, String userId, String credentialConfigurationId) {
        StatusListQuotaLockEntity.QuotaLockId id =
                new StatusListQuotaLockEntity.QuotaLockId(realmId, userId, credentialConfigurationId);
        StatusListQuotaLockEntity lock = em.find(StatusListQuotaLockEntity.class, id, LockModeType.PESSIMISTIC_WRITE);
        if (lock == null) {
            throw new IllegalStateException(
                    "Quota lock row missing for " + realmId + "/" + userId + "/" + credentialConfigurationId);
        }
    }

    /**
     * Counts successful non-revoked mappings for the holder, grouped by credential type.
     * Rows without a credential type are omitted.
     */
    public Map<String, Long> countSuccessfulNonRevokedMappingsByType(String realmId, String userId) {
        if (isBlank(userId)) {
            return Map.of();
        }

        AtomicReference<List<Object[]>> result = new AtomicReference<>(List.of());

        withEntityManagerInTransaction(em -> {
            String q = """
                        SELECT m.credentialConfigurationId, COUNT(m)
                        FROM StatusListMappingEntity m
                        WHERE %s
                          AND m.credentialConfigurationId IS NOT NULL
                        GROUP BY m.credentialConfigurationId
                    """.formatted(SUCCESSFUL_NON_REVOKED_BASE_PREDICATE);

            TypedQuery<Object[]> query = em.createQuery(q, Object[].class);
            bindSuccessfulNonRevokedParams(query, realmId, userId);

            result.set(query.getResultList());
        });

        return result.get().stream()
                .filter(row -> row[0] instanceof String type && !type.isBlank())
                .collect(Collectors.toMap(row -> (String) row[0], row -> (Long) row[1], Long::sum));
    }

    private static void bindSuccessfulNonRevokedParams(TypedQuery<?> query, String realmId, String userId) {
        query.setParameter("realmId", realmId);
        query.setParameter("userId", userId);
        query.setParameter("status", StatusListMappingEntity.MappingStatus.SUCCESS);
        query.setParameter("invalid", TokenStatus.INVALID);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    /**
     * Persists changes to a status-list mapping entity.
     */
    public StatusListMappingEntity save(StatusListMappingEntity mapping) {
        if (mapping == null) {
            throw new IllegalArgumentException("mapping is required");
        }

        AtomicReference<StatusListMappingEntity> result = new AtomicReference<>();
        withEntityManagerInTransaction(em -> {
            result.set(em.merge(mapping));
        });

        return result.get();
    }
}
