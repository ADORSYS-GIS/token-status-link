package io.github.adorsysgis.keycloakstatuslist.jpa.repository;

import io.github.adorsysgis.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
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

    /**
     * Counts successful mappings for the holder and credential type whose token status is not INVALID.
     * Historical rows without a credential type are excluded because they cannot match the type filter.
     */
    public long countSuccessfulNonRevokedMappings(String realmId, String userId, String credentialConfigurationId) {
        if (isBlank(userId) || isBlank(credentialConfigurationId)) {
            return 0L;
        }

        AtomicReference<Long> result = new AtomicReference<>(0L);

        withEntityManagerInTransaction(em -> {
            String q = """
                        SELECT COUNT(m) FROM StatusListMappingEntity m
                        WHERE m.realmId = :realmId
                          AND m.userId = :userId
                          AND m.credentialConfigurationId = :credentialConfigurationId
                          AND m.status = :status
                          AND m.tokenStatus <> :invalid
                    """;

            TypedQuery<Long> query = em.createQuery(q, Long.class);
            query.setParameter("realmId", realmId);
            query.setParameter("userId", userId);
            query.setParameter("credentialConfigurationId", credentialConfigurationId);
            query.setParameter("status", StatusListMappingEntity.MappingStatus.SUCCESS);
            query.setParameter("invalid", TokenStatus.INVALID);

            result.set(query.getSingleResult());
        });

        return result.get();
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
                        WHERE m.realmId = :realmId
                          AND m.userId = :userId
                          AND m.credentialConfigurationId IS NOT NULL
                          AND m.status = :status
                          AND m.tokenStatus <> :invalid
                        GROUP BY m.credentialConfigurationId
                    """;

            TypedQuery<Object[]> query = em.createQuery(q, Object[].class);
            query.setParameter("realmId", realmId);
            query.setParameter("userId", userId);
            query.setParameter("status", StatusListMappingEntity.MappingStatus.SUCCESS);
            query.setParameter("invalid", TokenStatus.INVALID);

            result.set(query.getResultList());
        });

        return result.get().stream()
                .filter(row -> row[0] instanceof String type && !type.isBlank())
                .collect(Collectors.toMap(row -> (String) row[0], row -> (Long) row[1], Long::sum));
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
