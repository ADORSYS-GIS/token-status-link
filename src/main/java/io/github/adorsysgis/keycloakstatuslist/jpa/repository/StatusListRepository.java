package io.github.adorsysgis.keycloakstatuslist.jpa.repository;

import io.github.adorsysgis.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
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
import org.keycloak.models.jpa.entities.RealmEntity;
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
     * Locks the latest mapping for the realm so list-id choice, quota check, and index reservation
     * share one serialized window. When the table is empty, {@code SELECT … FOR UPDATE} would lock
     * nothing, so this takes {@code PESSIMISTIC_WRITE} on the existing Keycloak realm row and
     * re-reads. Must run inside an open transaction.
     */
    public StatusListMappingEntity lockLatestMapping(EntityManager em, String realmId) {
        StatusListMappingEntity latest = findLatestMappingForUpdate(em, realmId);
        if (latest != null) {
            return latest;
        }

        lockRealmForFirstMapping(em, realmId);
        return findLatestMappingForUpdate(em, realmId);
    }

    private StatusListMappingEntity findLatestMappingForUpdate(EntityManager em, String realmId) {
        String q = """
                SELECT m FROM StatusListMappingEntity m
                WHERE m.realmId = :realmId
                ORDER BY m.createdTimestamp DESC
                """;

        TypedQuery<StatusListMappingEntity> query = em.createQuery(q, StatusListMappingEntity.class);
        query.setParameter("realmId", realmId);
        query.setMaxResults(1);
        query.setLockMode(LockModeType.PESSIMISTIC_WRITE);

        List<StatusListMappingEntity> result = query.getResultList();
        StatusListMappingEntity latest = result.isEmpty() ? null : result.get(0);
        logger.debug(latest);
        return latest;
    }

    private void lockRealmForFirstMapping(EntityManager em, String realmId) {
        RealmEntity realm = em.find(RealmEntity.class, realmId, LockModeType.PESSIMISTIC_WRITE);
        if (realm == null) {
            throw new IllegalStateException("Cannot reserve a status-list index; realm not found: " + realmId);
        }
    }

    /**
     * Identify the next status list ID from an already-locked latest mapping. Reuse it if it has not
     * reached the maximum number of entries allowed per list, otherwise generate a new one.
     */
    public String getNextStatusListId(StatusListMappingEntity latest, int maxEntries) {
        if (latest == null || latest.getIdx() + 1 >= maxEntries) {
            logger.debugf("Running status list has reached max entries (%d), generating new list ID", maxEntries);
            return KeycloakModelUtils.generateId();
        }

        return latest.getStatusListId();
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
     * Finds mappings for Keycloak issued credential ids owned by the given user, any mapping status.
     */
    public Map<String, StatusListMappingEntity> findMappingsByTokenIds(
            String realmId, String userId, Collection<String> tokenIds) {
        AtomicReference<Map<String, StatusListMappingEntity>> result = new AtomicReference<>(Map.of());
        withEntityManagerInTransaction(em -> result.set(findMappingsByTokenIds(em, realmId, userId, tokenIds)));
        return result.get();
    }

    /**
     * Finds mappings for Keycloak issued credential ids owned by the given user, any mapping status.
     * Must run inside an open transaction.
     */
    public Map<String, StatusListMappingEntity> findMappingsByTokenIds(
            EntityManager em, String realmId, String userId, Collection<String> tokenIds) {
        List<String> normalizedTokenIds = tokenIds == null
                ? List.of()
                : tokenIds.stream().filter(StringUtil::isNotBlank).distinct().toList();
        if (normalizedTokenIds.isEmpty() || StringUtil.isBlank(userId)) {
            return Map.of();
        }

        String q = """
                    SELECT m FROM StatusListMappingEntity m
                    WHERE m.realmId = :realmId
                      AND m.userId = :userId
                      AND m.tokenId IN :tokenIds
                    ORDER BY m.createdTimestamp DESC
                """;

        TypedQuery<StatusListMappingEntity> query = em.createQuery(q, StatusListMappingEntity.class);
        query.setParameter("realmId", realmId);
        query.setParameter("userId", userId);
        query.setParameter("tokenIds", normalizedTokenIds);

        return query.getResultList().stream()
                .filter(mapping -> StringUtil.isNotBlank(mapping.getTokenId()))
                .collect(Collectors.toMap(
                        StatusListMappingEntity::getTokenId, Function.identity(), (first, ignored) -> first));
    }

    /**
     * Every mapping of the holder, any status, newest first. Quota reservation derives both occupancy
     * and in-flight {@code INIT} rows from this one read: a concurrent attempt can move its row from
     * {@code INIT} to {@code SUCCESS} without holding the reservation lock, so two separate reads
     * could miss it in both. Must run inside an open transaction, typically after
     * {@link #lockLatestMapping}.
     */
    public List<StatusListMappingEntity> findMappingsByUser(EntityManager em, String realmId, String userId) {
        if (StringUtil.isBlank(userId)) {
            return List.of();
        }

        String q = """
                    SELECT m FROM StatusListMappingEntity m
                    WHERE m.realmId = :realmId
                      AND m.userId = :userId
                    ORDER BY m.createdTimestamp DESC
                """;

        TypedQuery<StatusListMappingEntity> query = em.createQuery(q, StatusListMappingEntity.class);
        query.setParameter("realmId", realmId);
        query.setParameter("userId", userId);

        return query.getResultList();
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
