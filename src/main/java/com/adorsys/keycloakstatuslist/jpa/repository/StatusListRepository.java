package com.adorsys.keycloakstatuslist.jpa.repository;

import com.adorsys.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.TypedQuery;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.utils.KeycloakModelUtils;

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
     * Finds the successful status-list mapping for one of the supplied issued credential identifiers.
     */
    public Optional<StatusListMappingEntity> findSuccessfulMappingByTokenIds(
            String realmId, String userId, Collection<String> tokenIds) {
        if (tokenIds == null || tokenIds.isEmpty()) {
            return Optional.empty();
        }

        AtomicReference<StatusListMappingEntity> result = new AtomicReference<>();

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
            query.setParameter("tokenIds", tokenIds);
            query.setParameter("status", StatusListMappingEntity.MappingStatus.SUCCESS);
            query.setMaxResults(1);

            result.set(query.getResultStream().findFirst().orElse(null));
        });

        return Optional.ofNullable(result.get());
    }

    /**
     * Finds a successful mapping created during issuance before Keycloak had assigned/persisted the
     * issued credential id, then claims that mapping by storing the issued credential id as token_id.
     *
     * <p>The normal path is {@link #findSuccessfulMappingByTokenIds(String, String, Collection)}.
     * This method is a reconciliation path for OID4VCI issuance flows where the status-list mapper
     * runs before the {@code issued_ver_credential.id} is available.
     */
    public Optional<StatusListMappingEntity> claimUnlinkedSuccessfulMappingNearIssuedAt(
            String realmId, String userId, long issuedAt, long toleranceMillis, String tokenId) {
        if (tokenId == null || tokenId.isBlank()) {
            return Optional.empty();
        }

        long start = Math.max(0, issuedAt - toleranceMillis);
        long end = issuedAt + toleranceMillis;
        AtomicReference<StatusListMappingEntity> result = new AtomicReference<>();

        withEntityManagerInTransaction(em -> {
            String q = """
                        SELECT m FROM StatusListMappingEntity m
                        WHERE m.realmId = :realmId
                          AND m.userId = :userId
                          AND (m.tokenId IS NULL OR m.tokenId = '')
                          AND m.status = :status
                          AND m.createdTimestamp BETWEEN :start AND :end
                    """;

            TypedQuery<StatusListMappingEntity> query = em.createQuery(q, StatusListMappingEntity.class);
            query.setParameter("realmId", realmId);
            query.setParameter("userId", userId);
            query.setParameter("status", StatusListMappingEntity.MappingStatus.SUCCESS);
            query.setParameter("start", start);
            query.setParameter("end", end);
            query.setLockMode(LockModeType.PESSIMISTIC_WRITE);

            List<StatusListMappingEntity> candidates = query.getResultList();
            if (candidates.isEmpty()) {
                return;
            }

            StatusListMappingEntity nearest = candidates.stream()
                    .min(Comparator.comparingLong(mapping -> Math.abs(mapping.getCreatedTimestamp() - issuedAt)))
                    .orElse(null);
            if (nearest == null) {
                return;
            }

            if (candidates.size() > 1) {
                logger.warnf(
                        "Found %d unlinked status-list mappings for user %s near issued credential time %d. "
                                + "Claiming nearest mapping %s.",
                        candidates.size(), userId, issuedAt, nearest.getId());
            }

            nearest.setTokenId(tokenId);
            result.set(em.merge(nearest));
            em.flush();
        });

        return Optional.ofNullable(result.get());
    }
}
