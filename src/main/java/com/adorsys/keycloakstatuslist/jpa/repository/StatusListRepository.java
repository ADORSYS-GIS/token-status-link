package com.adorsys.keycloakstatuslist.jpa.repository;

import com.adorsys.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import com.adorsys.keycloakstatuslist.model.CredentialStatusFilter;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.TypedQuery;
import java.util.Collections;
import java.util.List;
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
     * Finds a status list mapping by its primary key ID.
     *
     * @param id the entity's primary key
     * @return the entity, or null if not found
     */
    public StatusListMappingEntity findById(String id) {
        AtomicReference<StatusListMappingEntity> result = new AtomicReference<>();

        withEntityManagerInTransaction(em -> {
            result.set(em.find(StatusListMappingEntity.class, id));
        });

        return result.get();
    }

    /**
     * Merges the given entity into the persistence context within a transaction.
     *
     * @param entity the entity to update
     */
    public void updateMapping(StatusListMappingEntity entity) {
        withEntityManagerInTransaction(em -> em.merge(entity));
    }

    /**
     * Returns a paginated list of status list mappings for the given realm, ordered by creation time descending.
     *
     * @param realmId the realm identifier
     * @param filter  optional filter criteria
     * @param offset  zero-based offset for pagination
     * @param limit   maximum number of results to return
     * @return list of matching entities, or empty list if none found
     */
    public List<StatusListMappingEntity> getMappings(
            String realmId, CredentialStatusFilter filter, int offset, int limit) {
        AtomicReference<List<StatusListMappingEntity>> result = new AtomicReference<>(Collections.emptyList());

        withEntityManagerInTransaction(em -> {
            StringBuilder jpql = new StringBuilder(
                    "SELECT m FROM StatusListMappingEntity m WHERE m.realmId = :realmId");
            appendFilterClauses(jpql, filter);
            jpql.append(" ORDER BY m.createdTimestamp DESC");

            TypedQuery<StatusListMappingEntity> query = em.createQuery(jpql.toString(), StatusListMappingEntity.class);
            query.setParameter("realmId", realmId);
            setFilterParameters(query, filter);
            query.setFirstResult(offset);
            query.setMaxResults(limit);

            result.set(query.getResultList());
        });

        return result.get();
    }

    /**
     * Returns the total number of status list mappings for the given realm matching the filter.
     *
     * @param realmId the realm identifier
     * @param filter  optional filter criteria
     * @return total count of matching mappings
     */
    public long countMappings(String realmId, CredentialStatusFilter filter) {
        AtomicReference<Long> result = new AtomicReference<>(0L);

        withEntityManagerInTransaction(em -> {
            StringBuilder jpql = new StringBuilder(
                    "SELECT COUNT(m) FROM StatusListMappingEntity m WHERE m.realmId = :realmId");
            appendFilterClauses(jpql, filter);

            TypedQuery<Long> query = em.createQuery(jpql.toString(), Long.class);
            query.setParameter("realmId", realmId);
            setFilterParameters(query, filter);

            result.set(query.getSingleResult());
        });

        return result.get();
    }

    private static void appendFilterClauses(StringBuilder jpql, CredentialStatusFilter filter) {
        if (filter == null) {
            return;
        }
        if (filter.userId() != null) {
            jpql.append(" AND m.userId = :userId");
        }
        if (filter.tokenStatus() != null) {
            jpql.append(" AND m.tokenStatus = :tokenStatus");
        }
        if (filter.claims() != null) {
            for (int i = 0; i < filter.claims().size(); i++) {
                jpql.append(" AND m.metadata LIKE :claim").append(i);
            }
        }
    }

    private static <T> void setFilterParameters(TypedQuery<T> query, CredentialStatusFilter filter) {
        if (filter == null) {
            return;
        }
        if (filter.userId() != null) {
            query.setParameter("userId", filter.userId());
        }
        if (filter.tokenStatus() != null) {
            query.setParameter("tokenStatus", filter.tokenStatus());
        }
        if (filter.claims() != null) {
            for (int i = 0; i < filter.claims().size(); i++) {
                query.setParameter("claim" + i, "%" + filter.claims().get(i) + "%");
            }
        }
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
}
