package io.github.adorsysgis.keycloakstatuslist.jpa.repository;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import io.github.adorsysgis.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.TypedQuery;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.jpa.entities.RealmEntity;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for {@link StatusListRepository} index reservation and locking.
 */
@ExtendWith(MockitoExtension.class)
class StatusListRepositoryTest {

    private static final String TEST_REALM_ID = "test-realm-id";
    private static final String TEST_LIST_ID = "list-1";

    @Mock
    private KeycloakSession session;

    @Mock
    private EntityManager em;

    @Mock
    private TypedQuery<StatusListMappingEntity> query;

    private StatusListRepository repository;

    @BeforeEach
    void setUp() {
        repository = new StatusListRepository(session);
    }

    @Test
    void getNextIndexShouldReserveFirstSlotWhenListIsEmpty() {
        when(em.createQuery(anyString(), eq(StatusListMappingEntity.class))).thenReturn(query);
        when(query.getResultList()).thenReturn(List.of());

        Long next = repository.getNextIndex(em, TEST_LIST_ID);

        assertEquals(0L, next, "first index of an empty list should be 0");
        verify(query).setParameter("listId", TEST_LIST_ID);
        verify(query).setLockMode(LockModeType.PESSIMISTIC_WRITE);
    }

    @Test
    void getNextIndexShouldReserveLatestPlusOne() {
        StatusListMappingEntity latest = new StatusListMappingEntity();
        latest.setStatusListId(TEST_LIST_ID);
        latest.setIdx(7L);
        when(em.createQuery(anyString(), eq(StatusListMappingEntity.class))).thenReturn(query);
        when(query.getResultList()).thenReturn(List.of(latest));

        Long next = repository.getNextIndex(em, TEST_LIST_ID);

        assertEquals(8L, next, "next index should follow the latest");
    }

    @Test
    void getNextStatusListIdShouldReuseRunningListBelowMaxEntries() {
        StatusListMappingEntity latest = new StatusListMappingEntity();
        latest.setStatusListId(TEST_LIST_ID);
        latest.setIdx(5L);

        String next = repository.getNextStatusListId(latest, StatusListConfig.DEFAULT_MAX_ENTRIES);

        assertEquals(TEST_LIST_ID, next, "list below max entries should be reused");
    }

    @Test
    void getNextStatusListIdShouldRollOverToNewListAtMaxEntries() {
        StatusListMappingEntity latest = new StatusListMappingEntity();
        latest.setStatusListId(TEST_LIST_ID);
        latest.setIdx((long) StatusListConfig.DEFAULT_MAX_ENTRIES - 1);

        String next = repository.getNextStatusListId(latest, StatusListConfig.DEFAULT_MAX_ENTRIES);

        assertNotEquals(TEST_LIST_ID, next, "full list should roll over to a new id");
        assertFalse(next.isBlank(), "new list id should not be blank");
    }

    @Test
    void getNextStatusListIdShouldGenerateNewIdWhenNoMappingExistsYet() {
        String next = repository.getNextStatusListId(null, StatusListConfig.DEFAULT_MAX_ENTRIES);

        assertNotNull(next);
        assertFalse(next.isBlank(), "fresh list id should be generated");
    }

    @Test
    void lockLatestMappingShouldReturnExistingMappingWithoutRealmLock() {
        StatusListMappingEntity latest = new StatusListMappingEntity();
        latest.setStatusListId(TEST_LIST_ID);
        latest.setIdx(3L);
        when(em.createQuery(anyString(), eq(StatusListMappingEntity.class))).thenReturn(query);
        when(query.getResultList()).thenReturn(List.of(latest));

        StatusListMappingEntity result = repository.lockLatestMapping(em, TEST_REALM_ID);

        assertSame(latest, result, "should return the existing latest mapping");
        verify(em, never()).find(eq(RealmEntity.class), eq(TEST_REALM_ID), eq(LockModeType.PESSIMISTIC_WRITE));
    }

    @Test
    void lockLatestMappingShouldLockRealmWhenTableIsEmpty() {
        StatusListMappingEntity first = new StatusListMappingEntity();
        first.setStatusListId(TEST_LIST_ID);
        first.setIdx(0L);
        when(em.createQuery(anyString(), eq(StatusListMappingEntity.class))).thenReturn(query);
        // Empty first, then a mapping once the realm row is locked.
        when(query.getResultList()).thenReturn(List.of(), List.of(first));
        when(em.find(eq(RealmEntity.class), eq(TEST_REALM_ID), eq(LockModeType.PESSIMISTIC_WRITE)))
                .thenReturn(mock(RealmEntity.class));

        StatusListMappingEntity result = repository.lockLatestMapping(em, TEST_REALM_ID);

        assertSame(first, result, "should return the mapping after locking the realm");
        verify(em).find(eq(RealmEntity.class), eq(TEST_REALM_ID), eq(LockModeType.PESSIMISTIC_WRITE));
    }
}
