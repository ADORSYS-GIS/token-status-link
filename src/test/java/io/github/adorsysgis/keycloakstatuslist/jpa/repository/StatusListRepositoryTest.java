package io.github.adorsysgis.keycloakstatuslist.jpa.repository;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
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
    void bookNextIndexShouldFollowLockedMappingWhenListHasRoom() {
        StatusListMappingEntity latest = mapping("latest", TEST_LIST_ID, 5L);
        StatusListMappingEntity reservation = new StatusListMappingEntity();

        repository.bookNextIndex(reservation, latest, StatusListConfig.DEFAULT_MAX_ENTRIES);

        assertEquals(TEST_LIST_ID, reservation.getStatusListId(), "list with room should be reused");
        assertEquals(6L, reservation.getIdx(), "next index comes from the locked mapping");
    }

    @Test
    void lockLatestMappingShouldReturnExistingMapping() {
        StatusListMappingEntity latest = mapping("latest", TEST_LIST_ID, 3L);
        when(em.createQuery(anyString(), eq(StatusListMappingEntity.class))).thenReturn(query);
        when(query.getResultList()).thenReturn(List.of(latest));

        StatusListMappingEntity result = repository.lockLatestMapping(em, TEST_REALM_ID);

        assertSame(latest, result, "should return the existing latest mapping");
    }

    @Test
    void lockLatestMappingShouldLockRealmWhenTableIsEmpty() {
        StatusListMappingEntity first = mapping("first", TEST_LIST_ID, 0L);
        when(em.createQuery(anyString(), eq(StatusListMappingEntity.class))).thenReturn(query);
        when(query.getResultList()).thenReturn(List.of()).thenReturn(List.of(first));
        when(em.find(eq(RealmEntity.class), eq(TEST_REALM_ID), eq(LockModeType.PESSIMISTIC_WRITE)))
                .thenReturn(mock(RealmEntity.class));

        StatusListMappingEntity result = repository.lockLatestMapping(em, TEST_REALM_ID);

        assertSame(first, result, "should return the mapping after locking the realm");
        verify(em).find(eq(RealmEntity.class), eq(TEST_REALM_ID), eq(LockModeType.PESSIMISTIC_WRITE));
    }

    @Test
    void bookNextIndexShouldOpenNewListWhenLockedMappingIsFull() {
        StatusListMappingEntity lastSlot = mapping("last-slot", TEST_LIST_ID, 2L);
        StatusListMappingEntity reservation = new StatusListMappingEntity();

        repository.bookNextIndex(reservation, lastSlot, 3);

        assertEquals(0L, reservation.getIdx(), "a new list starts at index 0");
        assertNotEquals(TEST_LIST_ID, reservation.getStatusListId(), "a full list must not be extended");
        assertFalse(reservation.getStatusListId().isBlank());
    }

    @Test
    void bookNextIndexShouldOpenNewListWhenNoMappingExistsYet() {
        StatusListMappingEntity reservation = new StatusListMappingEntity();

        repository.bookNextIndex(reservation, null, StatusListConfig.DEFAULT_MAX_ENTRIES);

        assertEquals(0L, reservation.getIdx(), "the first list starts at index 0");
        assertNotNull(reservation.getStatusListId());
        assertFalse(reservation.getStatusListId().isBlank(), "fresh list id should be generated");
    }

    @Test
    void bookNextIndexShouldReuseListOpenedByConcurrentRollover() {
        StatusListMappingEntity concurrentNewList = mapping("new-list-tip", "list-2", 0L);
        StatusListMappingEntity reservation = new StatusListMappingEntity();

        repository.bookNextIndex(reservation, concurrentNewList, 3);

        assertEquals("list-2", reservation.getStatusListId(), "must share the list opened while waiting");
        assertEquals(1L, reservation.getIdx(), "next index follows the locked mapping");
    }

    private static StatusListMappingEntity mapping(String id, String statusListId, Long idx) {
        StatusListMappingEntity mapping = new StatusListMappingEntity();
        mapping.setId(id);
        mapping.setStatusListId(statusListId);
        mapping.setIdx(idx);
        return mapping;
    }
}
