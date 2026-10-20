package io.github.adorsysgis.keycloakstatuslist.jpa.repository;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
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

    @Mock
    private TypedQuery<StatusListMappingEntity> rereadQuery;

    @Mock
    private TypedQuery<StatusListMappingEntity> secondReread;

    @Mock
    private TypedQuery<StatusListMappingEntity> thirdReread;

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
        StatusListMappingEntity latest = mapping("latest", TEST_LIST_ID, 3L);
        when(em.createQuery(anyString(), eq(StatusListMappingEntity.class))).thenReturn(query);
        // FOR UPDATE, then tip-chase re-read confirms the same row.
        when(query.getResultList()).thenReturn(List.of(latest)).thenReturn(List.of(latest));

        StatusListMappingEntity result = repository.lockLatestMapping(em, TEST_REALM_ID);

        assertSame(latest, result, "should return the existing latest mapping");
        verify(em, never()).find(eq(RealmEntity.class), eq(TEST_REALM_ID), eq(LockModeType.PESSIMISTIC_WRITE));
        verify(em, never()).find(eq(StatusListMappingEntity.class), eq("latest"), eq(LockModeType.PESSIMISTIC_WRITE));
    }

    @Test
    void lockLatestMappingShouldLockRealmWhenTableIsEmpty() {
        StatusListMappingEntity first = mapping("first", TEST_LIST_ID, 0L);
        when(em.createQuery(anyString(), eq(StatusListMappingEntity.class))).thenReturn(query);
        // Empty, then the mapping once the realm row is locked, then tip-chase confirms the same row.
        when(query.getResultList())
                .thenReturn(List.of())
                .thenReturn(List.of(first))
                .thenReturn(List.of(first));
        when(em.find(eq(RealmEntity.class), eq(TEST_REALM_ID), eq(LockModeType.PESSIMISTIC_WRITE)))
                .thenReturn(mock(RealmEntity.class));

        StatusListMappingEntity result = repository.lockLatestMapping(em, TEST_REALM_ID);

        assertSame(first, result, "should return the mapping after locking the realm");
        verify(em).find(eq(RealmEntity.class), eq(TEST_REALM_ID), eq(LockModeType.PESSIMISTIC_WRITE));
    }

    @Test
    void lockLatestMappingShouldUseRowCommittedWhileWaiting() {
        StatusListMappingEntity waitedOn = mapping("waited-on", TEST_LIST_ID, 1L);
        StatusListMappingEntity committed = mapping("committed", "list-2", 0L);
        doReturn(query).doReturn(rereadQuery).when(em).createQuery(anyString(), eq(StatusListMappingEntity.class));
        when(query.getResultList()).thenReturn(List.of(waitedOn));
        // Tip is stable after one hop: first re-read sees committed, second confirms it.
        when(rereadQuery.getResultList()).thenReturn(List.of(committed)).thenReturn(List.of(committed));
        when(em.find(eq(StatusListMappingEntity.class), eq("committed"), eq(LockModeType.PESSIMISTIC_WRITE)))
                .thenReturn(committed);

        StatusListMappingEntity result = repository.lockLatestMapping(em, TEST_REALM_ID);

        assertSame(committed, result, "list choice must use the row inserted while this lock waited");
        verify(query).setLockMode(LockModeType.PESSIMISTIC_WRITE);
        verify(rereadQuery, never()).setLockMode(LockModeType.PESSIMISTIC_WRITE);
        verify(em).find(eq(StatusListMappingEntity.class), eq("committed"), eq(LockModeType.PESSIMISTIC_WRITE));
        verify(em, never()).find(eq(RealmEntity.class), eq(TEST_REALM_ID), eq(LockModeType.PESSIMISTIC_WRITE));
    }

    @Test
    void lockLatestMappingShouldChaseTipWhenAnotherRowCommitsDuringRefresh() {
        // Race #137: while B refreshes from the row it waited on, C can commit a newer tip.
        // One free slot left (idx 1 of max 3) → A takes idx 2; C then opens list-2 at idx 0.
        // B must land on C's tip so it reuses list-2 instead of overbooking list-1 or opening list-3.
        StatusListMappingEntity waitedOn = mapping("waited-on", TEST_LIST_ID, 1L);
        StatusListMappingEntity afterA = mapping("after-a", TEST_LIST_ID, 2L);
        StatusListMappingEntity afterC = mapping("after-c", "list-2", 0L);
        doReturn(query)
                .doReturn(rereadQuery)
                .doReturn(secondReread)
                .doReturn(thirdReread)
                .when(em)
                .createQuery(anyString(), eq(StatusListMappingEntity.class));
        when(query.getResultList()).thenReturn(List.of(waitedOn));
        when(rereadQuery.getResultList()).thenReturn(List.of(afterA));
        when(secondReread.getResultList()).thenReturn(List.of(afterC));
        when(thirdReread.getResultList()).thenReturn(List.of(afterC));
        when(em.find(eq(StatusListMappingEntity.class), eq("after-a"), eq(LockModeType.PESSIMISTIC_WRITE)))
                .thenReturn(afterA);
        when(em.find(eq(StatusListMappingEntity.class), eq("after-c"), eq(LockModeType.PESSIMISTIC_WRITE)))
                .thenReturn(afterC);

        StatusListMappingEntity result = repository.lockLatestMapping(em, TEST_REALM_ID);

        assertSame(afterC, result, "must chase past the intermediate tip committed during refresh");
        assertEquals("list-2", result.getStatusListId());
        assertEquals(0L, result.getIdx());
        verify(em).find(eq(StatusListMappingEntity.class), eq("after-a"), eq(LockModeType.PESSIMISTIC_WRITE));
        verify(em).find(eq(StatusListMappingEntity.class), eq("after-c"), eq(LockModeType.PESSIMISTIC_WRITE));
    }

    @Test
    void getNextStatusListIdShouldRollOverWhenLastSlotWasTakenWhileWaiting() {
        // After chasing the tip, latest.idx is the last valid index → open a new list (race 1).
        StatusListMappingEntity lastSlot = mapping("last-slot", TEST_LIST_ID, 2L);

        String next = repository.getNextStatusListId(lastSlot, 3);

        assertNotEquals(TEST_LIST_ID, next, "full list after last-slot race must roll over");
    }

    @Test
    void getNextStatusListIdShouldReuseListOpenedByConcurrentRollover() {
        // After chasing the tip, latest is idx 0 on a list opened by the winner (race 2).
        StatusListMappingEntity concurrentNewList = mapping("new-list-tip", "list-2", 0L);

        String next = repository.getNextStatusListId(concurrentNewList, 3);

        assertEquals("list-2", next, "must share the list opened while this reservation waited");
    }

    @Test
    void bookNextIndexShouldKeepListWhenBelowMaxEntries() {
        StatusListMappingEntity occupied = mapping("occupied", TEST_LIST_ID, 1L);
        StatusListMappingEntity reservation = mapping(null, TEST_LIST_ID, null);
        when(em.createQuery(anyString(), eq(StatusListMappingEntity.class))).thenReturn(query);
        when(query.getResultList()).thenReturn(List.of(occupied));

        Long idx = repository.bookNextIndex(em, reservation, 3);

        assertEquals(2L, idx);
        assertEquals(TEST_LIST_ID, reservation.getStatusListId());
    }

    @Test
    void bookNextIndexShouldRollOverWhenNextIndexWouldExceedMaxEntries() {
        // Last-slot race safety net: list choice was stale and getNextIndex returned past the end.
        StatusListMappingEntity lastSlot = mapping("last-slot", TEST_LIST_ID, 2L);
        StatusListMappingEntity reservation = mapping(null, TEST_LIST_ID, null);
        when(em.createQuery(anyString(), eq(StatusListMappingEntity.class))).thenReturn(query);
        when(query.getResultList()).thenReturn(List.of(lastSlot)).thenReturn(List.of());

        Long idx = repository.bookNextIndex(em, reservation, 3);

        assertEquals(0L, idx, "rolled-over list must start at index 0");
        assertNotEquals(TEST_LIST_ID, reservation.getStatusListId(), "must switch to a fresh list id");
        assertFalse(reservation.getStatusListId().isBlank());
    }

    private static StatusListMappingEntity mapping(String id, String statusListId, Long idx) {
        StatusListMappingEntity mapping = new StatusListMappingEntity();
        mapping.setId(id);
        mapping.setStatusListId(statusListId);
        mapping.setIdx(idx);
        return mapping;
    }
}
