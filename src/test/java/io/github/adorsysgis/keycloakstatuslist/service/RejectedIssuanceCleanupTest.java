package io.github.adorsysgis.keycloakstatuslist.service;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloakstatuslist.helpers.MockKeycloakTest;
import io.github.adorsysgis.keycloakstatuslist.jpa.repository.StatusListRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.UserProvider;
import org.mockito.Mock;

class RejectedIssuanceCleanupTest extends MockKeycloakTest {

    @Mock
    private UserProvider userProvider;

    @Mock
    private StatusListRepository statusListRepository;

    private RejectedIssuanceCleanup cleanup;

    @BeforeEach
    void setUp() {
        lenient().when(session.users()).thenReturn(userProvider);
        cleanup = new RejectedIssuanceCleanup(session, statusListRepository);
    }

    @Test
    void discard_deletesIssuedCredentialAndMarksInitReservationFailed() {
        when(userProvider.removeIssuedVerifiableCredential("issued-1")).thenReturn(true);
        when(statusListRepository.markInitMappingsFailed("realm-1", "issued-1")).thenReturn(1);

        cleanup.discard("realm-1", "issued-1");

        verify(userProvider).removeIssuedVerifiableCredential("issued-1");
        verify(statusListRepository).markInitMappingsFailed("realm-1", "issued-1");
    }

    @Test
    void discard_doesNotDeleteWhenIssuedCredentialIdIsMissing() {
        cleanup.discard("realm-1", " ");

        verify(userProvider, never()).removeIssuedVerifiableCredential(anyString());
        verify(statusListRepository, never()).markInitMappingsFailed(anyString(), anyString());
    }

    @Test
    void discard_swallowsDeleteFailureSoOriginalRejectCanPropagate() {
        when(userProvider.removeIssuedVerifiableCredential("issued-1")).thenThrow(new RuntimeException("db down"));

        assertDoesNotThrow(() -> cleanup.discard("realm-1", "issued-1"));
    }
}
