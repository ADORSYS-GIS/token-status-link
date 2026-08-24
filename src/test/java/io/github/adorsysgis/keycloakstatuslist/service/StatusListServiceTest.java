package io.github.adorsysgis.keycloakstatuslist.service;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloakstatuslist.client.StatusListHttpClient;
import io.github.adorsysgis.keycloakstatuslist.exception.StatusListException;
import io.github.adorsysgis.keycloakstatuslist.exception.StatusListServerException;
import io.github.adorsysgis.keycloakstatuslist.model.TokenStatus;
import java.util.List;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.jose.jwk.JWK;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for StatusListService. Tests core logic: publish-vs-update branching,
 * delegation, and error propagation.
 * Mocking: only StatusListHttpClient (external boundary). Real payloads and exceptions.
 */
@ExtendWith(MockitoExtension.class)
class StatusListServiceTest {

    @Mock
    private StatusListHttpClient httpClient;

    @Mock
    private JWK mockJwk;

    private StatusListService statusListService;

    @BeforeEach
    void setUp() {
        statusListService = new StatusListService(httpClient);
    }

    @Test
    void registerIssuer_delegatesToHttpClient() throws StatusListException {
        statusListService.registerIssuer("issuer-1", mockJwk);

        verify(httpClient).registerIssuer(eq("issuer-1"), eq(mockJwk));
    }

    @Test
    void checkServerHealth_delegatesToHttpClient() {
        when(httpClient.checkServerHealth()).thenReturn(true);

        assertTrue(statusListService.checkServerHealth());
        verify(httpClient).checkServerHealth();
    }

    @Test
    void publishOrUpdate_publishesNewListWithoutExistenceCheck() throws StatusListException {
        doNothing().when(httpClient).publishStatusList(any(), anyString());

        StatusListService.StatusListPayload payload = new StatusListService.StatusListPayload(
                "list-id", List.of(new StatusListService.StatusListPayload.StatusEntry(1, TokenStatus.VALID)));

        statusListService.publishOrUpdate(payload);

        verify(httpClient).publishStatusList(eq(payload), anyString());
        verify(httpClient, never()).updateStatusList(any(), anyString());
    }

    @Test
    void publishOrUpdate_whenPublishConflicts_updatesExistingList() throws StatusListException {
        doThrow(new StatusListServerException("already exists", HttpStatus.SC_CONFLICT))
                .when(httpClient)
                .publishStatusList(any(), anyString());
        doNothing().when(httpClient).updateStatusList(any(), anyString());

        StatusListService.StatusListPayload payload = new StatusListService.StatusListPayload(
                "list-id", List.of(new StatusListService.StatusListPayload.StatusEntry(1, TokenStatus.INVALID)));

        statusListService.publishOrUpdate(payload);

        verify(httpClient).publishStatusList(eq(payload), anyString());
        verify(httpClient).updateStatusList(eq(payload), anyString());
    }

    @Test
    void publishOrUpdate_whenPublishFailsWithNonConflict_throws() throws StatusListException {
        doThrow(new StatusListException("Connection failed")).when(httpClient).publishStatusList(any(), anyString());

        StatusListService.StatusListPayload payload = new StatusListService.StatusListPayload(
                "list-id", List.of(new StatusListService.StatusListPayload.StatusEntry(1, TokenStatus.VALID)));

        StatusListException exception =
                assertThrows(StatusListException.class, () -> statusListService.publishOrUpdate(payload));

        assertTrue(exception.getMessage().contains("Connection failed")
                || exception.getMessage().contains("Failed to publish or update"));
        verify(httpClient, never()).updateStatusList(any(), anyString());
    }

    @Test
    void updateStatusList_delegatesToHttpClient() throws StatusListException {
        StatusListService.StatusListPayload payload = new StatusListService.StatusListPayload(
                "list-id", List.of(new StatusListService.StatusListPayload.StatusEntry(1, TokenStatus.INVALID)));
        doNothing().when(httpClient).updateStatusList(any(), anyString());

        statusListService.updateStatusList(payload, "request-123");

        verify(httpClient).updateStatusList(eq(payload), eq("request-123"));
    }
}
