package com.adorsys.keycloakstatuslist.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.adorsys.keycloakstatuslist.client.StatusListHttpClient;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.jose.jwk.JWK;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for StatusListService. Tests core logic: publish-vs-update branching,
 * URI building, delegation, and error propagation.
 * Mocking: only StatusListHttpClient (external boundary). Real payloads and exceptions.
 */
@ExtendWith(MockitoExtension.class)
class StatusListServiceTest {

    private static final String SERVER_URL = "https://status-list-server.example.com/";

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
    void getStatusListUri_buildsFromServerUrl() {
        when(httpClient.getServerUrl()).thenReturn(SERVER_URL);

        String uri = statusListService.getStatusListUri("list-123");

        assertEquals(SERVER_URL + "statuslists/list-123", uri);
        verify(httpClient).getServerUrl();
    }

    @Test
    void publishOrUpdate_whenListDoesNotExist_publishesNewList() throws StatusListException {
        when(httpClient.checkStatusListExists("list-id")).thenReturn(false);
        doNothing().when(httpClient).publishStatusList(any(), anyString());

        StatusListService.StatusListPayload payload = new StatusListService.StatusListPayload(
                "list-id", List.of(new StatusListService.StatusListPayload.StatusEntry(1, "VALID")));

        statusListService.publishOrUpdate(payload);

        verify(httpClient).checkStatusListExists("list-id");
        verify(httpClient).publishStatusList(eq(payload), anyString());
        verify(httpClient, never()).updateStatusList(any(), anyString());
    }

    @Test
    void publishOrUpdate_whenListExists_updatesList() throws StatusListException {
        when(httpClient.checkStatusListExists("list-id")).thenReturn(true);
        doNothing().when(httpClient).updateStatusList(any(), anyString());

        StatusListService.StatusListPayload payload = new StatusListService.StatusListPayload(
                "list-id", List.of(new StatusListService.StatusListPayload.StatusEntry(1, "INVALID")));

        statusListService.publishOrUpdate(payload);

        verify(httpClient).checkStatusListExists("list-id");
        verify(httpClient).updateStatusList(eq(payload), anyString());
        verify(httpClient, never()).publishStatusList(any(), anyString());
    }

    @Test
    void publishOrUpdate_whenCheckFails_throws() throws StatusListException {
        when(httpClient.checkStatusListExists("list-id")).thenThrow(new StatusListException("Connection failed"));

        StatusListService.StatusListPayload payload = new StatusListService.StatusListPayload(
                "list-id", List.of(new StatusListService.StatusListPayload.StatusEntry(1, "VALID")));

        StatusListException exception =
                assertThrows(StatusListException.class, () -> statusListService.publishOrUpdate(payload));

        assertTrue(exception.getMessage().contains("Connection failed")
                || exception.getMessage().contains("Failed to publish or update"));
    }

    @Test
    void updateStatusList_delegatesToHttpClient() throws StatusListException {
        StatusListService.StatusListPayload payload = new StatusListService.StatusListPayload(
                "list-id", List.of(new StatusListService.StatusListPayload.StatusEntry(1, "INVALID")));
        doNothing().when(httpClient).updateStatusList(any(), anyString());

        statusListService.updateStatusList(payload, "request-123");

        verify(httpClient).updateStatusList(eq(payload), eq("request-123"));
    }
}
