package com.adorsys.keycloakstatuslist.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import com.adorsys.keycloakstatuslist.jpa.repository.StatusListRepository;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationResponse;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.IssuedVerifiableCredentialModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class CredentialRevocationServiceTest {

    @Mock
    private KeycloakSession session;

    @Mock
    private StatusListService statusListService;

    @Mock
    private StatusListRepository statusListRepository;

    @Mock
    private KeycloakContext context;

    @Mock
    private RealmModel realm;

    @Mock
    private UserProvider userProvider;

    @Mock
    private UserModel user;

    @Mock
    private IssuedVerifiableCredentialModel issuedCredential;

    private CredentialRevocationService service;

    @BeforeEach
    void setUp() {
        service = new CredentialRevocationService(session, statusListService, statusListRepository);
        lenient().when(session.getContext()).thenReturn(context);
        lenient().when(context.getRealm()).thenReturn(realm);
        lenient().when(realm.getId()).thenReturn("realm-1");
        lenient().when(session.users()).thenReturn(userProvider);
    }

    @Test
    void constructor_withSessionOnly_createsService() {
        CredentialRevocationService s = new CredentialRevocationService(session);
        assertNotNull(s);
    }

    @Test
    void revokeIssuedCredential_success_updatesStatusListAndRemovesIssuedCredential() throws Exception {
        CredentialRevocationRequest request = issuedRevocationRequest("issued-1", "User requested revocation");
        AuthResult authResult = new AuthResult(user, null, null, null);
        StatusListMappingEntity mapping = statusListMapping("list-1", 7L);

        when(user.getId()).thenReturn("user-1");
        when(issuedCredential.getId()).thenReturn("issued-1");
        when(issuedCredential.getVerifiableCredentialId()).thenReturn("credential-1");
        when(userProvider.getIssuedVerifiableCredentialsStreamByUser("user-1")).thenReturn(Stream.of(issuedCredential));
        when(statusListRepository.findSuccessfulMappingByTokenIds(eq("realm-1"), eq("user-1"), any()))
                .thenReturn(Optional.of(mapping));
        when(userProvider.removeIssuedVerifiableCredential("issued-1")).thenReturn(true);
        doNothing().when(statusListService).updateStatusList(any(), anyString());

        CredentialRevocationResponse response = service.revokeIssuedCredential(request, authResult);

        assertNotNull(response);
        assertTrue(response.isSuccess());
        assertEquals("User requested revocation", response.getRevocationReason());

        ArgumentCaptor<StatusListService.StatusListPayload> payloadCaptor =
                ArgumentCaptor.forClass(StatusListService.StatusListPayload.class);
        verify(statusListService).updateStatusList(payloadCaptor.capture(), anyString());
        StatusListService.StatusListPayload payload = payloadCaptor.getValue();
        assertEquals("list-1", payload.listId());
        assertEquals(1, payload.status().size());
        assertEquals(7L, payload.status().get(0).index());
        assertEquals(TokenStatus.INVALID, payload.status().get(0).status());
        verify(userProvider).removeIssuedVerifiableCredential("issued-1");
    }

    @Test
    void revokeIssuedCredential_missingCredentialId_throws400() throws Exception {
        CredentialRevocationRequest request = issuedRevocationRequest(" ", "reason");
        AuthResult authResult = new AuthResult(user, null, null, null);

        StatusListException exception =
                assertThrows(StatusListException.class, () -> service.revokeIssuedCredential(request, authResult));

        assertEquals(400, exception.getHttpStatus());
        assertTrue(exception.getMessage().contains("Missing credential_id"));
        verify(statusListService, never()).updateStatusList(any(), anyString());
        verify(userProvider, never()).removeIssuedVerifiableCredential(anyString());
    }

    @Test
    void revokeIssuedCredential_nullRequest_throwsNPE() {
        AuthResult authResult = new AuthResult(user, null, null, null);

        assertThrows(NullPointerException.class, () -> service.revokeIssuedCredential(null, authResult));
    }

    @Test
    void revokeIssuedCredential_nullAuthResult_throwsNPE() {
        CredentialRevocationRequest request = issuedRevocationRequest("issued-1", "reason");

        assertThrows(NullPointerException.class, () -> service.revokeIssuedCredential(request, null));
    }

    @Test
    void revokeIssuedCredential_missingUser_throws401() throws Exception {
        CredentialRevocationRequest request = issuedRevocationRequest("issued-1", "reason");
        AuthResult authResult = new AuthResult(null, null, null, null);

        StatusListException exception =
                assertThrows(StatusListException.class, () -> service.revokeIssuedCredential(request, authResult));

        assertEquals(401, exception.getHttpStatus());
        assertTrue(exception.getMessage().contains("Authenticated user is required"));
        verify(statusListService, never()).updateStatusList(any(), anyString());
    }

    @Test
    void revokeIssuedCredential_missingIssuedCredential_throws404() throws Exception {
        CredentialRevocationRequest request = issuedRevocationRequest("issued-1", "reason");
        AuthResult authResult = new AuthResult(user, null, null, null);

        when(user.getId()).thenReturn("user-1");
        when(userProvider.getIssuedVerifiableCredentialsStreamByUser("user-1")).thenReturn(Stream.empty());

        StatusListException exception =
                assertThrows(StatusListException.class, () -> service.revokeIssuedCredential(request, authResult));

        assertEquals(404, exception.getHttpStatus());
        assertTrue(exception.getMessage().contains("Issued credential not found"));
        verify(statusListService, never()).updateStatusList(any(), anyString());
        verify(userProvider, never()).removeIssuedVerifiableCredential(anyString());
    }

    @Test
    void revokeIssuedCredential_missingMapping_throws404AndDoesNotRemoveIssuedCredential() throws Exception {
        CredentialRevocationRequest request = issuedRevocationRequest("issued-1", "reason");
        AuthResult authResult = new AuthResult(user, null, null, null);

        when(user.getId()).thenReturn("user-1");
        when(issuedCredential.getId()).thenReturn("issued-1");
        when(issuedCredential.getVerifiableCredentialId()).thenReturn("credential-1");
        when(userProvider.getIssuedVerifiableCredentialsStreamByUser("user-1")).thenReturn(Stream.of(issuedCredential));
        when(statusListRepository.findSuccessfulMappingByTokenIds(eq("realm-1"), eq("user-1"), any()))
                .thenReturn(Optional.empty());

        StatusListException exception =
                assertThrows(StatusListException.class, () -> service.revokeIssuedCredential(request, authResult));

        assertEquals(404, exception.getHttpStatus());
        assertTrue(exception.getMessage().contains("Status list mapping not found"));
        verify(statusListService, never()).updateStatusList(any(), anyString());
        verify(userProvider, never()).removeIssuedVerifiableCredential(anyString());
    }

    @Test
    void revokeIssuedCredential_unlinkedMapping_claimsMappingThenRevokes() throws Exception {
        CredentialRevocationRequest request = issuedRevocationRequest("issued-1", "reason");
        AuthResult authResult = new AuthResult(user, null, null, null);
        StatusListMappingEntity mapping = statusListMapping("list-1", 7L);

        when(user.getId()).thenReturn("user-1");
        when(issuedCredential.getId()).thenReturn("issued-1");
        when(issuedCredential.getVerifiableCredentialId()).thenReturn("credential-1");
        when(issuedCredential.getIssuedAt()).thenReturn(1_785_227_763_540L);
        when(userProvider.getIssuedVerifiableCredentialsStreamByUser("user-1")).thenReturn(Stream.of(issuedCredential));
        when(statusListRepository.findSuccessfulMappingByTokenIds(eq("realm-1"), eq("user-1"), any()))
                .thenReturn(Optional.empty());
        when(statusListRepository.claimUnlinkedSuccessfulMappingNearIssuedAt(
                        eq("realm-1"), eq("user-1"), eq(1_785_227_763_540L), eq(60_000L), eq("issued-1")))
                .thenReturn(Optional.of(mapping));
        when(userProvider.removeIssuedVerifiableCredential("issued-1")).thenReturn(true);

        CredentialRevocationResponse response = service.revokeIssuedCredential(request, authResult);

        assertNotNull(response);
        assertTrue(response.isSuccess());

        ArgumentCaptor<StatusListService.StatusListPayload> payloadCaptor =
                ArgumentCaptor.forClass(StatusListService.StatusListPayload.class);
        verify(statusListService).updateStatusList(payloadCaptor.capture(), anyString());
        StatusListService.StatusListPayload payload = payloadCaptor.getValue();
        assertEquals("list-1", payload.listId());
        assertEquals(7L, payload.status().get(0).index());
        assertEquals(TokenStatus.INVALID, payload.status().get(0).status());
        verify(userProvider).removeIssuedVerifiableCredential("issued-1");
    }

    @Test
    void revokeIssuedCredential_statusListUpdateFails_doesNotRemoveIssuedCredential() throws Exception {
        CredentialRevocationRequest request = issuedRevocationRequest("issued-1", "reason");
        AuthResult authResult = new AuthResult(user, null, null, null);
        StatusListMappingEntity mapping = statusListMapping("list-1", 7L);

        when(user.getId()).thenReturn("user-1");
        when(issuedCredential.getId()).thenReturn("issued-1");
        when(issuedCredential.getVerifiableCredentialId()).thenReturn("credential-1");
        when(userProvider.getIssuedVerifiableCredentialsStreamByUser("user-1")).thenReturn(Stream.of(issuedCredential));
        when(statusListRepository.findSuccessfulMappingByTokenIds(eq("realm-1"), eq("user-1"), any()))
                .thenReturn(Optional.of(mapping));
        doThrow(new StatusListException("Status list server unavailable", 503))
                .when(statusListService)
                .updateStatusList(any(), anyString());

        StatusListException exception =
                assertThrows(StatusListException.class, () -> service.revokeIssuedCredential(request, authResult));

        assertEquals(503, exception.getHttpStatus());
        verify(userProvider, never()).removeIssuedVerifiableCredential(anyString());
    }

    @Test
    void revokeIssuedCredential_removeFails_throws500AfterStatusUpdate() throws Exception {
        CredentialRevocationRequest request = issuedRevocationRequest("issued-1", "reason");
        AuthResult authResult = new AuthResult(user, null, null, null);
        StatusListMappingEntity mapping = statusListMapping("list-1", 7L);

        when(user.getId()).thenReturn("user-1");
        when(issuedCredential.getId()).thenReturn("issued-1");
        when(issuedCredential.getVerifiableCredentialId()).thenReturn("credential-1");
        when(userProvider.getIssuedVerifiableCredentialsStreamByUser("user-1")).thenReturn(Stream.of(issuedCredential));
        when(statusListRepository.findSuccessfulMappingByTokenIds(eq("realm-1"), eq("user-1"), any()))
                .thenReturn(Optional.of(mapping));
        when(userProvider.removeIssuedVerifiableCredential("issued-1")).thenReturn(false);

        StatusListException exception =
                assertThrows(StatusListException.class, () -> service.revokeIssuedCredential(request, authResult));

        assertEquals(500, exception.getHttpStatus());
        assertTrue(exception.getMessage().contains("Issued credential could not be removed"));
        verify(statusListService).updateStatusList(any(), anyString());
    }

    @Test
    void revokeIssuedCredential_allowsDifferentClientBecauseUserOwnsIssuedCredential() throws Exception {
        CredentialRevocationRequest request = issuedRevocationRequest("issued-1", "reason");
        AuthResult authResult = new AuthResult(user, null, null, null);
        StatusListMappingEntity mapping = statusListMapping("list-1", 7L);

        when(user.getId()).thenReturn("user-1");
        when(issuedCredential.getId()).thenReturn("issued-1");
        when(issuedCredential.getVerifiableCredentialId()).thenReturn("credential-1");
        when(userProvider.getIssuedVerifiableCredentialsStreamByUser("user-1")).thenReturn(Stream.of(issuedCredential));
        when(statusListRepository.findSuccessfulMappingByTokenIds(eq("realm-1"), eq("user-1"), any()))
                .thenReturn(Optional.of(mapping));
        when(userProvider.removeIssuedVerifiableCredential("issued-1")).thenReturn(true);

        CredentialRevocationResponse response = service.revokeIssuedCredential(request, authResult);

        assertTrue(response.isSuccess());
        verify(statusListService).updateStatusList(any(), anyString());
        verify(userProvider).removeIssuedVerifiableCredential("issued-1");
    }

    private CredentialRevocationRequest issuedRevocationRequest(String credentialId, String reason) {
        CredentialRevocationRequest request = new CredentialRevocationRequest();
        request.setRevocationMode(CredentialRevocationRequest.ISSUED_CREDENTIAL_REVOCATION_MODE);
        request.setCredentialId(credentialId);
        request.setRevocationReason(reason);
        return request;
    }

    private StatusListMappingEntity statusListMapping(String listId, long index) {
        StatusListMappingEntity mapping = new StatusListMappingEntity();
        mapping.setStatusListId(listId);
        mapping.setIdx(index);
        mapping.setUserId("user-1");
        mapping.setRealmId("realm-1");
        mapping.setTokenId("issued-1");
        mapping.setStatus(StatusListMappingEntity.MappingStatus.SUCCESS);
        return mapping;
    }
}
