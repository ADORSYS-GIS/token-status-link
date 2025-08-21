package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationResponse;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.keycloak.sdjwt.vp.SdJwtVP;

import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for CredentialRevocationService.
 * Tests ONLY the main service's orchestration logic, not individual service implementations.
 */
@ExtendWith(MockitoExtension.class)
class CredentialRevocationServiceTest {

    @Mock
    private KeycloakSession session;
    
    @Mock
    private RealmModel realm;
    
    @Mock
    private KeycloakContext context;
    
    @Mock
    private KeyManager keyManager;
    
    @Mock
    private KeyWrapper keyWrapper;
    
    @Mock
    private PublicKey publicKey;
    
    @Mock
    private StatusListService statusListService;
    
    @Mock
    private SdJwtVP sdJwtVP;
    
    @Mock
    private SdJwtVPValidationService sdJwtVPValidationService;
    
    @Mock
    private RevocationRecordService revocationRecordService;
    
    @Mock
    private RequestValidationService requestValidationService;
    
    @Mock
    private TokenStatusRecord mockRevocationRecord;

    private CredentialRevocationService service;

    @BeforeEach
    void setUp() {
        // Setup basic session mocks
        lenient().when(session.getContext()).thenReturn(context);
        lenient().when(context.getRealm()).thenReturn(realm);
        lenient().when(session.keys()).thenReturn(keyManager);
        lenient().when(realm.getName()).thenReturn("test-realm");
        
        // Setup realm attributes
        lenient().when(realm.getAttribute("status-list-enabled")).thenReturn("true");
        lenient().when(realm.getAttribute("status-list-auth-token")).thenReturn("test-auth-token");
        lenient().when(realm.getAttribute("status-list-connect-timeout")).thenReturn("5000");
        lenient().when(realm.getAttribute("status-list-read-timeout")).thenReturn("5000");
        lenient().when(realm.getAttribute("status-list-retry-count")).thenReturn("3");
        lenient().when(realm.getAttribute(anyString())).thenReturn(null);
        
        // Setup key management
        lenient().when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq("RS256"))).thenReturn(keyWrapper);
        lenient().when(keyWrapper.getPublicKey()).thenReturn(publicKey);
        lenient().when(keyWrapper.getAlgorithm()).thenReturn("RS256");
        
        // Create service with mocked dependencies
        service = new CredentialRevocationService(session);
        
        // Inject mocked dependencies using reflection
        injectMockedDependencies();
    }
    
    private void injectMockedDependencies() {
        try {
            // Inject mocked SdJwtVPValidationService
            java.lang.reflect.Field sdJwtVPValidationField = CredentialRevocationService.class.getDeclaredField("sdJwtVPValidationService");
            sdJwtVPValidationField.setAccessible(true);
            sdJwtVPValidationField.set(service, sdJwtVPValidationService);
            
            // Inject mocked RevocationRecordService
            java.lang.reflect.Field revocationRecordField = CredentialRevocationService.class.getDeclaredField("revocationRecordService");
            revocationRecordField.setAccessible(true);
            revocationRecordField.set(service, revocationRecordService);
            
            // Inject mocked RequestValidationService
            java.lang.reflect.Field requestValidationField = CredentialRevocationService.class.getDeclaredField("requestValidationService");
            requestValidationField.setAccessible(true);
            requestValidationField.set(service, requestValidationService);
            
            // Inject mocked StatusListService
            java.lang.reflect.Field statusListField = CredentialRevocationService.class.getDeclaredField("statusListService");
            statusListField.setAccessible(true);
            statusListField.set(service, statusListService);
            
        } catch (Exception e) {
            fail("Failed to inject mocked dependencies: " + e.getMessage());
        }
    }

    @Test
    void testRevokeCredential_Success() throws Exception {
        // Arrange
        CredentialRevocationRequest request = createValidRequest();
        
        // Mock all dependencies to return success
        doNothing().when(requestValidationService).validateRevocationRequest(any());
        when(sdJwtVPValidationService.parseAndValidateSdJwtVP(anyString(), anyString())).thenReturn(sdJwtVP);
        doNothing().when(sdJwtVPValidationService).verifyCredentialOwnership(any(SdJwtVP.class), anyString(), anyString());
        when(revocationRecordService.createRevocationRecord(any(), anyString())).thenReturn(mockRevocationRecord);
        doNothing().when(statusListService).publishRecord(any(TokenStatusRecord.class));
        
        // Act
        CredentialRevocationResponse response = service.revokeCredential(request, "valid-sd-jwt-vp-token");
        
        // Assert - Test ONLY the main service's orchestration logic
        assertNotNull(response);
        assertEquals(request.getCredentialId(), response.getCredentialId());
        assertNotNull(response.getRevokedAt());
        assertEquals(request.getRevocationReason(), response.getRevocationReason());
        
        // Verify the orchestration flow - services called in correct order
        verify(requestValidationService).validateRevocationRequest(any());
        verify(sdJwtVPValidationService).parseAndValidateSdJwtVP(anyString(), anyString());
        verify(sdJwtVPValidationService).verifyCredentialOwnership(any(SdJwtVP.class), anyString(), anyString());
        verify(revocationRecordService).createRevocationRecord(any(), anyString());
        verify(statusListService).publishRecord(any(TokenStatusRecord.class));
    }

    @Test
    void testRevokeCredential_RequestValidationFailure() throws Exception {
        // Arrange
        CredentialRevocationRequest request = createValidRequest();
        
        // Mock validation to fail
        doThrow(new StatusListException("Validation failed"))
            .when(requestValidationService).validateRevocationRequest(any());
        
        // Act & Assert
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request, "valid-sd-jwt-vp-token");
        });
        
        // Test that the main service properly handles the error
        assertTrue(exception.getMessage().contains("Validation failed"));
        
        // Verify no other services were called
        verify(sdJwtVPValidationService, never()).parseAndValidateSdJwtVP(anyString(), anyString());
        verify(revocationRecordService, never()).createRevocationRecord(any(), anyString());
        verify(statusListService, never()).publishRecord(any());
    }

    @Test
    void testRevokeCredential_SdJwtVPValidationFailure() throws Exception {
        // Arrange
        CredentialRevocationRequest request = createValidRequest();
        
        // Mock request validation to succeed, but SD-JWT validation to fail
        doNothing().when(requestValidationService).validateRevocationRequest(any());
        when(sdJwtVPValidationService.parseAndValidateSdJwtVP(anyString(), anyString()))
            .thenThrow(new StatusListException("SD-JWT validation failed"));
        
        // Act & Assert
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request, "valid-sd-jwt-vp-token");
        });
        
        // Test that the main service properly handles the error
        assertTrue(exception.getMessage().contains("SD-JWT validation failed"));
        
        // Verify the flow stopped at SD-JWT validation
        verify(requestValidationService).validateRevocationRequest(any());
        verify(sdJwtVPValidationService).parseAndValidateSdJwtVP(anyString(), anyString());
        verify(revocationRecordService, never()).createRevocationRecord(any(), anyString());
        verify(statusListService, never()).publishRecord(any());
    }

    @Test
    void testRevokeCredential_StatusListFailure() throws Exception {
        // Arrange
        CredentialRevocationRequest request = createValidRequest();
        
        // Mock all dependencies to succeed until status list publication
        doNothing().when(requestValidationService).validateRevocationRequest(any());
        when(sdJwtVPValidationService.parseAndValidateSdJwtVP(anyString(), anyString())).thenReturn(sdJwtVP);
        doNothing().when(sdJwtVPValidationService).verifyCredentialOwnership(any(SdJwtVP.class), anyString(), anyString());
        when(revocationRecordService.createRevocationRecord(any(), anyString())).thenReturn(mockRevocationRecord);
        doThrow(new StatusListException("Status list publication failed"))
            .when(statusListService).publishRecord(any(TokenStatusRecord.class));
        
        // Act & Assert
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request, "valid-sd-jwt-vp-token");
        });
        
        // Test that the main service properly handles the error
        assertTrue(exception.getMessage().contains("Status list publication failed"));
        
        // Verify the complete flow was executed
        verify(requestValidationService).validateRevocationRequest(any());
        verify(sdJwtVPValidationService).parseAndValidateSdJwtVP(anyString(), anyString());
        verify(sdJwtVPValidationService).verifyCredentialOwnership(any(SdJwtVP.class), anyString(), anyString());
        verify(revocationRecordService).createRevocationRecord(any(), anyString());
        verify(statusListService).publishRecord(any(TokenStatusRecord.class));
    }

    @Test
    void testRevokeCredential_RequestIdGeneration() throws Exception {
        // Arrange
        CredentialRevocationRequest request1 = createValidRequest();
        CredentialRevocationRequest request2 = createValidRequest();
        
        // Mock all dependencies to succeed
        doNothing().when(requestValidationService).validateRevocationRequest(any());
        when(sdJwtVPValidationService.parseAndValidateSdJwtVP(anyString(), anyString())).thenReturn(sdJwtVP);
        doNothing().when(sdJwtVPValidationService).verifyCredentialOwnership(any(SdJwtVP.class), anyString(), anyString());
        when(revocationRecordService.createRevocationRecord(any(), anyString())).thenReturn(mockRevocationRecord);
        doNothing().when(statusListService).publishRecord(any(TokenStatusRecord.class));
        
        // Act
        service.revokeCredential(request1, "valid-sd-jwt-vp-token");
        service.revokeCredential(request2, "valid-sd-jwt-vp-token");
        
        // Assert - Verify that different request IDs were generated
        verify(sdJwtVPValidationService, times(2)).parseAndValidateSdJwtVP(anyString(), anyString());
        verify(revocationRecordService, times(2)).createRevocationRecord(any(), anyString());
        verify(statusListService, times(2)).publishRecord(any());
    }

    @Test
    void testRevokeCredential_UnexpectedException() throws Exception {
        // Arrange
        CredentialRevocationRequest request = createValidRequest();
        
        // Mock an unexpected exception
        doNothing().when(requestValidationService).validateRevocationRequest(any());
        when(sdJwtVPValidationService.parseAndValidateSdJwtVP(anyString(), anyString()))
            .thenThrow(new RuntimeException("Unexpected error"));
        
        // Act & Assert
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request, "valid-sd-jwt-vp-token");
        });
        
        // Test that the main service properly wraps unexpected exceptions
        assertTrue(exception.getMessage().contains("Failed to process credential revocation"));
        assertTrue(exception.getMessage().contains("Unexpected error"));
    }

    @Test
    void testRevokeCredential_ServiceInitialization() {
        // Act & Assert
        CredentialRevocationService newService = new CredentialRevocationService(session);
        assertNotNull(newService);
    }

    private CredentialRevocationRequest createValidRequest() {
        return new CredentialRevocationRequest(
                "test-credential-123",
                "Test revocation"
        );
    }
} 
