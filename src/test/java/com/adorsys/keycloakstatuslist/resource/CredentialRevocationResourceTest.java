package com.adorsys.keycloakstatuslist.resource;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationResponse;
import com.adorsys.keycloakstatuslist.service.CredentialRevocationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.KeycloakContext;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for CredentialRevocationResource.
 */
@ExtendWith(MockitoExtension.class)
class CredentialRevocationResourceTest {

    @Mock
    private KeycloakSession session;
    
    @Mock
    private RealmModel realm;
    
    @Mock
    private KeycloakContext context;
    
    @Mock
    private CredentialRevocationService revocationService;
    
    @Mock
    private HttpHeaders headers;
    
    @Mock
    private MultivaluedMap<String, String> headerMap;

    private CredentialRevocationResource resource;

    @BeforeEach
    void setUp() {
        lenient().when(session.getContext()).thenReturn(context);
        lenient().when(context.getRealm()).thenReturn(realm);
        lenient().when(realm.getName()).thenReturn("test-realm");
        
        // Mock realm attributes for enabled service
        lenient().when(realm.getAttribute("status-list-enabled")).thenReturn("true");
        lenient().when(realm.getAttribute("status-list-server-url")).thenReturn("https://test-server.com");
        
        // Mock headers
        lenient().when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer test-token");
        
        // Create resource with mocked service
        resource = new CredentialRevocationResource(session);
        
        // Inject mocked service using reflection
        try {
            java.lang.reflect.Field serviceField = CredentialRevocationResource.class.getDeclaredField("revocationService");
            serviceField.setAccessible(true);
            serviceField.set(resource, revocationService);
        } catch (Exception e) {
            fail("Failed to inject mocked service: " + e.getMessage());
        }
        
    }

    @Test
    void testRevokeCredential_Success() throws StatusListException {
        // Arrange
        CredentialRevocationRequest request = new CredentialRevocationRequest("test-credential-123", "Test revocation");
        CredentialRevocationResponse expectedResponse = CredentialRevocationResponse.success(
            "test-credential-123", 
            java.time.Instant.now(), 
            "Test revocation"
        );
        
        when(revocationService.revokeCredential(any(CredentialRevocationRequest.class), anyString()))
            .thenReturn(expectedResponse);
        
        // Act
        Response response = resource.revokeCredential(request, headers);
        
        // Assert
        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        assertNotNull(response.getEntity());
        assertTrue(response.getEntity() instanceof CredentialRevocationResponse);
        
        CredentialRevocationResponse actualResponse = (CredentialRevocationResponse) response.getEntity();
        assertEquals("Credential revoked successfully", actualResponse.getMessage());
        
        verify(revocationService).revokeCredential(request, "test-token");
    }

    @Test
    void testRevokeCredential_ServiceDisabled() throws StatusListException {
        // Arrange
        when(realm.getAttribute("status-list-enabled")).thenReturn("false");
        CredentialRevocationRequest request = new CredentialRevocationRequest("test-credential-123", "Test revocation");
        
        // Act
        Response response = resource.revokeCredential(request, headers);
        
        // Assert
        assertEquals(Response.Status.SERVICE_UNAVAILABLE.getStatusCode(), response.getStatus());
        assertNotNull(response.getEntity());
        
        CredentialRevocationResponse errorResponse = (CredentialRevocationResponse) response.getEntity();
        assertTrue(errorResponse.getMessage().contains("disabled"));
        
        verify(revocationService, never()).revokeCredential(any(), anyString());
    }

    @Test
    void testRevokeCredential_ServiceNotConfigured() throws StatusListException {
        // Arrange - Set server URL to empty string to trigger "not configured" state
        when(realm.getAttribute("status-list-server-url")).thenReturn("");
        CredentialRevocationRequest request = new CredentialRevocationRequest("test-credential-123", "Test revocation");
        
        // Act
        Response response = resource.revokeCredential(request, headers);
        
        // Assert
        assertEquals(Response.Status.SERVICE_UNAVAILABLE.getStatusCode(), response.getStatus());
        assertNotNull(response.getEntity());
        
        CredentialRevocationResponse errorResponse = (CredentialRevocationResponse) response.getEntity();
        assertTrue(errorResponse.getMessage().contains("not properly configured"));
        
        verify(revocationService, never()).revokeCredential(any(), anyString());
    }

    @Test
    void testRevokeCredential_MissingAuthorizationHeader() throws StatusListException {
        // Arrange
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn(null);
        CredentialRevocationRequest request = new CredentialRevocationRequest("test-credential-123", "Test revocation");
        
        // Act
        Response response = resource.revokeCredential(request, headers);
        
        // Assert
        assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
        assertNotNull(response.getEntity());
        
        CredentialRevocationResponse errorResponse = (CredentialRevocationResponse) response.getEntity();
        assertTrue(errorResponse.getMessage().contains("SD-JWT VP token is required"));
        
        verify(revocationService, never()).revokeCredential(any(), anyString());
    }

    @Test
    void testRevokeCredential_EmptyAuthorizationHeader() throws StatusListException {
        // Arrange
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("");
        CredentialRevocationRequest request = new CredentialRevocationRequest("test-credential-123", "Test revocation");
        
        // Act
        Response response = resource.revokeCredential(request, headers);
        
        // Assert
        assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
        assertNotNull(response.getEntity());
        
        CredentialRevocationResponse errorResponse = (CredentialRevocationResponse) response.getEntity();
        assertTrue(errorResponse.getMessage().contains("SD-JWT VP token is required"));
        
        verify(revocationService, never()).revokeCredential(any(), anyString());
    }

    @Test
    void testRevokeCredential_InvalidAuthorizationHeader() throws StatusListException {
        // Arrange
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("InvalidFormat token");
        CredentialRevocationRequest request = new CredentialRevocationRequest("test-credential-123", "Test revocation");
        
        // Act
        Response response = resource.revokeCredential(request, headers);
        
        // Assert
        assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
        assertNotNull(response.getEntity());
        
        CredentialRevocationResponse errorResponse = (CredentialRevocationResponse) response.getEntity();
        assertTrue(errorResponse.getMessage().contains("SD-JWT VP token is required"));
        
        verify(revocationService, never()).revokeCredential(any(), anyString());
    }

    @Test
    void testRevokeCredential_ServiceThrowsStatusListException() throws StatusListException {
        // Arrange
        CredentialRevocationRequest request = new CredentialRevocationRequest("test-credential-123", "Test revocation");
        when(revocationService.revokeCredential(any(CredentialRevocationRequest.class), anyString()))
            .thenThrow(new StatusListException("Invalid token format"));
        
        // Act
        Response response = resource.revokeCredential(request, headers);
        
        // Assert
        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        assertNotNull(response.getEntity());
        
        CredentialRevocationResponse errorResponse = (CredentialRevocationResponse) response.getEntity();
        assertEquals("Invalid token format", errorResponse.getMessage());
    }

    @Test
    void testRevokeCredential_ServiceThrowsIllegalArgumentException() throws StatusListException {
        // Arrange
        CredentialRevocationRequest request = new CredentialRevocationRequest("test-credential-123", "Test revocation");
        when(revocationService.revokeCredential(any(CredentialRevocationRequest.class), anyString()))
            .thenThrow(new IllegalArgumentException("Configuration error"));
        
        // Act
        Response response = resource.revokeCredential(request, headers);
        
        // Assert
        assertEquals(Response.Status.SERVICE_UNAVAILABLE.getStatusCode(), response.getStatus());
        assertNotNull(response.getEntity());
        
        CredentialRevocationResponse errorResponse = (CredentialRevocationResponse) response.getEntity();
        assertEquals("Configuration error", errorResponse.getMessage());
    }

    @Test
    void testRevokeCredential_ServiceThrowsUnexpectedException() throws StatusListException {
        // Arrange
        CredentialRevocationRequest request = new CredentialRevocationRequest("test-credential-123", "Test revocation");
        when(revocationService.revokeCredential(any(CredentialRevocationRequest.class), anyString()))
            .thenThrow(new RuntimeException("Unexpected error"));
        
        // Act
        Response response = resource.revokeCredential(request, headers);
        
        // Assert
        assertEquals(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), response.getStatus());
        assertNotNull(response.getEntity());
        
        CredentialRevocationResponse errorResponse = (CredentialRevocationResponse) response.getEntity();
        assertTrue(errorResponse.getMessage().contains("Internal server error"));
    }

    @Test
    void testGetServiceStatus_EnabledAndConfigured() {
        // Act
        Response response = resource.getServiceStatus();
        
        // Assert
        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        assertNotNull(response.getEntity());
        
        @SuppressWarnings("unchecked")
        Map<String, Object> status = (Map<String, Object>) response.getEntity();
        assertEquals(true, status.get("enabled"));
        assertEquals(true, status.get("configured"));
        assertEquals("credential-revocation", status.get("service"));
        assertEquals("Credential revocation service is available", status.get("message"));
    }

    @Test
    void testGetServiceStatus_Disabled() {
        // Arrange
        when(realm.getAttribute("status-list-enabled")).thenReturn("false");
        
        // Act
        Response response = resource.getServiceStatus();
        
        // Assert
        assertEquals(Response.Status.SERVICE_UNAVAILABLE.getStatusCode(), response.getStatus());
        assertNotNull(response.getEntity());
        
        @SuppressWarnings("unchecked")
        Map<String, Object> status = (Map<String, Object>) response.getEntity();
        assertEquals(false, status.get("enabled"));
        assertEquals(false, status.get("configured"));
        assertEquals("credential-revocation", status.get("service"));
        assertEquals("Credential revocation service is disabled", status.get("message"));
    }

    @Test
    void testGetServiceStatus_NotConfigured() {
        // Arrange - Set server URL to empty string to trigger "not configured" state
        when(realm.getAttribute("status-list-server-url")).thenReturn("");
        
        // Act
        Response response = resource.getServiceStatus();
        
        // Assert
        assertEquals(Response.Status.SERVICE_UNAVAILABLE.getStatusCode(), response.getStatus());
        assertNotNull(response.getEntity());
        
        @SuppressWarnings("unchecked")
        Map<String, Object> status = (Map<String, Object>) response.getEntity();
        assertEquals(true, status.get("enabled"));
        assertEquals(false, status.get("configured"));
        assertEquals("credential-revocation", status.get("service"));
        assertEquals("Credential revocation service is not properly configured", status.get("message"));
    }

    @Test
    void testGetServiceStatus_ExceptionHandling() {
        // Arrange - Mock the realm context to throw an exception when accessed
        when(context.getRealm()).thenThrow(new RuntimeException("Realm error"));
        
        // Act
        Response response = resource.getServiceStatus();
        
        // Assert
        assertEquals(Response.Status.SERVICE_UNAVAILABLE.getStatusCode(), response.getStatus());
        assertNotNull(response.getEntity());
        
        @SuppressWarnings("unchecked")
        Map<String, Object> status = (Map<String, Object>) response.getEntity();
        assertEquals(false, status.get("enabled"));
        assertEquals(false, status.get("configured"));
        assertEquals("credential-revocation", status.get("service"));
        assertEquals("Credential revocation service is disabled", status.get("message"));
    }

    @Test
    void testExtractSdJwtVpToken_ValidBearerToken() throws StatusListException {
        // Arrange
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer valid-token-123");
        
        // Act
        Response response = resource.revokeCredential(
            new CredentialRevocationRequest("test", "reason"), headers);
        
        // Assert
        assertNotNull(response);
        verify(revocationService).revokeCredential(any(), eq("valid-token-123"));
    }

    @Test
    void testExtractSdJwtVpToken_BearerTokenWithSpaces() throws StatusListException {
        // Arrange
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer   token-with-spaces  ");
        
        // Act
        Response response = resource.revokeCredential(
            new CredentialRevocationRequest("test", "reason"), headers);
        
        // Assert
        assertNotNull(response);
        verify(revocationService).revokeCredential(any(), eq("  token-with-spaces  "));
    }
} 
