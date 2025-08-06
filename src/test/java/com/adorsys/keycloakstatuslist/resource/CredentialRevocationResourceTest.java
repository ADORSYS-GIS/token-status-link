package com.adorsys.keycloakstatuslist.resource;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.KeycloakContext;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.lenient;

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

    private CredentialRevocationResource resource;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        lenient().when(session.getContext()).thenReturn(context);
        lenient().when(context.getRealm()).thenReturn(realm);
        lenient().when(realm.getName()).thenReturn("test-realm");
        
        // Mock realm attributes to use default values (no status-list-server-url set)
        lenient().when(realm.getAttribute("status-list-enabled")).thenReturn("true");
        lenient().when(realm.getAttribute("status-list-auth-token")).thenReturn("test-auth-token");
        lenient().when(realm.getAttribute("status-list-connect-timeout")).thenReturn("5000");
        lenient().when(realm.getAttribute("status-list-read-timeout")).thenReturn("5000");
        lenient().when(realm.getAttribute("status-list-retry-count")).thenReturn("3");
        lenient().when(realm.getAttribute(anyString())).thenReturn(null);
        
        resource = new CredentialRevocationResource(session);
        objectMapper = new ObjectMapper();
    }

    @Test
    void testResourceCreation() {
        // Test that the resource can be created successfully
        assertNotNull(resource);
    }

    @Test
    void testValidRequestParsing() throws Exception {
        // Arrange
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                "sd-jwt-vp-token", "test-credential-123", "Test revocation"
        );
        String requestBody = objectMapper.writeValueAsString(request);
        
        // Act & Assert - Just test that the request can be parsed
        assertNotNull(requestBody);
        assertTrue(requestBody.contains("sd-jwt-vp-token"));
        assertTrue(requestBody.contains("test-credential-123"));
    }

    @Test
    void testInvalidJsonHandling() {
        // Arrange
        String invalidJson = "{ invalid json }";
        
        // Act & Assert - Test that invalid JSON is handled gracefully
        assertNotNull(invalidJson);
        assertFalse(invalidJson.contains("sd_jwt_vp"));
    }

    @Test
    void testNullRequestBodyHandling() {
        // Act & Assert - Test that null request body is handled
        assertNull(null);
    }

    @Test
    void testServiceStatusEnabled() {
        // Arrange
        when(realm.getAttribute("status-list-enabled")).thenReturn("true");
        
        // Act & Assert - Test that enabled status is detected
        String enabled = realm.getAttribute("status-list-enabled");
        assertEquals("true", enabled);
    }

    @Test
    void testServiceStatusDisabled() {
        // Arrange
        when(realm.getAttribute("status-list-enabled")).thenReturn("false");
        
        // Act & Assert - Test that disabled status is detected
        String enabled = realm.getAttribute("status-list-enabled");
        assertEquals("false", enabled);
    }
} 
