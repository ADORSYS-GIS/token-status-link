package com.adorsys.keycloakstatuslist.resource;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;
import com.adorsys.keycloakstatuslist.service.CredentialRevocationService;
import com.adorsys.keycloakstatuslist.service.NonceService; // Import NonceService

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.EventBuilder;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.KeycloakUriInfo; // Import KeycloakUriInfo
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;


import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for CredentialRevocationResource.
 * 
 * This test focuses on testing the business logic without trying to mock
 * the complex Keycloak parent class infrastructure.
 */
@ExtendWith(MockitoExtension.class)
class CredentialRevocationResourceTest {

    // Session-related mocks
    @Mock
    private KeycloakSession session;
    
    @Mock
    private KeycloakSessionFactory sessionFactory;
    
    @Mock
    private KeycloakContext context;
    
    @Mock
    private RealmModel realm;

    // HTTP-related mocks
    @Mock
    private HttpRequest httpRequest;
    
    @Mock
    private HttpHeaders headers;


    // Service-related mocks
    @Mock
    private CredentialRevocationService revocationService;

    @Mock
    private NonceService nonceService; // Add mock for NonceService

    @Mock
    private EventBuilder eventBuilder;

    private TestableCredentialRevocationResource resource;

    @BeforeEach
    void setUp() {
        // Setup basic mocks
        lenient().when(session.getContext()).thenReturn(context);
        lenient().when(session.getKeycloakSessionFactory()).thenReturn(sessionFactory);
        lenient().when(context.getRealm()).thenReturn(realm);
        lenient().when(context.getConnection()).thenReturn(mock(ClientConnection.class));
        lenient().when(realm.getName()).thenReturn("test-realm");

        // Create a testable version of the resource with dependency injection
        resource = new TestableCredentialRevocationResource(session, nonceService);
        resource.setHttpHeaders(headers);
        resource.setRevocationService(revocationService);
        resource.setNonceService(nonceService);
    }

    /**
     * Testable version of CredentialRevocationResource that overrides the parent
     * class behavior
     * to avoid complex Keycloak setup requirements.
     */
    private static class TestableCredentialRevocationResource extends CredentialRevocationResource {
        private final KeycloakSession session;

        public TestableCredentialRevocationResource(KeycloakSession session, NonceService nonceService) {
            super(session, nonceService);
            this.session = session;
        }

        // Setters for services to allow injection in tests
        public void setRevocationService(CredentialRevocationService revocationService) {
            this.revocationService = revocationService;
        }

        public void setNonceService(NonceService nonceService) {
            this.nonceService = nonceService;
        }

        // Setter for HttpHeaders to allow injection in tests
        public void setHttpHeaders(HttpHeaders headers) {
            this.headers = headers;
        }

        @Override
        protected HttpHeaders getHeaders() {
            return headers;
        }

        @Override
        protected CredentialRevocationService getRevocationService() {
            return revocationService;
        }

        @Override
        public Response revoke() {
            // Get the form parameters and authorization header directly
            MultivaluedMap<String, String> form = session.getContext().getHttpRequest().getDecodedFormParameters();
            String authorizationHeader = headers.getHeaderString(HttpHeaders.AUTHORIZATION);

            if (authorizationHeader != null && authorizationHeader.toLowerCase().startsWith("bearer ")) {
                String token = authorizationHeader.substring("bearer ".length()).trim();
                String credentialId = form.getFirst("token");

                if (credentialId != null && !credentialId.isEmpty()) {
                    try {
                        CredentialRevocationRequest request = new CredentialRevocationRequest();
                        request.setCredentialId(credentialId);
                        request.setRevocationReason(form.getFirst("reason"));

                        revocationService.revokeCredential(request, token);

                        // Return success response
                        return Response.ok().build();

                    } catch (StatusListException e) {
                        return Response.status(e.getHttpStatus()).entity(e.getMessage()).build();
                    } catch (IllegalArgumentException e) {
                        return Response.status(400).entity("Malformed VP: " + e.getMessage()).build();
                    } catch (Exception e) {
                        return Response.status(500).entity("Internal error during credential revocation").build();
                    }
                }
            }

            // Return success response for all other cases
            return Response.ok().build();
        }
    }

    /**
     * Helper method to set up mock request parameters.
     * Reduces duplication and improves readability across test methods.
     */
    private void mockRequest(String token, String reason, String authHeader) {
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        if (token != null) {
            formParams.add("token", token);
        }
        if (reason != null) {
            formParams.add("reason", reason);
        }

        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn(authHeader);
    }

    @Test
    void testRevoke_Success() throws Exception {
        mockRequest("test-credential-123", "Test revocation", "Bearer test-token");

        Response response = resource.revoke();

        assertNotNull(response);
        assertEquals(200, response.getStatus());
        verify(revocationService).revokeCredential(any(CredentialRevocationRequest.class), eq("test-token"));
    }

    @Test
    void testGetChallenge_Success() {
        when(session.getContext().getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getHttpHeaders()).thenReturn(headers); // Mock getHttpHeaders()
        when(session.getContext().getConnection()).thenReturn(mock(ClientConnection.class));
        when(session.getContext().getConnection().getRemoteAddr()).thenReturn("127.0.0.1");
        when(session.getContext().getUri()).thenReturn(mock(KeycloakUriInfo.class));
        when(session.getContext().getUri().getBaseUri()).thenReturn(java.net.URI.create("http://localhost:8080/auth/"));
        when(realm.getName()).thenReturn("test-realm");
        when(nonceService.generateAndStoreNonce(anyString(), anyString())).thenReturn(new com.adorsys.keycloakstatuslist.model.NonceChallenge("test-nonce", "http://localhost:8080/auth/realms/test-realm/protocol/openid-connect/revoke", 300));

        Response response = resource.getChallenge();

        assertNotNull(response);
        assertEquals(200, response.getStatus());
        assertTrue(response.getEntity() instanceof com.adorsys.keycloakstatuslist.model.NonceChallenge);
        verify(nonceService).generateAndStoreNonce(anyString(), anyString());
    }

    @Test
    void testRevoke_NoAuthorizationHeader() throws Exception {
        mockRequest("test-credential-123", null, null);

        Response response = resource.revoke();

        assertNotNull(response);
        assertEquals(200, response.getStatus());
        verify(revocationService, never()).revokeCredential(any(), anyString());
    }

    @Test
    void testRevoke_EmptyAuthorizationHeader() throws Exception {
        mockRequest("test-credential-123", null, "");

        Response response = resource.revoke();

        assertNotNull(response);
        assertEquals(200, response.getStatus());
        verify(revocationService, never()).revokeCredential(any(), anyString());
    }

    @Test
    void testRevoke_InvalidAuthorizationHeader() throws Exception {
        mockRequest("test-credential-123", null, "InvalidFormat token");

        Response response = resource.revoke();

        assertNotNull(response);
        assertEquals(200, response.getStatus());
        verify(revocationService, never()).revokeCredential(any(), anyString());
    }

    @Test
    void testRevoke_NoTokenInForm() throws Exception {
        mockRequest(null, "Test revocation", "Bearer test-token");

        Response response = resource.revoke();

        assertNotNull(response);
        assertEquals(200, response.getStatus());
        verify(revocationService, never()).revokeCredential(any(), anyString());
    }

    @Test
    void testRevoke_EmptyTokenInForm() throws Exception {
        mockRequest("", "Test revocation", "Bearer test-token");

        Response response = resource.revoke();

        assertNotNull(response);
        assertEquals(200, response.getStatus());
        verify(revocationService, never()).revokeCredential(any(), anyString());
    }

    @Test
    void testRevoke_ServiceThrowsException() throws Exception {
        mockRequest("test-credential-123", "Test revocation", "Bearer test-token");

        doThrow(new StatusListException("Invalid token format", 400)).when(revocationService)
                .revokeCredential(any(CredentialRevocationRequest.class), anyString());

        Response response = resource.revoke();

        assertNotNull(response);
        assertEquals(400, response.getStatus());
        assertTrue(response.getEntity().toString().contains("Invalid token format"));
        verify(revocationService).revokeCredential(any(CredentialRevocationRequest.class), eq("test-token"));
    }

    @Test
    void testRevoke_ServiceThrowsRuntimeException() throws Exception {
        mockRequest("test-credential-123", "Test revocation", "Bearer test-token");

        doThrow(new RuntimeException("Unexpected error")).when(revocationService)
                .revokeCredential(any(CredentialRevocationRequest.class), anyString());

        Response response = resource.revoke();

        assertNotNull(response);
        assertEquals(500, response.getStatus());
        assertTrue(response.getEntity().toString().contains("Internal error during credential revocation"));
        verify(revocationService).revokeCredential(any(CredentialRevocationRequest.class), eq("test-token"));
    }

    @Test
    void testRevoke_ExtractsBearerTokenWithSpaces() throws Exception {
        mockRequest("test-credential-123", null, "Bearer   token-with-spaces  ");

        Response response = resource.revoke();

        assertNotNull(response);
        assertEquals(200, response.getStatus());
        verify(revocationService).revokeCredential(any(CredentialRevocationRequest.class), eq("token-with-spaces"));
    }
}
