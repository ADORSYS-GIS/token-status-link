package io.github.adorsysgis.keycloakstatuslist.resource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;

import io.github.adorsysgis.keycloakstatuslist.model.CredentialRevocationResponse;
import io.github.adorsysgis.keycloakstatuslist.model.IssuedCredentialStatusResponse;
import io.github.adorsysgis.keycloakstatuslist.model.IssuedCredentialStatusResponse.IssuedCredentialStatus;
import io.github.adorsysgis.keycloakstatuslist.service.CredentialRevocationService;
import jakarta.ws.rs.core.Response;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class IssuedCredentialStatusEndpointTest {

    @Mock
    private KeycloakSession session;

    @Mock
    private UserModel user;

    @Mock
    private ClientModel client;

    private TestableIssuedCredentialStatusEndpoint endpoint;
    private FakeCredentialRevocationService credentialRevocationService;

    @BeforeEach
    void setUp() {
        credentialRevocationService = new FakeCredentialRevocationService();
        endpoint = new TestableIssuedCredentialStatusEndpoint(session, credentialRevocationService);
    }

    @Test
    void shouldReturnAuthenticatedUsersIssuedCredentialStatuses() {
        AuthResult authResult = new AuthResult(user, null, null, client);
        endpoint.authResult = authResult;
        credentialRevocationService.response = new IssuedCredentialStatusResponse(List.of(new IssuedCredentialStatus(
                "issued-1", "PidCredential", 123L, 456L, "wallet-client", "revision-1", "VALID")));

        Response response = endpoint.getIssuedCredentialStatuses();

        assertEquals(200, response.getStatus());
        assertInstanceOf(IssuedCredentialStatusResponse.class, response.getEntity());
        IssuedCredentialStatusResponse entity = (IssuedCredentialStatusResponse) response.getEntity();
        assertEquals(1, entity.credentials().size());
        assertEquals("issued-1", entity.credentials().get(0).credentialId());
        assertEquals("VALID", entity.credentials().get(0).status());
        assertEquals(authResult, credentialRevocationService.lastAuthResult);
    }

    @Test
    void shouldReturnUnauthorizedWhenBearerTokenIsInvalid() {
        endpoint.authResult = null;

        Response response = endpoint.getIssuedCredentialStatuses();

        assertEquals(401, response.getStatus());
        assertEquals("Invalid bearer token", ((CredentialRevocationResponse) response.getEntity()).getMessage());
        assertNull(credentialRevocationService.lastAuthResult);
    }

    @Test
    void shouldReturnUnauthorizedWhenBearerTokenHasNoUser() {
        endpoint.authResult = new AuthResult(null, null, null, client);

        Response response = endpoint.getIssuedCredentialStatuses();

        assertEquals(401, response.getStatus());
        assertEquals("Invalid bearer token", ((CredentialRevocationResponse) response.getEntity()).getMessage());
        assertNull(credentialRevocationService.lastAuthResult);
    }

    @Test
    void shouldMapIllegalArgumentExceptionToBadRequest() {
        endpoint.authResult = new AuthResult(user, null, null, client);
        credentialRevocationService.illegalArgumentException = new IllegalArgumentException("bad request");

        Response response = endpoint.getIssuedCredentialStatuses();

        assertEquals(400, response.getStatus());
        assertEquals("bad request", ((CredentialRevocationResponse) response.getEntity()).getMessage());
    }

    @Test
    void shouldMapUnexpectedExceptionToServerError() {
        endpoint.authResult = new AuthResult(user, null, null, client);
        credentialRevocationService.runtimeException = new RuntimeException("boom");

        Response response = endpoint.getIssuedCredentialStatuses();

        assertEquals(500, response.getStatus());
        assertEquals(
                "Internal error during status lookup",
                ((CredentialRevocationResponse) response.getEntity()).getMessage());
    }

    private static final class TestableIssuedCredentialStatusEndpoint extends IssuedCredentialStatusEndpoint {
        private AuthResult authResult;

        private TestableIssuedCredentialStatusEndpoint(
                KeycloakSession session, CredentialRevocationService credentialRevocationService) {
            super(session, credentialRevocationService);
        }

        @Override
        protected AuthResult authenticateBearerToken() {
            return authResult;
        }

        @Override
        protected Response addCors(AuthResult authResult, Response.ResponseBuilder responseBuilder) {
            return responseBuilder.build();
        }
    }

    private static final class FakeCredentialRevocationService extends CredentialRevocationService {
        private AuthResult lastAuthResult;
        private IssuedCredentialStatusResponse response = new IssuedCredentialStatusResponse(List.of());
        private IllegalArgumentException illegalArgumentException;
        private RuntimeException runtimeException;

        private FakeCredentialRevocationService() {
            super(null, null, null);
        }

        @Override
        public IssuedCredentialStatusResponse getIssuedCredentialStatuses(AuthResult authResult) {
            this.lastAuthResult = authResult;
            if (illegalArgumentException != null) {
                throw illegalArgumentException;
            }
            if (runtimeException != null) {
                throw runtimeException;
            }
            return response;
        }
    }
}
