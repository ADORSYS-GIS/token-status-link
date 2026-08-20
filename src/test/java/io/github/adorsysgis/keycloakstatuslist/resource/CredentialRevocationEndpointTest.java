package io.github.adorsysgis.keycloakstatuslist.resource;

import static io.github.adorsysgis.keycloakstatuslist.model.CredentialRevocationRequest.CREDENTIAL_ID_KEY;
import static io.github.adorsysgis.keycloakstatuslist.model.CredentialRevocationRequest.ISSUED_CREDENTIAL_REVOCATION_MODE;
import static io.github.adorsysgis.keycloakstatuslist.model.CredentialRevocationRequest.REVOCATION_MODE_KEY;
import static io.github.adorsysgis.keycloakstatuslist.model.CredentialRevocationRequest.REVOCATION_REASON_KEY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import io.github.adorsysgis.keycloakstatuslist.exception.StatusListException;
import io.github.adorsysgis.keycloakstatuslist.model.CredentialRevocationRequest;
import io.github.adorsysgis.keycloakstatuslist.model.CredentialRevocationResponse;
import io.github.adorsysgis.keycloakstatuslist.service.CredentialRevocationService;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.events.EventBuilder;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class CredentialRevocationEndpointTest {

    @Mock
    private KeycloakSession session;

    @Mock
    private KeycloakContext context;

    @Mock
    private HttpRequest httpRequest;

    @Mock
    private RealmModel realm;

    @Mock
    private EventBuilder eventBuilder;

    private TestableCredentialRevocationEndpoint endpoint;
    private FakeCredentialRevocationService revocationService;

    @BeforeEach
    void setUp() {
        when(session.getContext()).thenReturn(context);
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(context.getRealm()).thenReturn(realm);

        lenient().when(realm.getAttribute(StatusListConfig.STATUS_LIST_ENABLED)).thenReturn("true");
        lenient()
                .when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL))
                .thenReturn("https://status.example.com");

        revocationService = new FakeCredentialRevocationService();
        endpoint = new TestableCredentialRevocationEndpoint(session, eventBuilder, revocationService);
    }

    @Test
    void shouldReturnServerErrorWhenServiceIsDisabled() {
        setIssuedCredentialRevocationForm("issued-credential-1", "manual-check");
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_ENABLED)).thenReturn("false");

        Response response = endpoint.revoke();

        assertEquals(500, response.getStatus());
        assertEquals(
                "Credential revocation service is disabled",
                ((CredentialRevocationResponse) response.getEntity()).getMessage());
        assertNoRevocationAttempt();
    }

    @Test
    void shouldReturnServerErrorWhenServiceEnabledCheckFails() {
        setIssuedCredentialRevocationForm("issued-credential-1", "manual-check");
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_ENABLED))
                .thenThrow(new RuntimeException("realm misconfigured"));

        Response response = endpoint.revoke();

        assertEquals(500, response.getStatus());
        assertEquals(
                "Credential revocation service is disabled",
                ((CredentialRevocationResponse) response.getEntity()).getMessage());
        assertNoRevocationAttempt();
    }

    @Test
    void shouldReturnServerErrorWhenServiceIsNotConfigured() {
        setIssuedCredentialRevocationForm("issued-credential-1", "manual-check");
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL)).thenReturn(" ");

        Response response = endpoint.revoke();

        assertEquals(500, response.getStatus());
        assertEquals(
                "Credential revocation service is not configured",
                ((CredentialRevocationResponse) response.getEntity()).getMessage());
        assertNoRevocationAttempt();
    }

    @Test
    void shouldReturnServerErrorWhenServiceConfigurationCheckFails() {
        setIssuedCredentialRevocationForm("issued-credential-1", "manual-check");
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_ENABLED)).thenReturn("true");
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL))
                .thenThrow(new RuntimeException("missing attribute"));

        Response response = endpoint.revoke();

        assertEquals(500, response.getStatus());
        assertEquals(
                "Credential revocation service is not configured",
                ((CredentialRevocationResponse) response.getEntity()).getMessage());
        assertNoRevocationAttempt();
    }

    @Test
    void shouldRevokeIssuedCredentialInIssuedCredentialMode() throws Exception {
        UserModel user = org.mockito.Mockito.mock(UserModel.class);
        AuthResult authResult = new AuthResult(user, null, null, null);
        endpoint.authResult = authResult;
        setIssuedCredentialRevocationForm("issued-credential-1", "user-request");
        revocationService.response = CredentialRevocationResponse.success(Instant.now(), "user-request");

        Response response = endpoint.revoke();

        assertEquals(200, response.getStatus());
        assertInstanceOf(CredentialRevocationResponse.class, response.getEntity());
        assertTrue(((CredentialRevocationResponse) response.getEntity()).isSuccess());

        assertEquals(authResult, revocationService.lastAuthResult);
        CredentialRevocationRequest capturedRequest = revocationService.lastRequest;
        assertNotNull(capturedRequest);
        assertEquals(ISSUED_CREDENTIAL_REVOCATION_MODE, capturedRequest.getRevocationMode());
        assertEquals("user-request", capturedRequest.getRevocationReason());
        assertEquals("issued-credential-1", capturedRequest.getCredentialId());
    }

    @Test
    void shouldReturnUnauthorizedWhenBearerTokenIsInvalid() {
        endpoint.authResult = null;
        setIssuedCredentialRevocationForm("issued-credential-1", "user-request");

        Response response = endpoint.revoke();

        assertEquals(401, response.getStatus());
        assertEquals("Invalid bearer token", ((CredentialRevocationResponse) response.getEntity()).getMessage());
        assertNoRevocationAttempt();
    }

    @Test
    void shouldReturnUnauthorizedWhenBearerTokenHasNoUser() {
        endpoint.authResult = new AuthResult(null, null, null, null);
        setIssuedCredentialRevocationForm("issued-credential-1", "user-request");

        Response response = endpoint.revoke();

        assertEquals(401, response.getStatus());
        assertEquals("Invalid bearer token", ((CredentialRevocationResponse) response.getEntity()).getMessage());
        assertNoRevocationAttempt();
    }

    @Test
    void shouldMapStatusListExceptionToConfiguredHttpStatus() throws Exception {
        UserModel user = org.mockito.Mockito.mock(UserModel.class);
        endpoint.authResult = new AuthResult(user, null, null, null);
        setIssuedCredentialRevocationForm("issued-credential-1", "status-list-error");
        revocationService.statusListException = new StatusListException("unprocessable", 422);

        Response response = endpoint.revoke();

        assertEquals(422, response.getStatus());
        assertInstanceOf(CredentialRevocationResponse.class, response.getEntity());
        assertEquals("unprocessable", ((CredentialRevocationResponse) response.getEntity()).getMessage());
    }

    @Test
    void shouldMapIllegalArgumentExceptionToBadRequest() throws Exception {
        UserModel user = org.mockito.Mockito.mock(UserModel.class);
        endpoint.authResult = new AuthResult(user, null, null, null);
        setIssuedCredentialRevocationForm("issued-credential-1", "bad-request");
        revocationService.illegalArgumentException = new IllegalArgumentException("Malformed request");

        Response response = endpoint.revoke();

        assertEquals(400, response.getStatus());
        assertEquals("Malformed request", ((CredentialRevocationResponse) response.getEntity()).getMessage());
    }

    @Test
    void shouldMapUnexpectedExceptionToInternalServerError() throws Exception {
        UserModel user = org.mockito.Mockito.mock(UserModel.class);
        endpoint.authResult = new AuthResult(user, null, null, null);
        setIssuedCredentialRevocationForm("issued-credential-1", "unexpected");
        revocationService.runtimeException = new RuntimeException("boom");

        Response response = endpoint.revoke();

        assertEquals(500, response.getStatus());
        assertNotNull(response.getEntity());
    }

    private void assertNoRevocationAttempt() {
        assertNull(revocationService.lastRequest);
        assertNull(revocationService.lastAuthResult);
    }

    private void setIssuedCredentialRevocationForm(String credentialId, String reason) {
        MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
        form.add(REVOCATION_MODE_KEY, ISSUED_CREDENTIAL_REVOCATION_MODE);
        form.add(CREDENTIAL_ID_KEY, credentialId);
        form.add(REVOCATION_REASON_KEY, reason);
        when(httpRequest.getDecodedFormParameters()).thenReturn(form);
    }

    private static final class TestableCredentialRevocationEndpoint extends CredentialRevocationEndpoint {
        private AuthResult authResult;

        private TestableCredentialRevocationEndpoint(
                KeycloakSession session, EventBuilder event, CredentialRevocationService revocationService) {
            super(session, event, revocationService);
        }

        @Override
        protected AuthResult authenticateBearerToken() {
            return authResult;
        }
    }

    private static final class FakeCredentialRevocationService extends CredentialRevocationService {
        private CredentialRevocationRequest lastRequest;
        private AuthResult lastAuthResult;
        private CredentialRevocationResponse response = CredentialRevocationResponse.success(Instant.now(), "ok");
        private StatusListException statusListException;
        private IllegalArgumentException illegalArgumentException;
        private RuntimeException runtimeException;

        private FakeCredentialRevocationService() {
            super(null, null, null);
        }

        @Override
        public CredentialRevocationResponse revokeIssuedCredential(
                CredentialRevocationRequest request, AuthResult authResult) throws StatusListException {
            this.lastRequest = request;
            this.lastAuthResult = authResult;
            if (statusListException != null) {
                throw statusListException;
            }
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
