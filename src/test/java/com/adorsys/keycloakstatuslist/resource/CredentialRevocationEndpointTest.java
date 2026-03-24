package com.adorsys.keycloakstatuslist.resource;

import static com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest.CREDENTIAL_REVOCATION_MODE;
import static com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest.REVOCATION_MODE_KEY;
import static com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest.REVOCATION_REASON_KEY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationResponse;
import com.adorsys.keycloakstatuslist.service.CredentialRevocationService;
import jakarta.ws.rs.core.HttpHeaders;
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
    private HttpHeaders headers;

    @Mock
    private RealmModel realm;

    @Mock
    private EventBuilder eventBuilder;

    private CredentialRevocationEndpoint endpoint;
    private FakeCredentialRevocationService revocationService;

    @BeforeEach
    void setUp() {
        when(session.getContext()).thenReturn(context);
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(context.getRequestHeaders()).thenReturn(headers);
        when(context.getRealm()).thenReturn(realm);

        lenient().when(realm.getAttribute(StatusListConfig.STATUS_LIST_ENABLED)).thenReturn("true");
        lenient().when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL)).thenReturn("https://status.example.com");

        revocationService = new FakeCredentialRevocationService();
        endpoint = new CredentialRevocationEndpoint(session, eventBuilder, revocationService);
    }

    @Test
    void shouldExposeChallengeSubResource() {
        Object challengeResource = endpoint.challenge();
        assertInstanceOf(RevocationChallengeResource.class, challengeResource);
    }

    @Test
    void shouldReturnUnauthorizedWhenAuthorizationHeaderMissing() {
        setCredentialRevocationForm("manual-check");
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn(null);

        Response response = endpoint.revoke();

        assertEquals(401, response.getStatus());
        assertInstanceOf(CredentialRevocationResponse.class, response.getEntity());
        assertEquals("Missing Authorization header", ((CredentialRevocationResponse) response.getEntity()).getMessage());
        assertNoRevocationAttempt();
    }

    @Test
    void shouldReturnBadRequestWhenAuthorizationHeaderIsMalformed() {
        setCredentialRevocationForm("manual-check");
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("invalid-format");

        Response response = endpoint.revoke();

        assertEquals(400, response.getStatus());
        assertEquals(
                "Invalid authorization header format",
                ((CredentialRevocationResponse) response.getEntity()).getMessage());
        assertNoRevocationAttempt();
    }

    @Test
    void shouldReturnBadRequestWhenBearerTokenValueIsMissing() {
        setCredentialRevocationForm("manual-check");
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer    ");

        Response response = endpoint.revoke();

        assertEquals(400, response.getStatus());
        assertEquals(
                "Invalid authorization header format",
                ((CredentialRevocationResponse) response.getEntity()).getMessage());
        assertNoRevocationAttempt();
    }

    @Test
    void shouldReturnServerErrorWhenServiceIsDisabled() {
        setCredentialRevocationForm("manual-check");
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_ENABLED)).thenReturn("false");
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer test-token");

        Response response = endpoint.revoke();

        assertEquals(500, response.getStatus());
        assertEquals(
                "Credential revocation service is disabled",
                ((CredentialRevocationResponse) response.getEntity()).getMessage());
        assertNoRevocationAttempt();
    }

    @Test
    void shouldReturnServerErrorWhenServiceEnabledCheckFails() {
        setCredentialRevocationForm("manual-check");
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_ENABLED)).thenThrow(new RuntimeException("realm misconfigured"));
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer test-token");

        Response response = endpoint.revoke();

        assertEquals(500, response.getStatus());
        assertEquals(
                "Credential revocation service is disabled",
                ((CredentialRevocationResponse) response.getEntity()).getMessage());
        assertNoRevocationAttempt();
    }

    @Test
    void shouldReturnServerErrorWhenServiceIsNotConfigured() {
        setCredentialRevocationForm("manual-check");
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL)).thenReturn(" ");
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer test-token");

        Response response = endpoint.revoke();

        assertEquals(500, response.getStatus());
        assertEquals(
                "Credential revocation service is not configured",
                ((CredentialRevocationResponse) response.getEntity()).getMessage());
        assertNoRevocationAttempt();
    }

    @Test
    void shouldReturnServerErrorWhenServiceConfigurationCheckFails() {
        setCredentialRevocationForm("manual-check");
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_ENABLED)).thenReturn("true");
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL)).thenThrow(new RuntimeException("missing attribute"));
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer test-token");

        Response response = endpoint.revoke();

        assertEquals(500, response.getStatus());
        assertEquals(
                "Credential revocation service is not configured",
                ((CredentialRevocationResponse) response.getEntity()).getMessage());
        assertNoRevocationAttempt();
    }

    @Test
    void shouldRevokeCredentialInCredentialMode() throws Exception {
        setCredentialRevocationForm("test-reason");
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer   test-token  ");
        revocationService.response = CredentialRevocationResponse.success(Instant.now(), "test-reason");

        Response response = endpoint.revoke();

        assertEquals(200, response.getStatus());
        assertInstanceOf(CredentialRevocationResponse.class, response.getEntity());
        assertTrue(((CredentialRevocationResponse) response.getEntity()).isSuccess());

        assertEquals("test-token", revocationService.lastToken);
        CredentialRevocationRequest capturedRequest = revocationService.lastRequest;
        assertNotNull(capturedRequest);
        assertEquals(CREDENTIAL_REVOCATION_MODE, capturedRequest.getRevocationMode());
        assertEquals("test-reason", capturedRequest.getRevocationReason());
    }

    @Test
    void shouldMapStatusListExceptionToConfiguredHttpStatus() throws Exception {
        setCredentialRevocationForm("status-list-error");
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer test-token");
        revocationService.statusListException = new StatusListException("unprocessable", 422);

        Response response = endpoint.revoke();

        assertEquals(422, response.getStatus());
        assertInstanceOf(CredentialRevocationResponse.class, response.getEntity());
        assertEquals("unprocessable", ((CredentialRevocationResponse) response.getEntity()).getMessage());
    }

    @Test
    void shouldMapIllegalArgumentExceptionToBadRequest() throws Exception {
        setCredentialRevocationForm("bad-vp");
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer test-token");
        revocationService.illegalArgumentException = new IllegalArgumentException("Malformed VP");

        Response response = endpoint.revoke();

        assertEquals(400, response.getStatus());
        assertEquals("Malformed VP", ((CredentialRevocationResponse) response.getEntity()).getMessage());
    }

    @Test
    void shouldMapUnexpectedExceptionToInternalServerError() throws Exception {
        setCredentialRevocationForm("unexpected");
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer test-token");
        revocationService.runtimeException = new RuntimeException("boom");

        Response response = endpoint.revoke();

        assertEquals(500, response.getStatus());
        assertNotNull(response.getEntity());
    }

    private void assertNoRevocationAttempt() {
        assertNull(revocationService.lastRequest);
        assertNull(revocationService.lastToken);
    }

    private void setCredentialRevocationForm(String reason) {
        MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
        form.add(REVOCATION_MODE_KEY, CREDENTIAL_REVOCATION_MODE);
        form.add(REVOCATION_REASON_KEY, reason);
        when(httpRequest.getDecodedFormParameters()).thenReturn(form);
    }

    private static final class FakeCredentialRevocationService extends CredentialRevocationService {
        private CredentialRevocationRequest lastRequest;
        private String lastToken;
        private CredentialRevocationResponse response = CredentialRevocationResponse.success(Instant.now(), "ok");
        private StatusListException statusListException;
        private IllegalArgumentException illegalArgumentException;
        private RuntimeException runtimeException;

        private FakeCredentialRevocationService() {
            super(null, null, null);
        }

        @Override
        public CredentialRevocationResponse revokeCredential(CredentialRevocationRequest request, String sdJwtVpToken)
                throws StatusListException {
            this.lastRequest = request;
            this.lastToken = sdJwtVpToken;
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
