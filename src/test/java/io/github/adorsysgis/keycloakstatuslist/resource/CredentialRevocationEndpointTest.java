package io.github.adorsysgis.keycloakstatuslist.resource;

import static io.github.adorsysgis.keycloakstatuslist.model.CredentialRevocationRequest.CREDENTIAL_ID_KEY;
import static io.github.adorsysgis.keycloakstatuslist.model.CredentialRevocationRequest.ISSUED_CREDENTIAL_REVOCATION_MODE;
import static io.github.adorsysgis.keycloakstatuslist.model.CredentialRevocationRequest.REVOCATION_MODE_KEY;
import static io.github.adorsysgis.keycloakstatuslist.model.CredentialRevocationRequest.REVOCATION_REASON_KEY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import io.github.adorsysgis.keycloakstatuslist.exception.StatusListException;
import io.github.adorsysgis.keycloakstatuslist.model.CredentialRevocationRequest;
import io.github.adorsysgis.keycloakstatuslist.model.CredentialRevocationResponse;
import io.github.adorsysgis.keycloakstatuslist.service.CredentialRevocationService;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.time.Instant;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientProvider;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.cors.Cors;
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
    private HttpHeaders headers;

    @Mock
    private RealmModel realm;

    @Mock
    private ClientProvider clientProvider;

    @Mock
    private Cors cors;

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
        endpoint = new TestableCredentialRevocationEndpoint(session, revocationService, cors);
        lenient().when(httpRequest.getHttpHeaders()).thenReturn(headers);
        lenient().when(headers.getRequestHeaders()).thenReturn(new MultivaluedHashMap<>());
        lenient()
                .when(cors.checkAllowedOrigins(org.mockito.ArgumentMatchers.anyList()))
                .thenReturn(cors);
        lenient()
                .when(cors.allowedMethods(org.mockito.ArgumentMatchers.<String[]>any()))
                .thenReturn(cors);
        lenient().when(cors.preflight()).thenReturn(cors);
        lenient().when(cors.auth()).thenReturn(cors);
        lenient()
                .when(cors.add(org.mockito.ArgumentMatchers.any(Response.ResponseBuilder.class)))
                .thenAnswer(invocation ->
                        invocation.<Response.ResponseBuilder>getArgument(0).build());
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
                "Credential revocation service is misconfigured",
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
                "Credential revocation service is misconfigured",
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
                "Credential revocation service is misconfigured",
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
    void shouldAddConfiguredOriginToSuccessfulRevocationResponse() throws Exception {
        String origin = "http://frontend.example";
        ClientModel client = clientWithOrigins(origin);
        UserModel user = org.mockito.Mockito.mock(UserModel.class);
        endpoint.authResult = new AuthResult(user, null, null, client);
        setRequestOrigin(origin);
        setIssuedCredentialRevocationForm("issued-credential-1", "user-request");

        Response response = endpoint.revoke();

        assertEquals(200, response.getStatus());
        verify(cors).checkAllowedOrigins(Set.of(origin).stream().toList());
        verify(cors).auth();
        verify(cors).add(org.mockito.ArgumentMatchers.any(Response.ResponseBuilder.class));
    }

    @Test
    void shouldNotAuthorizeAnOriginOutsideClientWebOrigins() throws Exception {
        String origin = "https://attacker.example";
        ClientModel client = clientWithOrigins("https://trusted.example");
        endpoint.authResult = new AuthResult(org.mockito.Mockito.mock(UserModel.class), null, null, client);
        setRequestOrigin(origin);
        setIssuedCredentialRevocationForm("issued-credential-1", "user-request");
        doAnswer(invocation -> {
                    if (!invocation.<java.util.List<String>>getArgument(0).contains(origin)) {
                        throw new ForbiddenException();
                    }
                    return cors;
                })
                .when(cors)
                .checkAllowedOrigins(org.mockito.ArgumentMatchers.anyList());

        assertThrows(ForbiddenException.class, endpoint::revoke);

        verify(cors)
                .checkAllowedOrigins(Set.of("https://trusted.example").stream().toList());
        assertNoRevocationAttempt();
        verify(cors, never()).add(org.mockito.ArgumentMatchers.any(Response.ResponseBuilder.class));
    }

    @Test
    void shouldAnswerPreflightOnlyForConfiguredOrigins() {
        String origin = "http://frontend.example";
        ClientModel client = clientWithOrigins(origin);
        when(session.clients()).thenReturn(clientProvider);
        when(clientProvider.getClientsStream(realm)).thenReturn(Stream.of(client));
        setRequestOrigin(origin);

        Response response = endpoint.preflight();

        assertEquals(200, response.getStatus());
        verify(cors).checkAllowedOrigins(Set.of(origin).stream().toList());
        verify(cors).allowedMethods("POST");
        verify(cors).preflight();
        verify(cors).auth();
        verify(cors).add(org.mockito.ArgumentMatchers.any(Response.ResponseBuilder.class));
    }

    @Test
    void shouldNotAddPreflightCorsHeadersForUnconfiguredOrigin() {
        ClientModel client = clientWithOrigins("https://trusted.example");
        when(session.clients()).thenReturn(clientProvider);
        when(clientProvider.getClientsStream(realm)).thenReturn(Stream.of(client));
        setRequestOrigin("https://attacker.example");

        Response response = endpoint.preflight();

        assertEquals(200, response.getStatus());
        verify(cors, never()).add(org.mockito.ArgumentMatchers.any(Response.ResponseBuilder.class));
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

    private void setRequestOrigin(String origin) {
        headers.getRequestHeaders().putSingle(Cors.ORIGIN_HEADER, origin);
    }

    private ClientModel clientWithOrigins(String... origins) {
        ClientModel client = org.mockito.Mockito.mock(ClientModel.class);
        when(client.getWebOrigins()).thenReturn(Set.of(origins));
        return client;
    }

    private static final class TestableCredentialRevocationEndpoint extends CredentialRevocationEndpoint {
        private AuthResult authResult;
        private final Cors cors;

        private TestableCredentialRevocationEndpoint(
                KeycloakSession session, CredentialRevocationService revocationService, Cors cors) {
            super(session, revocationService);
            this.cors = cors;
        }

        @Override
        protected AuthResult authenticateBearerToken() {
            return authResult;
        }

        @Override
        protected Cors cors() {
            return cors;
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
