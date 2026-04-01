package com.adorsys.keycloakstatuslist.resource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.adorsys.keycloakstatuslist.model.RevocationChallenge;
import com.adorsys.keycloakstatuslist.service.nonce.NonceCacheService;
import com.adorsys.keycloakstatuslist.service.nonce.NonceCacheServiceProviderFactory;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.services.Urls;
import org.keycloak.services.resource.RealmResourceProvider;

class RevocationChallengeResourceTest {

    private KeycloakSession session;
    private KeycloakContext context;
    private RealmModel realm;
    private KeycloakUriInfo uriInfo;
    private NonceCacheService nonceCacheService;

    private RevocationChallengeResource resource;

    @BeforeEach
    void setUp() {
        session = mock(KeycloakSession.class);
        context = mock(KeycloakContext.class);
        realm = mock(RealmModel.class);
        uriInfo = mock(KeycloakUriInfo.class);
        nonceCacheService = new NonceCacheService();

        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realm);
        when(context.getUri()).thenReturn(uriInfo);
        when(realm.getName()).thenReturn("test-realm");
        when(uriInfo.getBaseUri()).thenReturn(URI.create("https://issuer.example.com/"));

        resource = new RevocationChallengeResource(session);
    }

    @Test
    void shouldReturnChallengeWhenNonceProviderIsAvailable() {
        String expectedAudience = Urls.realmIssuer(URI.create("https://issuer.example.com/"), "test-realm")
                + "/protocol/openid-connect/revoke";

        when(session.getProvider(RealmResourceProvider.class, NonceCacheServiceProviderFactory.PROVIDER_ID))
                .thenReturn(nonceCacheService);

        Response response = resource.getChallenge();

        assertEquals(200, response.getStatus());
        assertInstanceOf(RevocationChallenge.class, response.getEntity());

        RevocationChallenge responseChallenge = (RevocationChallenge) response.getEntity();
        assertNotNull(responseChallenge.getNonce());
        assertEquals(expectedAudience, responseChallenge.getAudience());
        assertTrue(responseChallenge.getExpiresAt() > 0);
    }

    @Test
    void shouldReturnServerErrorWhenNonceProviderIsMissing() {
        when(session.getProvider(RealmResourceProvider.class, NonceCacheServiceProviderFactory.PROVIDER_ID))
                .thenReturn(null);

        Response response = resource.getChallenge();

        assertEquals(500, response.getStatus());
        assertInstanceOf(Map.class, response.getEntity());

        @SuppressWarnings("unchecked")
        Map<String, String> body = (Map<String, String>) response.getEntity();
        assertEquals("Nonce service not available", body.get("error"));
    }

    @Test
    void shouldReturnServerErrorWhenNonceIssuanceThrows() {
        when(session.getProvider(RealmResourceProvider.class, NonceCacheServiceProviderFactory.PROVIDER_ID))
                .thenReturn(new ThrowingNonceCacheService());

        Response response = resource.getChallenge();

        assertEquals(500, response.getStatus());
        assertInstanceOf(Map.class, response.getEntity());

        @SuppressWarnings("unchecked")
        Map<String, String> body = (Map<String, String>) response.getEntity();
        assertNotNull(body.get("error"));
        assertTrue(body.get("error").contains("Failed to issue challenge"));
    }

    private static final class ThrowingNonceCacheService extends NonceCacheService {
        @Override
        public RevocationChallenge issueNonce(String audience) {
            throw new RuntimeException("cache unavailable");
        }
    }
}
