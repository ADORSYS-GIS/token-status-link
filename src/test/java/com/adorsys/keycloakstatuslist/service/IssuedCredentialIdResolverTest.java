package com.adorsys.keycloakstatuslist.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.keycloak.OID4VCConstants.OPENID_CREDENTIAL;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import com.adorsys.keycloakstatuslist.helpers.MockKeycloakTest;
import jakarta.ws.rs.core.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

class IssuedCredentialIdResolverTest extends MockKeycloakTest {

    @Mock
    private HttpHeaders headers;

    private IssuedCredentialIdResolver resolver;

    @BeforeEach
    void setUp() {
        resolver = new IssuedCredentialIdResolver(session);
        lenient().when(context.getRequestHeaders()).thenReturn(headers);
    }

    @Test
    void shouldResolveIssuedCredentialIdFromBearerAccessToken() {
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION))
                .thenReturn("Bearer " + accessTokenWithIssuedCredentialId("issued-credential-1"));

        assertEquals("issued-credential-1", resolver.resolve().orElseThrow());
    }

    @Test
    void shouldResolveIssuedCredentialIdFromDpopAccessToken() {
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION))
                .thenReturn("DPoP " + accessTokenWithIssuedCredentialId("issued-credential-1"));

        assertEquals("issued-credential-1", resolver.resolve().orElseThrow());
    }

    @Test
    void shouldReturnEmptyWhenAuthorizationHeaderIsMissing() {
        assertTrue(resolver.resolve().isEmpty());
    }

    @Test
    void shouldReturnEmptyWhenAuthorizationSchemeIsUnsupported() {
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION))
                .thenReturn("Basic " + accessTokenWithIssuedCredentialId("issued-credential-1"));

        assertTrue(resolver.resolve().isEmpty());
    }

    @Test
    void shouldReturnEmptyWhenTokenIsMalformed() {
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer not-a-token");

        assertTrue(resolver.resolve().isEmpty());
    }

    @Test
    void shouldReturnEmptyWhenIssuedCredentialIdIsMissing() {
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer " + accessTokenWithoutIssuedId());

        assertTrue(resolver.resolve().isEmpty());
    }

    private String accessTokenWithIssuedCredentialId(String issuedCredentialId) {
        String payload = """
                {
                  "typ": "Bearer",
                  "authorization_details": [
                    {
                      "type": "%s",
                      "credential_configuration_id": "PidCredential",
                      "issued_credential_id": "%s"
                    }
                  ]
                }
                """.formatted(OPENID_CREDENTIAL, issuedCredentialId);

        return unsignedJwt(payload);
    }

    private String accessTokenWithoutIssuedId() {
        String payload = """
                {
                  "typ": "Bearer",
                  "authorization_details": [
                    {
                      "type": "%s",
                      "credential_configuration_id": "PidCredential"
                    }
                  ]
                }
                """.formatted(OPENID_CREDENTIAL);

        return unsignedJwt(payload);
    }

    private String unsignedJwt(String payload) {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return encoder.encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8))
                + "."
                + encoder.encodeToString(payload.getBytes(StandardCharsets.UTF_8))
                + ".";
    }
}
