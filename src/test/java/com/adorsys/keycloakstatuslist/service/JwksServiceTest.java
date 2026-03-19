package com.adorsys.keycloakstatuslist.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class JwksServiceTest {

    @Mock
    private KeycloakSession session;

    @Mock
    private org.keycloak.models.KeycloakContext context;

    @Mock
    private KeyManager keyManager;

    @Mock
    private RealmModel realm;

    @Mock
    private SdJwtVP sdJwtVP;

    @Mock
    private SignatureProvider signatureProvider;

    @Mock
    private SignatureVerifierContext verifierContext;

    private JwksService service;

    @BeforeEach
    void setUp() {
        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realm);
        when(session.keys()).thenReturn(keyManager);
        service = new JwksService(session);
    }

    @Test
    void testGetSignatureVerifierContexts_NoKeys() throws Exception {
        when(keyManager.getKeysStream(realm)).thenReturn(Stream.empty());
        List<SignatureVerifierContext> result = service.getSignatureVerifierContexts(sdJwtVP, "issuer");
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void testGetSignatureVerifierContexts_WithOneKey() throws Exception {
        KeyWrapper key = mock(KeyWrapper.class);
        when(key.getUse()).thenReturn(KeyUse.SIG);
        when(key.getAlgorithmOrDefault()).thenReturn("RS256");

        when(keyManager.getKeysStream(realm)).thenReturn(Stream.of(key));
        when(session.getProvider(SignatureProvider.class, "RS256")).thenReturn(signatureProvider);
        when(signatureProvider.verifier(key)).thenReturn(verifierContext);

        List<SignatureVerifierContext> result = service.getSignatureVerifierContexts(sdJwtVP, "issuer");
        assertNotNull(result);
        assertEquals(1, result.size());
        assertSame(verifierContext, result.get(0));
    }
}
