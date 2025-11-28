package com.adorsys.keycloakstatuslist.resource;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.service.StatusListService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.models.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.stream.Stream;

import static org.mockito.Mockito.*;

class CredentialRevocationResourceProviderFactoryTest {

    private CredentialRevocationResourceProviderFactory factory;
    private KeycloakSessionFactory keycloakSessionFactory;
    private KeycloakSession session;
    private RealmProvider realmProvider;
    private RealmModel realm;
    private KeyManager keyManager;
    private KeyWrapper keyWrapper;
    private StatusListService statusListService;

    @BeforeEach
    void setUp() throws Exception {
        factory = new CredentialRevocationResourceProviderFactory();

        keycloakSessionFactory = mock(KeycloakSessionFactory.class);
        session = mock(KeycloakSession.class);
        realmProvider = mock(RealmProvider.class);
        realm = mock(RealmModel.class);
        keyManager = mock(KeyManager.class);
        keyWrapper = mock(KeyWrapper.class);
        statusListService = mock(StatusListService.class);

        when(keycloakSessionFactory.create()).thenReturn(session);
        when(session.realms()).thenReturn(realmProvider);
        when(session.keys()).thenReturn(keyManager);
        when(session.getTransactionManager()).thenReturn(mock(KeycloakTransactionManager.class));

        when(realmProvider.getRealmsStream()).thenAnswer(invocation -> Stream.of(realm));
        when(realm.getName()).thenReturn("test-realm");
        when(realm.getAttribute("status-list-enabled")).thenReturn("true");
        when(realm.getAttribute("status-list-server-url")).thenReturn("http://localhost:8080/statuslist");

        KeyPair keyPair = generateRsaKeyPair();
        when(keyManager.getActiveKey(realm, KeyUse.SIG, Algorithm.RS256)).thenReturn(keyWrapper);
        when(keyWrapper.getPublicKey()).thenReturn(keyPair.getPublic());
        when(keyWrapper.getAlgorithm()).thenReturn(Algorithm.RS256);
        when(keyWrapper.getKid()).thenReturn("test-kid");
    }

    @Test
    void testRegisterRealmAsIssuer_sendsJwkPublicKey() throws Exception {

        StatusListConfig config = new StatusListConfig(realm);
        KeyWrapper activeKey = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);

        Object publicKeyJwk = JWKBuilder.create().kid(activeKey.getKid()).algorithm(activeKey.getAlgorithmOrDefault()).rsa(activeKey.getPublicKey());

        statusListService.registerIssuer(config.getTokenIssuerId(), publicKeyJwk, activeKey.getAlgorithm());

        verify(statusListService).registerIssuer(anyString(), isA(JWK.class), anyString());
    }

    private KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }
}