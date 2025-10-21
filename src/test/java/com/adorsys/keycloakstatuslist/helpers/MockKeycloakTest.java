package com.adorsys.keycloakstatuslist.helpers;

import jakarta.persistence.EntityManager;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakTransactionManager;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.util.JsonSerialization;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
public class MockKeycloakTest {

    protected static final String TEST_REALM_ID = "test-realm-id";
    protected static final String TEST_REALM_NAME = "test-realm";
    protected static final String TEST_CLIENT_ID = "test-client";

    @Mock
    protected KeycloakSession session;
    @Mock
    protected KeyManager keyManager;
    @Mock
    protected KeycloakSessionFactory sessionFactory;
    @Mock
    protected KeycloakTransactionManager transactionManager;

    @Mock
    protected JpaConnectionProvider jpaConnectionProvider;
    @Mock
    protected EntityManager entityManager;

    @Mock
    protected KeycloakContext context;
    @Mock
    protected RealmModel realm;
    @Mock
    protected ClientModel client;
    @Mock
    protected UserSessionModel userSession;


    @Mock
    protected CloseableHttpClient httpClient;
    @Mock
    protected CloseableHttpResponse httpResponse;

    @BeforeEach
    void rootSetup() {
        lenient().when(session.keys()).thenReturn(keyManager);
        lenient().when(keyManager.getActiveKey(any(), any(), eq(Algorithm.RS256))).thenReturn(getActiveRsaKey());

        lenient().when(session.getKeycloakSessionFactory()).thenReturn(sessionFactory);
        lenient().when(sessionFactory.create()).thenReturn(session);
        lenient().when(session.getTransactionManager()).thenReturn(transactionManager);
        lenient().doNothing().when(transactionManager).begin();

        lenient().when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpaConnectionProvider);
        lenient().when(jpaConnectionProvider.getEntityManager()).thenReturn(entityManager);

        lenient().when(session.getContext()).thenReturn(context);
        lenient().when(context.getRealm()).thenReturn(realm);
        lenient().when(context.getClient()).thenReturn(client);
        lenient().when(realm.getName()).thenReturn(TEST_REALM_NAME);
        lenient().when(realm.getId()).thenReturn(TEST_REALM_ID);
        lenient().when(client.getClientId()).thenReturn(TEST_CLIENT_ID);
    }

    @BeforeEach
    void httpSetUp() {
    }

    @AfterEach
    void httpTearDown() {
    }

    static KeyWrapper getActiveRsaKey() {
        try {
            JWK jwk = testJwkResource("/keycloak-active-key-rsa.json");
            return RSATestUtils.getRsaKeyWrapper(jwk);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings("SameParameterValue")
    protected static JWK testJwkResource(String filename) {
        try (InputStream stream = MockKeycloakTest.class.getResourceAsStream(filename)) {
            return JsonSerialization.readValue(stream, JWK.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings("SameParameterValue")
    protected static void setPrivateField(Object target, String fieldName, Object value) {
        Class<?> clazz = target.getClass();
        while (clazz != null) {
            try {
                Field field = clazz.getDeclaredField(fieldName);
                field.setAccessible(true);
                field.set(target, value);
                return;
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass(); // climb up the hierarchy
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
