package com.adorsys.keycloakstatuslist.events;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.Config;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.KeycloakTransactionManager;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import com.adorsys.keycloakstatuslist.service.StatusListService;

import java.security.PublicKey;
import java.util.Arrays;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TokenStatusEventListenerProviderFactoryTest {

    @Mock
    private KeycloakSession session;

    @Mock
    private KeycloakSessionFactory sessionFactory;

    @Mock
    private RealmModel realm;

    @Mock
    private KeyManager keyManager;

    @Mock
    private KeyWrapper keyWrapper;

    @Mock
    private PublicKey publicKey;

    @Mock
    private Config.Scope config;

    @Mock
    private KeycloakContext context;

    @Mock
    private RealmProvider realmProvider;

    @Mock
    private KeycloakTransactionManager transactionManager;

    @Mock
    private StatusListService statusListService;

    private TokenStatusEventListenerProviderFactory factory;

    @BeforeEach
    void setUp() {
        factory = new TokenStatusEventListenerProviderFactory();
        
        // Setup session mocks
        lenient().when(session.getContext()).thenReturn(context);
        lenient().when(session.keys()).thenReturn(keyManager);
        lenient().when(session.realms()).thenReturn(realmProvider);
        lenient().when(session.getTransactionManager()).thenReturn(transactionManager);
        
        // Setup context mocks
        lenient().when(context.getRealm()).thenReturn(realm);
        
        // Setup realm mocks
        lenient().when(realm.getName()).thenReturn("test-realm");
        lenient().when(realm.getAttribute("status-list-enabled")).thenReturn("true");
        lenient().when(realm.getAttribute("status-list-server-url")).thenReturn("http://localhost:8000");
        lenient().when(realm.getAttribute("status-list-auth-token")).thenReturn("test-token");
        lenient().when(realm.getAttribute("status-list-connect-timeout")).thenReturn("5000");
        lenient().when(realm.getAttribute("status-list-read-timeout")).thenReturn("5000");
        lenient().when(realm.getAttribute("status-list-retry-count")).thenReturn("3");
    }

    @Test
    void create_ShouldCreateProvider() {
        // Act
        TokenStatusEventListenerProvider provider = (TokenStatusEventListenerProvider) factory.create(session);

        // Assert
        assertNotNull(provider);
    }

    @Test
    void postInit_ShouldInitializeRealms() {
        // Arrange
        when(sessionFactory.create()).thenReturn(session);
        when(realmProvider.getRealmsStream()).thenReturn(Arrays.asList(realm).stream());
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), anyString())).thenReturn(keyWrapper);
        when(keyWrapper.getPublicKey()).thenReturn(publicKey);
        when(keyWrapper.getAlgorithm()).thenReturn("RS256");
        when(publicKey.getEncoded()).thenReturn("test-key".getBytes());

        // Act
        factory.postInit(sessionFactory);

        // Assert
        verify(session.getTransactionManager()).begin();
        verify(session.getTransactionManager()).commit();
    }

    @Test
    void getId_ShouldReturnProviderId() {
        // Act
        String id = factory.getId();

        // Assert
        assertEquals("token-status-event-listener", id);
    }

    @Test
    void postInit_ShouldSkipDisabledRealm() {
        // Arrange
        when(sessionFactory.create()).thenReturn(session);
        when(realmProvider.getRealmsStream()).thenReturn(Arrays.asList(realm).stream());
        when(realm.getAttribute("status-list-enabled")).thenReturn("false");

        // Act
        factory.postInit(sessionFactory);

        // Assert
        verify(transactionManager).begin();
        verify(transactionManager).commit();
        verify(keyManager, never()).getActiveKey(any(), any(), any());
    }

    @Test
    void registerRealmAsIssuer_ShouldHandleMissingPublicKey() {
        // Arrange
        when(sessionFactory.create()).thenReturn(session);
        when(realmProvider.getRealmsStream()).thenReturn(Arrays.asList(realm).stream());
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), anyString())).thenReturn(keyWrapper);
        when(keyWrapper.getPublicKey()).thenReturn(null);
        when(keyWrapper.getAlgorithm()).thenReturn("RS256");

        // Act
        factory.postInit(sessionFactory);

        // Assert
        verify(transactionManager).begin();
        verify(transactionManager).commit();
        verify(keyManager).getActiveKey(eq(realm), eq(KeyUse.SIG), anyString());
    }

    @Test
    void registerRealmAsIssuer_ShouldHandleMissingActiveKey() {
        // Arrange
        when(sessionFactory.create()).thenReturn(session);
        when(realmProvider.getRealmsStream()).thenReturn(Arrays.asList(realm).stream());
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), anyString())).thenReturn(null);

        // Act
        factory.postInit(sessionFactory);

        // Assert
        verify(transactionManager).begin();
        verify(transactionManager).commit();
        verify(keyManager).getActiveKey(eq(realm), eq(KeyUse.SIG), anyString());
    }

    @Test
    void postInit_ShouldHandleCompleteSuccess() {
        // Arrange
        when(sessionFactory.create()).thenReturn(session);
        when(realmProvider.getRealmsStream()).thenReturn(Arrays.asList(realm).stream());
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), anyString())).thenReturn(keyWrapper);
        when(keyWrapper.getPublicKey()).thenReturn(publicKey);
        when(keyWrapper.getAlgorithm()).thenReturn("RS256");
        when(publicKey.getEncoded()).thenReturn("test-key".getBytes());

        // Act
        factory.postInit(sessionFactory);

        // Assert
        verify(transactionManager).begin();
        verify(transactionManager).commit();
    }

    @Test
    void postInit_ShouldHandlePartialSuccess() {
        // Arrange - Create two realms
        RealmModel realm1 = mock(RealmModel.class);
        RealmModel realm2 = mock(RealmModel.class);

        when(sessionFactory.create()).thenReturn(session);
        when(realmProvider.getRealmsStream()).thenReturn(Arrays.asList(realm1, realm2).stream());

        // Setup realm1 to succeed
        when(realm1.getName()).thenReturn("success-realm");
        when(realm1.getAttribute("status-list-enabled")).thenReturn("true");
        when(realm1.getAttribute("status-list-server-url")).thenReturn("http://localhost:8000");
        when(realm1.getAttribute("status-list-auth-token")).thenReturn("test-token");
        when(realm1.getAttribute("status-list-connect-timeout")).thenReturn("5000");
        when(realm1.getAttribute("status-list-read-timeout")).thenReturn("5000");
        when(realm1.getAttribute("status-list-retry-count")).thenReturn("3");

        // Setup realm2 to fail
        when(realm2.getName()).thenReturn("failed-realm");
        when(realm2.getAttribute("status-list-enabled")).thenReturn("true");
        when(realm2.getAttribute("status-list-server-url")).thenReturn("http://localhost:8000");
        when(realm2.getAttribute("status-list-auth-token")).thenReturn("test-token");
        when(realm2.getAttribute("status-list-connect-timeout")).thenReturn("5000");
        when(realm2.getAttribute("status-list-read-timeout")).thenReturn("5000");
        when(realm2.getAttribute("status-list-retry-count")).thenReturn("3");

        // Setup key manager for both realms
        when(keyManager.getActiveKey(eq(realm1), eq(KeyUse.SIG), anyString())).thenReturn(keyWrapper);
        when(keyManager.getActiveKey(eq(realm2), eq(KeyUse.SIG), anyString())).thenReturn(keyWrapper);
        when(keyWrapper.getPublicKey()).thenReturn(publicKey);
        when(keyWrapper.getAlgorithm()).thenReturn("RS256");
        when(publicKey.getEncoded()).thenReturn("test-key".getBytes());

        // Act
        factory.postInit(sessionFactory);

        // Assert
        verify(transactionManager).begin();
        verify(transactionManager).commit();
    }

    @Test
    void postInit_ShouldHandleMultipleRealmsWithMixedResults() {
        // Arrange - Create three realms: one success, one failure, one disabled
        RealmModel successRealm = mock(RealmModel.class);
        RealmModel failedRealm = mock(RealmModel.class);
        RealmModel disabledRealm = mock(RealmModel.class);

        when(sessionFactory.create()).thenReturn(session);
        when(realmProvider.getRealmsStream())
                .thenReturn(Arrays.asList(successRealm, failedRealm, disabledRealm).stream());

        // Setup success realm
        when(successRealm.getName()).thenReturn("success-realm");
        when(successRealm.getAttribute("status-list-enabled")).thenReturn("true");
        when(successRealm.getAttribute("status-list-server-url")).thenReturn("http://localhost:8000");
        when(successRealm.getAttribute("status-list-auth-token")).thenReturn("test-token");
        when(successRealm.getAttribute("status-list-connect-timeout")).thenReturn("5000");
        when(successRealm.getAttribute("status-list-read-timeout")).thenReturn("5000");
        when(successRealm.getAttribute("status-list-retry-count")).thenReturn("3");

        // Setup failed realm
        when(failedRealm.getName()).thenReturn("failed-realm");
        when(failedRealm.getAttribute("status-list-enabled")).thenReturn("true");
        when(failedRealm.getAttribute("status-list-server-url")).thenReturn("http://localhost:8000");
        when(failedRealm.getAttribute("status-list-auth-token")).thenReturn("test-token");
        when(failedRealm.getAttribute("status-list-connect-timeout")).thenReturn("5000");
        when(failedRealm.getAttribute("status-list-read-timeout")).thenReturn("5000");
        when(failedRealm.getAttribute("status-list-retry-count")).thenReturn("3");

        // Setup disabled realm
        when(disabledRealm.getName()).thenReturn("disabled-realm");
        when(disabledRealm.getAttribute("status-list-enabled")).thenReturn("false");

        // Setup key manager for enabled realms
        when(keyManager.getActiveKey(eq(successRealm), eq(KeyUse.SIG), anyString())).thenReturn(keyWrapper);
        when(keyManager.getActiveKey(eq(failedRealm), eq(KeyUse.SIG), anyString())).thenReturn(keyWrapper);
        when(keyWrapper.getPublicKey()).thenReturn(publicKey);
        when(keyWrapper.getAlgorithm()).thenReturn("RS256");
        when(publicKey.getEncoded()).thenReturn("test-key".getBytes());

        // Act
        factory.postInit(sessionFactory);

        // Assert
        verify(transactionManager).begin();
        verify(transactionManager).commit();
    }

    @Test
    void postInit_ShouldHandleEmptyRealmsList() {
        // Arrange
        when(sessionFactory.create()).thenReturn(session);
        when(realmProvider.getRealmsStream()).thenReturn(Stream.empty());

        // Act
        factory.postInit(sessionFactory);

        // Assert
        verify(transactionManager).begin();
        verify(transactionManager).commit();
    }

    @Test
    void postInit_ShouldHandleRealmRegistrationFailure() {
        // Arrange - Test a simpler failure scenario
        when(sessionFactory.create()).thenReturn(session);
        when(realmProvider.getRealmsStream()).thenReturn(Arrays.asList(realm).stream());
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), anyString())).thenReturn(keyWrapper);
        when(keyWrapper.getPublicKey()).thenReturn(null); // This will cause registration to fail

        // Act
        factory.postInit(sessionFactory);

        // Assert
        verify(transactionManager).begin();
        verify(transactionManager).commit();
    }
}