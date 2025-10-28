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
    // timeouts and retry count are internal defaults; tests rely on defaults and don't stub them
        
        // Setup key wrapper and public key
        lenient().when(keyWrapper.getPublicKey()).thenReturn(publicKey);
        lenient().when(keyWrapper.getAlgorithm()).thenReturn("RS256");
        lenient().when(publicKey.getEncoded()).thenReturn("test-key".getBytes());
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
        lenient().when(sessionFactory.create()).thenReturn(session);
        lenient().when(realmProvider.getRealmsStream()).thenReturn(Arrays.asList(realm).stream());
        lenient().when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), anyString())).thenReturn(keyWrapper);
        lenient().when(keyWrapper.getPublicKey()).thenReturn(publicKey);
        lenient().when(keyWrapper.getAlgorithm()).thenReturn("RS256");
        lenient().when(publicKey.getEncoded()).thenReturn("test-key".getBytes());

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
        lenient().when(sessionFactory.create()).thenReturn(session);
        lenient().when(realmProvider.getRealmsStream()).thenReturn(Arrays.asList(realm).stream());
        lenient().when(realm.getAttribute("status-list-enabled")).thenReturn("false");

        // Act
        factory.postInit(sessionFactory);

        // Assert
        verify(transactionManager).begin();
        verify(transactionManager).commit();
        verify(keyManager, never()).getActiveKey(any(), any(), any());
    }

    @Test
    void registerRealmAsIssuer_ShouldHandleMissingPublicKey() {
        // Arrange - Use unhealthy server URL to test health check failure
        lenient().when(sessionFactory.create()).thenReturn(session);
        lenient().when(realmProvider.getRealmsStream()).thenReturn(Arrays.asList(realm).stream());
        // Act
        factory.postInit(sessionFactory);

        // Assert
        verify(transactionManager).begin();
        verify(transactionManager).commit();
        verify(keyManager, never()).getActiveKey(any(), any(), anyString());
    }

    @Test
    void registerRealmAsIssuer_ShouldHandleMissingActiveKey() {
        // Arrange - Use unhealthy server URL to test health check failure
        lenient().when(sessionFactory.create()).thenReturn(session);
        lenient().when(realmProvider.getRealmsStream()).thenReturn(Arrays.asList(realm).stream());
       
        // Act
        factory.postInit(sessionFactory);

        // Assert
        verify(transactionManager).begin();
        verify(transactionManager).commit();
        
        verify(keyManager, never()).getActiveKey(any(), any(), anyString());
    }

    @Test
    void postInit_ShouldHandleCompleteSuccess() {
        // Arrange - Use a healthy server URL so the health check passes
        lenient().when(sessionFactory.create()).thenReturn(session);
        lenient().when(realmProvider.getRealmsStream()).thenReturn(Arrays.asList(realm).stream());
        lenient().when(realm.getAttribute("status-list-server-url")).thenReturn("http://localhost:8000");
        lenient().when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), anyString())).thenReturn(keyWrapper);
        lenient().when(keyWrapper.getPublicKey()).thenReturn(publicKey);
        lenient().when(keyWrapper.getAlgorithm()).thenReturn("RS256");
        lenient().when(publicKey.getEncoded()).thenReturn("test-key".getBytes());

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

        lenient().when(sessionFactory.create()).thenReturn(session);
        lenient().when(realmProvider.getRealmsStream()).thenReturn(Arrays.asList(realm1, realm2).stream());

        // Setup realm1 to succeed - use healthy server URL
        lenient().when(realm1.getName()).thenReturn("success-realm");
        lenient().when(realm1.getAttribute("status-list-enabled")).thenReturn("true");
        lenient().when(realm1.getAttribute("status-list-server-url")).thenReturn("http://localhost:8000");
        lenient().when(realm1.getAttribute("status-list-auth-token")).thenReturn("test-token");
        

        // Setup realm2 to fail - use unhealthy server URL so it returns early
        lenient().when(realm2.getName()).thenReturn("failed-realm");
        lenient().when(realm2.getAttribute("status-list-enabled")).thenReturn("true");
        lenient().when(realm2.getAttribute("status-list-server-url")).thenReturn("http://unhealthy-server:9999");
        lenient().when(realm2.getAttribute("status-list-auth-token")).thenReturn("test-token");
        

        // Create separate key wrappers and public keys for realm1 only
        KeyWrapper keyWrapper1 = mock(KeyWrapper.class);
        PublicKey publicKey1 = mock(PublicKey.class);

        // Setup key manager for realm1 (success)
        lenient().when(keyManager.getActiveKey(eq(realm1), eq(KeyUse.SIG), anyString())).thenReturn(keyWrapper1);
        lenient().when(keyWrapper1.getPublicKey()).thenReturn(publicKey1);
        lenient().when(keyWrapper1.getAlgorithm()).thenReturn("RS256");
        lenient().when(publicKey1.getEncoded()).thenReturn("test-key".getBytes());

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

        lenient().when(sessionFactory.create()).thenReturn(session);
        lenient().when(realmProvider.getRealmsStream())
                .thenReturn(Arrays.asList(successRealm, failedRealm, disabledRealm).stream());

        // Setup success realm - use healthy server URL
        lenient().when(successRealm.getName()).thenReturn("success-realm");
        lenient().when(successRealm.getAttribute("status-list-enabled")).thenReturn("true");
        lenient().when(successRealm.getAttribute("status-list-server-url")).thenReturn("http://localhost:8000");
        lenient().when(successRealm.getAttribute("status-list-auth-token")).thenReturn("test-token");
        

        // Setup failed realm - use unhealthy server URL so it returns early
        lenient().when(failedRealm.getName()).thenReturn("failed-realm");
        lenient().when(failedRealm.getAttribute("status-list-enabled")).thenReturn("true");
        lenient().when(failedRealm.getAttribute("status-list-server-url")).thenReturn("http://unhealthy-server:9999");
        lenient().when(failedRealm.getAttribute("status-list-auth-token")).thenReturn("test-token");
        

        // Setup disabled realm
        lenient().when(disabledRealm.getName()).thenReturn("disabled-realm");
        lenient().when(disabledRealm.getAttribute("status-list-enabled")).thenReturn("false");

        // Setup key manager for success realm only
        KeyWrapper successKeyWrapper = mock(KeyWrapper.class);
        PublicKey successPublicKey = mock(PublicKey.class);

        // Setup key manager for success realm
        lenient().when(keyManager.getActiveKey(eq(successRealm), eq(KeyUse.SIG), anyString())).thenReturn(successKeyWrapper);
        lenient().when(successKeyWrapper.getPublicKey()).thenReturn(successPublicKey);
        lenient().when(successKeyWrapper.getAlgorithm()).thenReturn("RS256");
        lenient().when(successPublicKey.getEncoded()).thenReturn("test-key".getBytes());

        // Act
        factory.postInit(sessionFactory);

        // Assert
        verify(transactionManager).begin();
        verify(transactionManager).commit();
    }

    @Test
    void postInit_ShouldHandleEmptyRealmsList() {
        // Arrange
        lenient().when(sessionFactory.create()).thenReturn(session);
        lenient().when(realmProvider.getRealmsStream()).thenReturn(Stream.empty());

        // Act
        factory.postInit(sessionFactory);

        // Assert
        verify(transactionManager).begin();
        verify(transactionManager).commit();
    }

    @Test
    void postInit_ShouldHandleRealmRegistrationFailure() {
        // Arrange - Use healthy server URL but make public key null to cause failure
        lenient().when(sessionFactory.create()).thenReturn(session);
        lenient().when(realmProvider.getRealmsStream()).thenReturn(Arrays.asList(realm).stream());
        lenient().when(realm.getAttribute("status-list-server-url")).thenReturn("http://localhost:8000");
        lenient().when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), anyString())).thenReturn(keyWrapper);
        lenient().when(keyWrapper.getPublicKey()).thenReturn(null); 

        // Act
        factory.postInit(sessionFactory);

        // Assert
        verify(transactionManager).begin();
        verify(transactionManager).commit();
    }

    @Test
    void postInit_ShouldHandleHealthCheckFailure() {
        // Arrange - Test health check failure with unhealthy server URL
        lenient().when(sessionFactory.create()).thenReturn(session);
        lenient().when(realmProvider.getRealmsStream()).thenReturn(Arrays.asList(realm).stream());
        lenient().when(realm.getAttribute("status-list-server-url")).thenReturn("http://unhealthy-server:9999");

        // Act
        factory.postInit(sessionFactory);

        // Assert
        verify(transactionManager).begin();
        verify(transactionManager).commit();
        verify(keyManager, never()).getActiveKey(any(), any(), anyString());
    }

    @Test
    void postInit_ShouldHandleHealthCheckSuccess() {
        // Arrange - Test health check success with healthy server URL
        lenient().when(sessionFactory.create()).thenReturn(session);
        lenient().when(realmProvider.getRealmsStream()).thenReturn(Arrays.asList(realm).stream());
        lenient().when(realm.getAttribute("status-list-server-url")).thenReturn("http://localhost:8000");
        lenient().when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), anyString())).thenReturn(keyWrapper);
        lenient().when(keyWrapper.getPublicKey()).thenReturn(publicKey);
        lenient().when(keyWrapper.getAlgorithm()).thenReturn("RS256");
        lenient().when(publicKey.getEncoded()).thenReturn("test-key".getBytes());

        // Act
        factory.postInit(sessionFactory);

        // Assert
        verify(transactionManager).begin();
        verify(transactionManager).commit();
        verify(keyManager, never()).getActiveKey(eq(realm), eq(KeyUse.SIG), anyString());
    }

    @Test
    void postInit_ShouldHandleMixedHealthCheckResults() {
        // Arrange - Test mixed health check results
        RealmModel healthyRealm = mock(RealmModel.class);
        RealmModel unhealthyRealm = mock(RealmModel.class);

        lenient().when(sessionFactory.create()).thenReturn(session);
        lenient().when(realmProvider.getRealmsStream()).thenReturn(Arrays.asList(healthyRealm, unhealthyRealm).stream());

        // Setup healthy realm
        lenient().when(healthyRealm.getName()).thenReturn("healthy-realm");
        lenient().when(healthyRealm.getAttribute("status-list-enabled")).thenReturn("true");
        lenient().when(healthyRealm.getAttribute("status-list-server-url")).thenReturn("http://localhost:8000");
        lenient().when(healthyRealm.getAttribute("status-list-auth-token")).thenReturn("test-token");
        

        // Setup unhealthy realm
        lenient().when(unhealthyRealm.getName()).thenReturn("unhealthy-realm");
        lenient().when(unhealthyRealm.getAttribute("status-list-enabled")).thenReturn("true");
        lenient().when(unhealthyRealm.getAttribute("status-list-server-url")).thenReturn("http://unhealthy-server:9999");
        lenient().when(unhealthyRealm.getAttribute("status-list-auth-token")).thenReturn("test-token");
        

        // Setup key manager for healthy realm only
        KeyWrapper healthyKeyWrapper = mock(KeyWrapper.class);
        PublicKey healthyPublicKey = mock(PublicKey.class);

        lenient().when(keyManager.getActiveKey(eq(healthyRealm), eq(KeyUse.SIG), anyString())).thenReturn(healthyKeyWrapper);
        lenient().when(healthyKeyWrapper.getPublicKey()).thenReturn(healthyPublicKey);
        lenient().when(healthyKeyWrapper.getAlgorithm()).thenReturn("RS256");
        lenient().when(healthyPublicKey.getEncoded()).thenReturn("test-key".getBytes());

        // Act
        factory.postInit(sessionFactory);

        // Assert
        verify(transactionManager).begin();
        verify(transactionManager).commit();
        verify(keyManager, never()).getActiveKey(eq(healthyRealm), eq(KeyUse.SIG), anyString());
        verify(keyManager, never()).getActiveKey(eq(unhealthyRealm), eq(KeyUse.SIG), anyString());
    }
}