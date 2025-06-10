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

import java.security.PublicKey;
import java.util.Arrays;

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
    }

    @Test
    void create_ShouldCreateProvider() {
        // Act
        TokenStatusEventListenerProvider provider = (TokenStatusEventListenerProvider) factory.create(session);

        // Assert
        assertNotNull(provider);
    }

    @Test
    void postInit_ShouldRegisterRealms() {
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
    void postInit_ShouldHandleRegistrationFailure() {
        // Arrange
        when(sessionFactory.create()).thenReturn(session);
        when(realmProvider.getRealmsStream()).thenReturn(Arrays.asList(realm).stream());
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), anyString())).thenReturn(null);

        // Act
        factory.postInit(sessionFactory);

        // Assert
        verify(transactionManager).begin();
        verify(transactionManager).commit();
    }

    @Test
    void getId_ShouldReturnProviderId() {
        // Act
        String id = factory.getId();

        // Assert
        assertEquals("token-status-event-listener", id);
    }

    @Test
    void close_ShouldClearRegisteredRealms() {
        // Arrange
        when(sessionFactory.create()).thenReturn(session);
        when(realmProvider.getRealmsStream()).thenReturn(Arrays.asList(realm).stream());
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), anyString())).thenReturn(keyWrapper);
        when(keyWrapper.getPublicKey()).thenReturn(publicKey);
        when(keyWrapper.getAlgorithm()).thenReturn("RS256");
        when(publicKey.getEncoded()).thenReturn("test-key".getBytes());

        // Act
        factory.postInit(sessionFactory);
        factory.close();
        factory.postInit(sessionFactory);

        // Assert
        verify(session.getTransactionManager(), times(2)).begin();
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
    void postInit_ShouldHandleMultipleRealms() {
        // Arrange
        RealmModel realm2 = mock(RealmModel.class);
        when(realm2.getName()).thenReturn("test-realm-2");
        when(sessionFactory.create()).thenReturn(session);
        when(realmProvider.getRealmsStream()).thenReturn(Arrays.asList(realm, realm2).stream());
        when(keyManager.getActiveKey(any(), eq(KeyUse.SIG), anyString())).thenReturn(keyWrapper);
        when(keyWrapper.getPublicKey()).thenReturn(publicKey);
        when(keyWrapper.getAlgorithm()).thenReturn("RS256");
        when(publicKey.getEncoded()).thenReturn("test-key".getBytes());

        // Act
        factory.postInit(sessionFactory);

        // Assert
        verify(transactionManager).begin();
        verify(transactionManager).commit();
        verify(keyManager, times(2)).getActiveKey(any(), eq(KeyUse.SIG), anyString());
    }
} 