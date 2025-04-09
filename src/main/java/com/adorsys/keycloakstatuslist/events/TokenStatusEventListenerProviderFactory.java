package com.adorsys.keycloakstatuslist.events;

import java.util.Set;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Factory for creating TokenStatusEventListenerProvider instances.
 */
public class TokenStatusEventListenerProviderFactory implements EventListenerProviderFactory {

    // Provider ID used in Keycloak configuration
    public static final String PROVIDER_ID = "token-status-event-listener";
    
    // Set of supported event types
    private static final Set<EventType> SUPPORTED_EVENTS;
    
    static {
        SUPPORTED_EVENTS = Set.of(EventType.LOGIN, EventType.LOGOUT, EventType.REFRESH_TOKEN, EventType.REVOKE_GRANT, EventType.CLIENT_LOGIN, EventType.TOKEN_EXCHANGE);
    }
    
    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new com.adorsys.keycloakstatuslist.events.TokenStatusEventListenerProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
        // No initialization needed
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No post-initialization needed
    }

    @Override
    public void close() {
        // No resources to close
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}