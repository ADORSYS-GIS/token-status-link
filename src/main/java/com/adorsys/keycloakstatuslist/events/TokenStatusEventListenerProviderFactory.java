package com.adorsys.keycloakstatuslist.events;

import java.util.Set;

import org.jboss.logging.Logger;
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
    private static final Logger logger = Logger.getLogger(TokenStatusEventListenerProviderFactory.class);

    // Provider ID used in Keycloak configuration
    public static final String PROVIDER_ID = "token-status-event-listener";

    // Set of supported event types
    private static final Set<EventType> SUPPORTED_EVENTS = Set.of(
            EventType.LOGIN,
            EventType.LOGOUT,
            EventType.REFRESH_TOKEN,
            EventType.REVOKE_GRANT,
            EventType.CLIENT_LOGIN,
            EventType.TOKEN_EXCHANGE
    );

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        logger.info("Creating TokenStatusEventListenerProvider");
        return new TokenStatusEventListenerProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
        logger.info("Initializing TokenStatusEventListenerProviderFactory");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        logger.info("Post-initializing TokenStatusEventListenerProviderFactory");
    }

    @Override
    public void close() {
        logger.info("Closing TokenStatusEventListenerProviderFactory");
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}