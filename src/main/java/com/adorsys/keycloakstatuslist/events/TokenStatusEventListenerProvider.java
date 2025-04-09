package com.adorsys.keycloakstatuslist.events;

import java.time.Instant;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.model.TokenStatus;

/**
 * Event listener provider that reacts to Keycloak token events and publishes token status
 * to the status list server.
 */
public class TokenStatusEventListenerProvider implements EventListenerProvider {
    private static final Logger logger = Logger.getLogger(TokenStatusEventListenerProvider.class);
    
    private final KeycloakSession session;
    private final com.adorsys.keycloakstatuslist.service.StatusListService statusListService;
    
    public TokenStatusEventListenerProvider(KeycloakSession session) {
        this.session = session;
        
        // Initialize config for current realm
        RealmModel realm = session.getContext().getRealm();
        StatusListConfig config = new StatusListConfig(session, realm);
        
        // Initialize status list service
        this.statusListService = new com.adorsys.keycloakstatuslist.service.StatusListService(config);
    }

    @Override
    public void onEvent(Event event) {
        // Skip events that don't pertain to tokens
        if (!isTokenRelatedEvent(event.getType())) {
            return;
        }

        logger.debug("Processing token event: " + event.getType().name());

        try {
            RealmModel realm = session.realms().getRealm(event.getRealmId());
            Map<String, String> details = event.getDetails();

            // Create token status based on the event
            TokenStatus tokenStatus = createTokenStatus(event, realm);

            // Publish token status
            if (tokenStatus != null) {
                boolean published = statusListService.publishTokenStatus(tokenStatus);
                if (published) {
                    logger.debug("Successfully published token status for event: " + event.getType().name());
                } else {
                    logger.warn("Failed to publish token status for event: " + event.getType().name());
                }
            }
        } catch (Exception e) {
            logger.error("Error processing token event: " + e.getMessage(), e);
        }
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean includeRepresentation) {
        // We don't process admin events in this plugin
    }

    @Override
    public void close() {
        // No resources to close
    }

    private boolean isTokenRelatedEvent(EventType eventType) {
        return eventType == EventType.LOGIN 
                || eventType == EventType.LOGOUT 
                || eventType == EventType.REFRESH_TOKEN 
                || eventType == EventType.REVOKE_GRANT 
                || eventType == EventType.LOGOUT_ERROR 
                || eventType == EventType.CLIENT_LOGIN 
                || eventType == EventType.TOKEN_EXCHANGE;
    }
    
    private TokenStatus createTokenStatus(Event event, RealmModel realm) {
        Map<String, String> details = event.getDetails();
        String tokenId = details.get("token_id");
        
        // Skip if token_id is not available
        if (tokenId == null) {
            logger.debug("No token_id in event details, skipping");
            return null;
        }
        
        TokenStatus tokenStatus = new TokenStatus();
        tokenStatus.setTokenId(tokenId);
        tokenStatus.setUserId(event.getUserId());
        tokenStatus.setClientId(event.getClientId());
        tokenStatus.setIssuer(realm.getName());
        
        // Set status based on event type
        switch (event.getType()) {
            case LOGIN:
            case REFRESH_TOKEN:
            case CLIENT_LOGIN:
            case TOKEN_EXCHANGE:
                tokenStatus.setStatus("ACTIVE");
                tokenStatus.setIssuedAt(Instant.now());
                // Try to get expiration from details
                String exp = details.get("exp");
                if (exp != null) {
                    try {
                        tokenStatus.setExpiresAt(Instant.ofEpochSecond(Long.parseLong(exp)));
                    } catch (NumberFormatException e) {
                        logger.warn("Invalid expiration time format: " + exp);
                    }
                }
                break;
                
            case LOGOUT:
            case REVOKE_GRANT:
                tokenStatus.setStatus("REVOKED");
                tokenStatus.setRevokedAt(Instant.now());
                break;
                
            default:
                // Skip unsupported event types
                return null;
        }
        
        return tokenStatus;
    }
}