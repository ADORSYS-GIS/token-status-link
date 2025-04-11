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
import com.adorsys.keycloakstatuslist.service.StatusListService;

public class TokenStatusEventListenerProvider implements EventListenerProvider {
    private static final Logger logger = Logger.getLogger(TokenStatusEventListenerProvider.class);

    private final KeycloakSession session;
    private final StatusListService statusListService;

    public TokenStatusEventListenerProvider(KeycloakSession session) {
        this.session = session;
        RealmModel realm = session.getContext().getRealm();
        StatusListConfig config = new StatusListConfig(session, realm);
        this.statusListService = new StatusListService(config);
    }

    @Override
    public void onEvent(Event event) {
        if (!isTokenRelatedEvent(event.getType())) {
            return;
        }

        logger.debug("Processing token event: " + event.getType().name());

        try {
            RealmModel realm = session.realms().getRealm(event.getRealmId());
            Map<String, String> details = event.getDetails();
            TokenStatus tokenStatus = createTokenStatus(event, realm);

            if (tokenStatus != null) {
                boolean success;
                if (isUpdateEvent(event.getType())) {
                    success = statusListService.updateTokenStatus(tokenStatus);
                    logger.debug(success ? "Successfully updated token status" : "Failed to update token status");
                } else {
                    success = statusListService.publishTokenStatus(tokenStatus);
                    logger.debug(success ? "Successfully published token status" : "Failed to publish token status");
                }
            }
        } catch (Exception e) {
            logger.error("Error processing token event: " + e.getMessage(), e);
        }
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean includeRepresentation) {
        // Not handling admin events
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

    private boolean isUpdateEvent(EventType eventType) {
        return eventType == EventType.LOGOUT
                || eventType == EventType.REVOKE_GRANT
                || eventType == EventType.LOGOUT_ERROR;
    }

    private TokenStatus createTokenStatus(Event event, RealmModel realm) {
        Map<String, String> details = event.getDetails();
        String tokenId = details.get("token_id");

        if (tokenId == null) {
            logger.debug("No token_id in event details, skipping");
            return null;
        }

        TokenStatus tokenStatus = new TokenStatus();
        tokenStatus.setTokenId(tokenId);
        tokenStatus.setUserId(event.getUserId());
        tokenStatus.setClientId(event.getClientId());
        tokenStatus.setIssuer(realm.getName());

        switch (event.getType()) {
            case LOGIN:
            case REFRESH_TOKEN:
            case CLIENT_LOGIN:
            case TOKEN_EXCHANGE:
                tokenStatus.setStatus("ACTIVE");
                tokenStatus.setIssuedAt(Instant.now());
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
            case LOGOUT_ERROR:
                tokenStatus.setStatus("REVOKED");
                tokenStatus.setRevokedAt(Instant.now());
                break;

            default:
                return null;
        }

        return tokenStatus;
    }
}