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
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
import com.adorsys.keycloakstatuslist.service.StatusListService;

/**
 * Event listener for Keycloak token events to update the status list.
 */
public class TokenStatusEventListenerProvider implements EventListenerProvider {
    private static final Logger logger = Logger.getLogger(TokenStatusEventListenerProvider.class);

    private final KeycloakSession session;
    private final StatusListService statusListService;

    public TokenStatusEventListenerProvider(KeycloakSession session) {
        this.session = session;
        RealmModel realm = session.getContext().getRealm();
        StatusListConfig config = new StatusListConfig(session, realm);
        this.statusListService = new StatusListService(config.getServerUrl(), config.getAuthToken());
        logger.info("TokenStatusEventListenerProvider initialized with realm: " + realm.getName());
    }

    @Override
    public void onEvent(Event event) {
        if (session.getContext().getRealm() == null) {
            logger.warn("No realm context available for event: " + event.getType());
            return;
        }

        try {
            logger.debug("Processing event: " + event.getType().name());

            // Check if this is an event we should process
            if (shouldProcessEvent(event)) {
                RealmModel realm = session.realms().getRealm(event.getRealmId());
                StatusListConfig config = new StatusListConfig(session, realm);

                if (!config.isEnabled()) {
                    logger.debug("Status list service is disabled for realm: " + realm.getName());
                    return;
                }

                TokenStatusRecord statusRecord = createStatusRecord(event, realm);
                if (statusRecord != null) {
                    logger.info("Processing token status for event type: " + event.getType().name());
                    logger.debug("Status record: " + statusRecord);

                    statusListService.publishRecord(statusRecord);
                    logger.info("Successfully published token status: " + statusRecord.getCredentialId() +
                            ", Status: " + statusRecord.getStatus().getValue());
                }
            }
        } catch (Exception e) {
            logger.error("Error processing event: " + e.getMessage(), e);
        }
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean includeRepresentation) {
        // Currently not processing admin events
        logger.debug("Received admin event: " + adminEvent.getOperationType() + " " + adminEvent.getResourceType());
    }

    @Override
    public void close() {
        // No resources to close
    }

    private boolean shouldProcessEvent(Event event) {
        EventType type = event.getType();
        return type == EventType.LOGIN ||
                type == EventType.LOGOUT ||
                type == EventType.REFRESH_TOKEN ||
                type == EventType.TOKEN_EXCHANGE ||
                type == EventType.REVOKE_GRANT ||
                type == EventType.CLIENT_LOGIN;
    }

    private boolean isRevocationEvent(EventType type) {
        return type == EventType.LOGOUT || type == EventType.REVOKE_GRANT;
    }

    private TokenStatusRecord createStatusRecord(Event event, RealmModel realm) {
        Map<String, String> details = event.getDetails();

        // Extract token ID - for login events it's in SESSION_ID
        String tokenId = event.getSessionId();
        if (tokenId == null) {
            // Try to get from refresh token ID
            tokenId = details.get("refresh_token_id");
        }

        if (tokenId == null) {
            logger.warn("No token identifier found in event, skipping");
            return null;
        }

        TokenStatusRecord statusRecord = new TokenStatusRecord();
        statusRecord.setCredentialId(tokenId);
        statusRecord.setIssuerId(realm.getName());
        statusRecord.setCredentialType("SD-JWT");

        // Build status reason with client ID and user ID if available
        StringBuilder statusReason = new StringBuilder();
        if (event.getClientId() != null) {
            statusReason.append("Client: ").append(event.getClientId());
        }
        if (event.getUserId() != null) {
            if (statusReason.length() > 0) {
                statusReason.append(", ");
            }
            statusReason.append("User: ").append(event.getUserId());
        }
        if (statusReason.length() > 0) {
            statusRecord.setStatusReason(statusReason.toString());
        }

        EventType eventType = event.getType();
        Instant now = Instant.now();

        if (isRevocationEvent(eventType)) {
            statusRecord.setStatus(TokenStatus.REVOKED);
            statusRecord.setRevokedAt(now);
            statusRecord.setIssuedAt(now.minusSeconds(60)); // Set to 1 minute ago as a fallback

            // Try to get expiration from token details
            String exp = details.get("exp");
            if (exp != null) {
                try {
                    statusRecord.setExpiresAt(Instant.ofEpochSecond(Long.parseLong(exp)));
                } catch (NumberFormatException e) {
                    logger.warn("Invalid expiration time format: " + exp);
                    statusRecord.setExpiresAt(now.plusSeconds(3600)); // Default to 1 hour
                }
            } else {
                statusRecord.setExpiresAt(now.plusSeconds(3600)); // Default to 1 hour
            }

            // Append revocation reason to status reason
            if (statusRecord.getStatusReason() == null || statusRecord.getStatusReason().isEmpty()) {
                statusRecord.setStatusReason("User logout or token revocation");
            } else {
                statusRecord.setStatusReason(statusRecord.getStatusReason() + ", Reason: User logout or token revocation");
            }
        } else {
            statusRecord.setStatus(TokenStatus.VALID);
            statusRecord.setIssuedAt(now);

            // Try to get expiration from token details
            String exp = details.get("exp");
            if (exp != null) {
                try {
                    statusRecord.setExpiresAt(Instant.ofEpochSecond(Long.parseLong(exp)));
                } catch (NumberFormatException e) {
                    logger.warn("Invalid expiration time format: " + exp);
                    statusRecord.setExpiresAt(now.plusSeconds(3600)); // Default to 1 hour
                }
            } else {
                statusRecord.setExpiresAt(now.plusSeconds(3600)); // Default to 1 hour
            }

            // Set status reason for valid tokens if not already set
            if (statusRecord.getStatusReason() == null || statusRecord.getStatusReason().isEmpty()) {
                statusRecord.setStatusReason("Token issued");
            }
        }

        return statusRecord;
    }
}