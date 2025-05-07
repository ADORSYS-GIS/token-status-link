package com.adorsys.keycloakstatuslist.events;

import java.time.Instant;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.KeyManager;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.exception.StatusListServerException;
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

    // Default public key placeholder when none is available from the realm
    private static final String DEFAULT_PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAolpIHxdSlTXLo1s6H1OCdpSj/4C0R3iT4QkP/ihstbuZxnSBVHUI0GWsteQV63hzKvKj5cuAQ9B8QcitOzpL5Y4sJKqy0gC9WoKjXJbflQBLsq+VzKXgPn2u02oLLbL2aVeOAzzVuZndMMwi5dWK3StCnxq7N77LFScjIiX+W6aS+RYFjD+rW3FUEmRKkbjLqt13i4FIXSQiIm5SHNJLIh5WM2XMk4LF9+C91kYkzXrWahQNAP4K466FbDeTZcvQsXPPMxzjf9HgGTjBUT1hYHK2dEI37kjGVTRRwj5bVjfmL+tkIF7RtLQXkGUDcOYqZe0APuBVvRhS6iDvRbK3FwIDAQAB";

    public TokenStatusEventListenerProvider(KeycloakSession session) {
        this.session = session;
        RealmModel realm = session.getContext().getRealm();
        StatusListConfig config = new StatusListConfig(session, realm);
        this.statusListService = new StatusListService(config.getServerUrl(), config.getAuthToken());
        logger.info("TokenStatusEventListenerProvider initialized with realm: " + (realm != null ? realm.getName() : "null"));
    }

    @Override
    public void onEvent(Event event) {
        if (session.getContext().getRealm() == null) {
            logger.warn("No realm context available for event: " + event.getType());
            return;
        }

        try {
            logger.debug("Processing event: " + event.getType().name() + ", details: " + event.getDetails());

            // Check if this is an event we should process
            if (shouldProcessEvent(event)) {
                RealmModel realm = session.realms().getRealm(event.getRealmId());
                StatusListConfig config = new StatusListConfig(session, realm);

                logger.debug("Realm: " + realm.getName() + ", StatusListConfig enabled: " + config.isEnabled());

                if (!config.isEnabled()) {
                    logger.debug("Status list service is disabled for realm: " + realm.getName());
                    return;
                }

                TokenStatusRecord statusRecord = createStatusRecord(event, realm);
                if (statusRecord == null) {
                    logger.debug("No status record created for event: " + event.getType().name());
                    return;
                }

                logger.info("Processing token status for event type: " + event.getType().name());
                logger.debug("Status record: " + statusRecord);

                statusListService.publishRecord(statusRecord);
                logger.info("Successfully published token status: " + statusRecord.getCredentialId() +
                        ", Status: " + statusRecord.getStatus());
            } else {
                logger.debug("Event not processed: " + event.getType().name());
            }
        } catch (StatusListException e) {
            if (e instanceof StatusListServerException serverEx) {
                logger.error("Server error publishing token status: Status code: " + serverEx.getStatusCode() + ", Message: " + serverEx.getMessage(), serverEx);
            } else {
                logger.error("Error publishing token status: " + e.getMessage(), e);
            }
        } catch (Exception e) {
            logger.error("Unexpected error processing event: " + e.getMessage(), e);
        }
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean includeRepresentation) {
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
        statusRecord.setIssuer(realm.getName());

        // Set public key and algorithm
        try {
            String[] keyAndAlg = getRealmPublicKeyAndAlg(realm);
            statusRecord.setPublicKey(keyAndAlg[0]);
            statusRecord.setAlg(keyAndAlg[1]);
        } catch (Exception e) {
            logger.warn("Could not retrieve realm public key and algorithm, using default", e);
            statusRecord.setPublicKey(DEFAULT_PUBLIC_KEY);
            statusRecord.setAlg("RS256");
        }

        statusRecord.setCredentialType("oauth2");

        // Build status reason with client ID and user ID if available
        StringBuilder statusReason = new StringBuilder();
        if (event.getClientId() != null) {
            statusReason.append("Client: ").append(event.getClientId());
        }
        if (event.getUserId() != null) {
            if (!statusReason.isEmpty()) {
                statusReason.append(", ");
            }
            statusReason.append("User: ").append(event.getUserId());
        }
        if (!statusReason.isEmpty()) {
            statusRecord.setStatusReason(statusReason.toString());
        }

        EventType eventType = event.getType();
        Instant now = Instant.now();

        if (isRevocationEvent(eventType)) {
            statusRecord.setStatus(TokenStatus.REVOKED);
            statusRecord.setRevokedAt(now);
            statusRecord.setIssuedAt(now.minusSeconds(60));

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
                statusRecord.setExpiresAt(now.plusSeconds(3600));
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
                    statusRecord.setExpiresAt(now.plusSeconds(3600));
                }
            } else {
                statusRecord.setExpiresAt(now.plusSeconds(3600));
            }

            // Set status reason for valid tokens if not already set
            if (statusRecord.getStatusReason() == null || statusRecord.getStatusReason().isEmpty()) {
                statusRecord.setStatusReason("Token issued");
            }
        }

        return statusRecord;
    }

    /**
     * Get the public key and algorithm for the realm.
     */
    private String[] getRealmPublicKeyAndAlg(RealmModel realm) {
        try {
            KeyManager keyManager = session.keys();
            // Specify algorithm and key use for getActiveKey
            KeyWrapper activeKey = keyManager.getActiveKey(realm, KeyUse.valueOf("RS256"), "SIG");
            if (activeKey != null) {
                String publicKey = activeKey.getPublicKey() != null ? activeKey.getPublicKey().toString() : DEFAULT_PUBLIC_KEY;
                String algorithm = activeKey.getAlgorithm() != null ? activeKey.getAlgorithm() : "RS256";
                return new String[]{publicKey, algorithm};
            }
            logger.warn("No active key found for realm: " + realm.getName());
            return new String[]{DEFAULT_PUBLIC_KEY, "RS256"};
        } catch (Exception e) {
            logger.error("Error retrieving realm public key and algorithm", e);
            return new String[]{DEFAULT_PUBLIC_KEY, "RS256"};
        }
    }
}