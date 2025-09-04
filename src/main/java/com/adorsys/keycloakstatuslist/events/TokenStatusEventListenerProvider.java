package com.adorsys.keycloakstatuslist.events;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.exception.StatusListServerException;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
import com.adorsys.keycloakstatuslist.service.CryptoIdentityService;
import com.adorsys.keycloakstatuslist.service.StatusListService;
import org.jboss.logging.Logger;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import java.time.Instant;
import java.util.Map;

/**
 * Event listener for Keycloak token events to update the status list.
 */
public class TokenStatusEventListenerProvider implements EventListenerProvider {

    private static final Logger logger = Logger.getLogger(TokenStatusEventListenerProvider.class);

    private final KeycloakSession session;
    private final CryptoIdentityService cryptoIdentityService;

    public TokenStatusEventListenerProvider(KeycloakSession session) {
        this.session = session;
        this.cryptoIdentityService = new CryptoIdentityService(session);
        RealmModel realm = session.getContext().getRealm();
        logger.info("TokenStatusEventListenerProvider initialized with realm: " + (realm != null ? realm.getName() : "null"));
    }

    private StatusListService getStatusListService(RealmModel realm) {
        StatusListConfig config = new StatusListConfig(realm);
        CryptoIdentityService cryptoIdentityService = new CryptoIdentityService(session);
        return new StatusListService(
                config.getServerUrl(),
                cryptoIdentityService.getJwtToken(config),
                config.getConnectTimeout(),
                config.getReadTimeout(),
                config.getRetryCount()
        );
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
                StatusListConfig config = new StatusListConfig(realm);

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

                StatusListService statusListService = getStatusListService(realm);
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
        // Only process REVOKE_GRANT (long-lived token revocation)
        return type == EventType.REVOKE_GRANT;
    }

    private boolean isRevocationEvent(EventType type) {
        // Only REVOKE_GRANT is considered a revocation event
        return type == EventType.REVOKE_GRANT;
    }

    private TokenStatusRecord createStatusRecord(Event event, RealmModel realm) {
        Map<String, String> details = event.getDetails();

        // Extract token ID (for REVOKE_GRANT events, typically in session or refresh_token_id)
        String tokenId = event.getSessionId();
        if (tokenId == null) {
            // Try to get from refresh token ID (for some revocation flows)
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

        // Set public key and algorithm for the status record
        try {
            String[] keyAndAlg = getRealmPublicKeyAndAlg(realm);
            statusRecord.setPublicKey(keyAndAlg[0]);
            statusRecord.setAlg(keyAndAlg[1]);
        } catch (Exception e) {
            logger.warn("Could not retrieve realm public key and algorithm, using default", e);
            return null;
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

            // Set expiration from token details if available, otherwise default to 1 hour
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

            // Append revocation reason to status reason
            if (statusRecord.getStatusReason() == null || statusRecord.getStatusReason().isEmpty()) {
                statusRecord.setStatusReason("Token revoked");
            } else {
                statusRecord.setStatusReason(statusRecord.getStatusReason() + ", Reason: Token revoked");
            }
        } else {
            // Should not reach here, as only REVOKE_GRANT is processed
            return null;
        }
        return statusRecord;
    }

    /**
     * Get the public key and algorithm for the realm.
     */
    private String[] getRealmPublicKeyAndAlg(RealmModel realm) {
        KeyWrapper activeKey = cryptoIdentityService.getActiveKey(realm);
        String publicKey = activeKey.getPublicKey().toString();
        String algorithm = activeKey.getAlgorithmOrDefault();
        return new String[]{publicKey, algorithm};
    }
}