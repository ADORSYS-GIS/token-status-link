package com.adorsys.keycloakstatuslist.events;

import java.time.Instant;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
import com.adorsys.keycloakstatuslist.service.StatusListService;

/**
 * Event listener for SD-JWT credential events to update the status list.
 */
public class SdJwtStatusEventListenerProvider implements EventListenerProvider {
    private static final Logger logger = Logger.getLogger(SdJwtStatusEventListenerProvider.class);

    // SD-JWT specific event types
    private static final String SD_JWT_ISSUED = "sd_jwt_issued";
    private static final String SD_JWT_REVOKED = "sd_jwt_revoked";
    private static final String SD_JWT_UPDATED = "sd_jwt_updated";

    private final KeycloakSession session;
    private final StatusListService statusListService;

    public SdJwtStatusEventListenerProvider(KeycloakSession session) {
        this.session = session;
        RealmModel realm = session.getContext().getRealm();
        StatusListConfig config = new StatusListConfig(session, realm);
        this.statusListService = new StatusListService(config);
    }

    @Override
    public void onEvent(Event event) {
        // Check if this is a custom SD-JWT event
        if (isSDJwtEvent(event.getType().name())) {
            logger.debug("Processing SD-JWT event: " + event.getType().name());

            try {
                RealmModel realm = session.realms().getRealm(event.getRealmId());
                TokenStatusRecord statusRecord = createStatusRecord(event, realm);

                if (statusRecord != null) {
                    try {
                        if (event.getType().name().equals(SD_JWT_REVOKED)) {
                            statusListService.revokeCredential(statusRecord);
                            logger.info("Successfully revoked SD-JWT credential: " + statusRecord.getCredentialId());
                        } else {
                            statusListService.registerCredential(statusRecord);
                            logger.info("Successfully registered SD-JWT credential: " + statusRecord.getCredentialId());
                        }
                    } catch (StatusListException e) {
                        logger.error("Error publishing credential status: " + e.getMessage(), e);
                    }
                }
            } catch (Exception e) {
                logger.error("Error processing SD-JWT event: " + e.getMessage(), e);
            }
        }
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean includeRepresentation) {
        // Handle potential admin events related to SD-JWT credentials
        if (adminEvent.getResourceType() == ResourceType.USER_FEDERATION_MAPPER) {
            if (adminEvent.getOperationType() == OperationType.DELETE &&
                    adminEvent.getRepresentation() != null &&
                    adminEvent.getRepresentation().contains("sd_jwt")) {

                logger.debug("Processing SD-JWT admin event: " + adminEvent.getOperationType());

                // Extract credential ID and submit revocation
                // This would require parsing the representation to extract the SD-JWT credential ID
                // and other necessary details
            }
        }
    }

    @Override
    public void close() {
        // No resources to close
    }

    private boolean isSDJwtEvent(String eventType) {
        return eventType.equals(SD_JWT_ISSUED) ||
                eventType.equals(SD_JWT_REVOKED) ||
                eventType.equals(SD_JWT_UPDATED);
    }

    private TokenStatusRecord createStatusRecord(Event event, RealmModel realm) {
        Map<String, String> details = event.getDetails();
        String credentialId = details.get("credential_id");

        if (credentialId == null) {
            logger.debug("No credential_id in event details, skipping");
            return null;
        }

        TokenStatusRecord statusRecord = new TokenStatusRecord();
        statusRecord.setCredentialId(credentialId);
        statusRecord.setIssuerId(realm.getName());
        statusRecord.setCredentialType("VerifiableCredential");

        String eventType = event.getType().name();

        if (eventType.equals(SD_JWT_ISSUED)) {
            statusRecord.setStatus(TokenStatus.ACTIVE);
            statusRecord.setIssuedAt(Instant.now());

            String exp = details.get("expires_at");
            if (exp != null) {
                try {
                    statusRecord.setExpiresAt(Instant.ofEpochSecond(Long.parseLong(exp)));
                } catch (NumberFormatException e) {
                    logger.warn("Invalid expiration time format: " + exp);
                }
            }
        } else if (eventType.equals(SD_JWT_REVOKED)) {
            statusRecord.setStatus(TokenStatus.REVOKED);
            statusRecord.setRevokedAt(Instant.now());
            statusRecord.setStatusReason(details.get("revocation_reason"));
        }

        return statusRecord;
    }
}