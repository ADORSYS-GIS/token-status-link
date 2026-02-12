package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.exception.StatusListServerException;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationResponse;
import com.adorsys.keycloakstatuslist.model.RevocationChallenge;
import com.adorsys.keycloakstatuslist.model.Status;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.adorsys.keycloakstatuslist.service.http.CloseableHttpClientAdapter;
import com.adorsys.keycloakstatuslist.service.http.HttpClient;
import com.adorsys.keycloakstatuslist.service.nonce.NonceCacheProvider;
import com.adorsys.keycloakstatuslist.service.nonce.NonceCacheServiceProviderFactory;
import com.adorsys.keycloakstatuslist.service.validation.SdJwtVPValidationService;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.util.JsonSerialization;

import static com.adorsys.keycloakstatuslist.service.StatusListService.StatusListPayload.StatusEntry;
import static com.adorsys.keycloakstatuslist.service.StatusListService.StatusListPayload;

/**
 * Main service for handling credential revocation requests. Orchestrates the
 * revocation process using specialized service classes.
 */
public class CredentialRevocationService {

    private static final Logger logger = Logger.getLogger(CredentialRevocationService.class);

    private final KeycloakSession session;
    private final SdJwtVPValidationService sdJwtVPValidationService;
    private StatusListService statusListService;

    public CredentialRevocationService(
            KeycloakSession session,
            StatusListService statusListService,
            SdJwtVPValidationService sdJwtVPValidationService) {
        this.session = session;
        this.statusListService = statusListService;
        this.sdJwtVPValidationService = sdJwtVPValidationService;
    }

    public CredentialRevocationService(KeycloakSession session) {
        this(
                session,
                null, // lazily initialized when first used
                new DefaultSdJwtVPValidationService(session));
    }

    /**
     * Gets or creates the StatusListService instance.
     */
    private StatusListService getStatusListService() {
        if (statusListService == null) {
            RealmModel realm = session.getContext().getRealm();
            StatusListConfig config = new StatusListConfig(realm);
            CryptoIdentityService cryptoIdentityService = new CryptoIdentityService(session);
            HttpClient httpClient = new CloseableHttpClientAdapter(CustomHttpClient.getHttpClient());
            this.statusListService = new StatusListService(
                    config.getServerUrl(),
                    cryptoIdentityService.getJwtToken(config),
                    httpClient);
        }
        return statusListService;
    }

    /**
     * Processes a credential revocation request.
     *
     * @param request      the revocation request containing credential ID and revocation reason
     * @param sdJwtVpToken the SD-JWT VP token from the Authorization header
     * @return response indicating success or failure of the revocation
     * @throws StatusListException if revocation processing fails
     */
    public CredentialRevocationResponse revokeCredential(CredentialRevocationRequest request, String sdJwtVpToken)
            throws StatusListException {

        String requestId = UUID.randomUUID().toString();
        Objects.requireNonNull(request);

        logger.infof("Processing credential revocation request. RequestId: %s",
                requestId);

        try {
            // Step 1: Parse the SD-JWT VP (without full verification yet)
            SdJwtVP sdJwtVP = sdJwtVPValidationService.parseAndValidateSdJwtVP(sdJwtVpToken, requestId);

            // Step 2: SECURITY - Validate nonce to prevent replay attacks
            RevocationChallenge challenge = validateNonce(sdJwtVP, requestId);

            // Step 3: Verify the SD-JWT VP signature using the expected nonce from the challenge
            sdJwtVPValidationService.verifySdJwtVP(sdJwtVP, requestId, challenge.getNonce());

            // Step 5: Publish revocation record
            StatusListPayload revocationPayload = buildRevocationPayload(sdJwtVP);
            getStatusListService().updateStatusList(revocationPayload, requestId);

            Instant revokedAt = Instant.now();
            logger.infof("Successfully revoked credential. RequestId: %s, RevokedAt: %s",
                    requestId, revokedAt);

            return CredentialRevocationResponse.success(
                    revokedAt,
                    request.getRevocationReason());

        } catch (StatusListServerException e) {
            logger.errorf("Status list server error. RequestId: %s, StatusCode: %d, Error: %s",
                    requestId, e.getStatusCode(), e.getMessage());
            throw e;
        } catch (StatusListException e) {
            logger.errorf(
                    "Status list operation failed. RequestId: %s, Error: %s", requestId, e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.errorf("Unexpected error during credential revocation. RequestId: %s, Error: %s",
                    requestId, e.getMessage(), e);
            throw new StatusListException("Failed to process credential revocation: " + e.getMessage(), e);
        }
    }

    /**
     * Validates the nonce from the Key Binding JWT to prevent replay attacks.
     * This is a critical security check that ensures each revocation request uses a fresh, one-time nonce.
     * 
     * @param sdJwtVP   the SD-JWT VP token
     * @param requestId the request ID for logging
     * @return the validated RevocationChallenge containing the expected nonce
     * @throws StatusListException if nonce validation fails
     */
    private RevocationChallenge validateNonce(SdJwtVP sdJwtVP, String requestId)
            throws StatusListException {

        // Extract nonce from Key Binding JWT
        String presentedNonce = sdJwtVPValidationService.extractNonceFromKeyBindingJWT(sdJwtVP);

        if (presentedNonce == null || presentedNonce.trim().isEmpty()) {
            logger.errorf("Missing nonce in Key Binding JWT. RequestId: %s",
                    requestId);
            throw new StatusListException("Invalid or missing nonce in Key Binding JWT", 401);
        }

        // Get nonce service provider via RealmResourceProvider
        NonceCacheProvider nonceService = (NonceCacheProvider) session.getProvider(
                RealmResourceProvider.class, NonceCacheServiceProviderFactory.PROVIDER_ID);

        if (nonceService == null) {
            logger.errorf("NonceCacheProvider not available. RequestId: %s", requestId);
            throw new StatusListException("Nonce validation service not available", 500);
        }

        // Consume the nonce (one-time use)
        RevocationChallenge challenge = nonceService.consumeNonce(presentedNonce);

        if (challenge == null) {
            logger.errorf("Invalid, expired, or replayed nonce. RequestId: %s, Nonce: %s",
                    requestId, presentedNonce);
            throw new StatusListException("Invalid, expired, or replayed nonce", 401);
        }

        logger.infof("Nonce validated successfully. RequestId: %s, Nonce: %s",
                requestId, presentedNonce);

        return challenge;
    }

    /**
     * Build revocation payload from status list references in SD-JWT.
     */
    private StatusListPayload buildRevocationPayload(SdJwtVP sdJwtVP) throws JsonProcessingException {
        ObjectNode issuerPayload = sdJwtVP.getIssuerSignedJWT().getPayload();
        Status status = JsonSerialization.mapper.treeToValue(issuerPayload.get("status"), Status.class);

        long idx = status.getStatusList().getIdx();
        String listId = URI.create(status.getStatusList().getUri())
                .getPath().replaceAll(".*/", "");

        StatusEntry statusEntry = new StatusEntry(idx, TokenStatus.INVALID.getValue());
        return new StatusListPayload(listId, List.of(statusEntry));
    }
}
