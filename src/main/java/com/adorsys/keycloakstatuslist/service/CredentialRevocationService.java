package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationResponse;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
import com.adorsys.keycloakstatuslist.service.http.CloseableHttpClientAdapter;
import com.adorsys.keycloakstatuslist.service.http.HttpClient;
import com.adorsys.keycloakstatuslist.service.validation.RequestValidationService;
import com.adorsys.keycloakstatuslist.service.validation.SdJwtVPValidationService;

import java.time.Instant;
import java.util.UUID;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sdjwt.vp.SdJwtVP;

/**
 * Main service for handling credential revocation requests. Orchestrates the revocation process
 * using specialized service classes.
 */
public class CredentialRevocationService {

    private static final Logger logger = Logger.getLogger(CredentialRevocationService.class);

    private final KeycloakSession session;
    private final SdJwtVPValidationService sdJwtVPValidationService;
    private final RevocationRecordService revocationRecordService;
    private final RequestValidationService requestValidationService;
    private StatusListService statusListService;

    public CredentialRevocationService(
            KeycloakSession session,
            StatusListService statusListService,
            SdJwtVPValidationService sdJwtVPValidationService,
            RevocationRecordService revocationRecordService,
            RequestValidationService requestValidationService) {
        this.session = session;
        this.statusListService = statusListService;
        this.sdJwtVPValidationService = sdJwtVPValidationService;
        this.revocationRecordService = revocationRecordService;
        this.requestValidationService = requestValidationService;
    }

    public CredentialRevocationService(KeycloakSession session) {
        this(
                session,
                null, // lazily initialized when first used
                new DefaultSdJwtVPValidationService(session),
                new RevocationRecordService(session),
                new DefaultRequestValidationService());
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
            this.statusListService =
                    new StatusListService(
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

        requestValidationService.validateRevocationRequest(request);

        logger.infof("Processing credential revocation request. RequestId: %s, CredentialId: %s",
                requestId, request.getCredentialId());

        try {
            SdJwtVP sdJwtVP = sdJwtVPValidationService.parseAndValidateSdJwtVP(sdJwtVpToken, requestId);
            sdJwtVPValidationService.verifyCredentialOwnership(sdJwtVP, request.getCredentialId(), requestId);

            TokenStatusRecord revocationRecord = revocationRecordService.createRevocationRecord(request, requestId);
            getStatusListService().publishRecord(revocationRecord);

            Instant revokedAt = Instant.now();
            logger.infof("Successfully revoked credential. RequestId: %s, CredentialId: %s, RevokedAt: %s",
                    requestId, request.getCredentialId(), revokedAt);

            return CredentialRevocationResponse.success(
                    request.getCredentialId(),
                    revokedAt,
                    request.getRevocationReason()
            );

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
}
