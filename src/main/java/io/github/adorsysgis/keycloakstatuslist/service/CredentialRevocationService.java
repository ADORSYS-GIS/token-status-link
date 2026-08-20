package io.github.adorsysgis.keycloakstatuslist.service;

import static io.github.adorsysgis.keycloakstatuslist.service.StatusListService.StatusListPayload;
import static io.github.adorsysgis.keycloakstatuslist.service.StatusListService.StatusListPayload.StatusEntry;

import io.github.adorsysgis.keycloakstatuslist.client.ApacheHttpStatusListClient;
import io.github.adorsysgis.keycloakstatuslist.client.StatusListHttpClient;
import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import io.github.adorsysgis.keycloakstatuslist.exception.StatusListException;
import io.github.adorsysgis.keycloakstatuslist.exception.StatusListServerException;
import io.github.adorsysgis.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import io.github.adorsysgis.keycloakstatuslist.jpa.repository.StatusListRepository;
import io.github.adorsysgis.keycloakstatuslist.model.CredentialRevocationRequest;
import io.github.adorsysgis.keycloakstatuslist.model.CredentialRevocationResponse;
import io.github.adorsysgis.keycloakstatuslist.model.IssuedCredentialStatusResponse;
import io.github.adorsysgis.keycloakstatuslist.model.IssuedCredentialStatusResponse.IssuedCredentialStatus;
import io.github.adorsysgis.keycloakstatuslist.model.TokenStatus;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.jboss.logging.Logger;
import org.keycloak.models.IssuedVerifiableCredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.keycloak.utils.StringUtil;

/**
 * Main service for revoking Keycloak-tracked issued credentials through the Token Status List server.
 */
public class CredentialRevocationService {

    private static final Logger logger = Logger.getLogger(CredentialRevocationService.class);

    private final KeycloakSession session;
    private final StatusListRepository statusListRepository;
    private StatusListService statusListService;

    public CredentialRevocationService(KeycloakSession session, StatusListService statusListService) {
        this(session, statusListService, session == null ? null : new StatusListRepository(session));
    }

    public CredentialRevocationService(
            KeycloakSession session, StatusListService statusListService, StatusListRepository statusListRepository) {
        this.session = session;
        this.statusListService = statusListService;
        this.statusListRepository = statusListRepository;
    }

    public CredentialRevocationService(KeycloakSession session) {
        this(session, null);
    }

    /**
     * Gets or creates the StatusListService instance.
     */
    private StatusListService getStatusListService() {
        if (statusListService == null) {
            RealmModel realm = session.getContext().getRealm();
            StatusListConfig config = new StatusListConfig(realm);
            CryptoIdentityService cryptoIdentityService = new CryptoIdentityService(session);

            CircuitBreaker circuitBreaker = CircuitBreaker.getInstance(config);

            StatusListHttpClient httpClient = new ApacheHttpStatusListClient(
                    config.getServerUrl(),
                    cryptoIdentityService.getJwtToken(config),
                    CustomHttpClient.getHttpClient(config),
                    circuitBreaker);
            this.statusListService = new StatusListService(httpClient);
        }
        return statusListService;
    }

    /**
     * Revokes a Keycloak-tracked issued credential on behalf of the authenticated client application user.
     */
    public CredentialRevocationResponse revokeIssuedCredential(
            CredentialRevocationRequest request, AuthResult authResult) throws StatusListException {

        String requestId = UUID.randomUUID().toString();
        if (request == null) {
            throw new IllegalArgumentException("Revocation request is required");
        }
        if (StringUtil.isBlank(request.getCredentialId())) {
            throw new IllegalArgumentException("Missing credential_id");
        }

        UserModel user = getAuthenticatedUser(authResult);
        RealmModel realm = session.getContext().getRealm();
        String userId = user.getId();
        String credentialId = request.getCredentialId().trim();

        logger.infof(
                "Processing issued credential revocation request. RequestId: %s, UserId: %s, CredentialId: %s",
                requestId, userId, credentialId);

        try {
            IssuedVerifiableCredentialModel issuedCredential = session.users()
                    .getIssuedVerifiableCredentialsStreamByUser(userId)
                    .filter(issued -> credentialId.equals(issued.getId()))
                    .findFirst()
                    .orElseThrow(() -> new StatusListException("Issued credential not found", 404));

            StatusListMappingEntity mapping = findStatusListMapping(realm.getId(), userId, issuedCredential);
            StatusEntry statusEntry = new StatusEntry(mapping.getIdx(), TokenStatus.INVALID);
            StatusListPayload revocationPayload =
                    new StatusListPayload(mapping.getStatusListId(), List.of(statusEntry));
            getStatusListService().updateStatusList(revocationPayload, requestId);
            mapping.setTokenStatus(TokenStatus.INVALID);
            statusListRepository.save(mapping);

            Instant revokedAt = Instant.now();
            logger.infof(
                    "Successfully revoked issued credential. RequestId: %s, CredentialId: %s, RevokedAt: %s",
                    requestId, credentialId, revokedAt);

            return CredentialRevocationResponse.success(revokedAt, request.getRevocationReason());

        } catch (StatusListServerException e) {
            logger.errorf(
                    "Status list server error. RequestId: %s, StatusCode: %d, Error: %s",
                    requestId, e.getStatusCode(), e.getMessage());
            throw e;
        } catch (StatusListException e) {
            logger.errorf("Issued credential revocation failed. RequestId: %s, Error: %s", requestId, e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.errorf(
                    "Unexpected error during issued credential revocation. RequestId: %s, Error: %s",
                    requestId, e.getMessage(), e);
            throw new StatusListException("Failed to process issued credential revocation: " + e.getMessage(), e);
        }
    }

    /**
     * Lists the authenticated user's issued credentials with status from the plugin mapping table.
     */
    public IssuedCredentialStatusResponse getIssuedCredentialStatuses(AuthResult authResult) {
        UserModel user = getAuthenticatedUser(authResult);
        RealmModel realm = session.getContext().getRealm();
        String userId = user.getId();

        List<IssuedVerifiableCredentialModel> issuedCredentials = session.users()
                .getIssuedVerifiableCredentialsStreamByUser(userId)
                .toList();

        List<String> credentialIds = issuedCredentials.stream()
                .map(IssuedVerifiableCredentialModel::getId)
                .filter(StringUtil::isNotBlank)
                .toList();
        Map<String, StatusListMappingEntity> mappings =
                statusListRepository.findSuccessfulMappingsByTokenIds(realm.getId(), userId, credentialIds);

        List<IssuedCredentialStatus> statuses = issuedCredentials.stream()
                .map(credential -> toIssuedCredentialStatus(credential, mappings.get(credential.getId())))
                .toList();

        return new IssuedCredentialStatusResponse(statuses);
    }

    private UserModel getAuthenticatedUser(AuthResult authResult) {
        if (authResult == null) {
            throw new IllegalArgumentException("Authentication result is required");
        }

        UserModel user = authResult.user();
        if (user == null || StringUtil.isBlank(user.getId())) {
            throw new IllegalArgumentException("Authenticated user is required");
        }

        return user;
    }

    private IssuedCredentialStatus toIssuedCredentialStatus(
            IssuedVerifiableCredentialModel credential, StatusListMappingEntity mapping) {
        return new IssuedCredentialStatus(
                credential.getId(),
                credential.getVerifiableCredentialId(),
                credential.getIssuedAt(),
                credential.getExpiresAt(),
                credential.getClientId(),
                credential.getRevision(),
                resolveTokenStatus(mapping));
    }

    private String resolveTokenStatus(StatusListMappingEntity mapping) {
        if (mapping == null || mapping.getTokenStatus() == null) {
            return "UNKNOWN";
        }

        return mapping.getTokenStatus().name();
    }

    private StatusListMappingEntity findStatusListMapping(
            String realmId, String userId, IssuedVerifiableCredentialModel issuedCredential)
            throws StatusListException {
        if (statusListRepository == null) {
            throw new StatusListException("Status list mapping repository is not available", 500);
        }

        String issuedCredentialId = issuedCredential.getId();
        if (StringUtil.isBlank(issuedCredentialId)) {
            throw new IllegalStateException("Issued credential is missing its Keycloak id");
        }

        return statusListRepository
                .findSuccessfulMappingByTokenId(realmId, userId, issuedCredentialId)
                .orElseThrow(() -> new StatusListException("Status list mapping not found for issued credential", 404));
    }
}
