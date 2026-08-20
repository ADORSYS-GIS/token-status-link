package com.adorsys.keycloakstatuslist.service;

import static com.adorsys.keycloakstatuslist.service.StatusListService.StatusListPayload;
import static com.adorsys.keycloakstatuslist.service.StatusListService.StatusListPayload.StatusEntry;

import com.adorsys.keycloakstatuslist.client.ApacheHttpStatusListClient;
import com.adorsys.keycloakstatuslist.client.StatusListHttpClient;
import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import com.adorsys.keycloakstatuslist.jpa.repository.StatusListRepository;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationResponse;
import com.adorsys.keycloakstatuslist.model.IssuedCredentialStatusResponse;
import com.adorsys.keycloakstatuslist.model.IssuedCredentialStatusResponse.IssuedCredentialStatus;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
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
        validateRevocationRequest(request);
        UserModel user = getAuthenticatedUser(authResult);

        RealmModel realm = session.getContext().getRealm();
        String userId = user.getId();
        String credentialId = request.getCredentialId().trim();

        logger.infof(
                "Processing issued credential revocation request. RequestId: %s, UserId: %s, CredentialId: %s",
                requestId, userId, credentialId);

        IssuedVerifiableCredentialModel issuedCredential = findIssuedCredential(userId, credentialId);
        StatusListMappingEntity mapping = findStatusListMapping(realm.getId(), userId, issuedCredential);
        revokeStatusListEntry(mapping, requestId);

        Instant revokedAt = Instant.now();
        logger.infof(
                "Successfully revoked issued credential. RequestId: %s, CredentialId: %s, RevokedAt: %s",
                requestId, credentialId, revokedAt);

        return CredentialRevocationResponse.success(revokedAt, request.getRevocationReason());
    }

    private void validateRevocationRequest(CredentialRevocationRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Revocation request is required");
        }
        if (StringUtil.isBlank(request.getCredentialId())) {
            throw new IllegalArgumentException("Missing credential_id");
        }
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

    private IssuedVerifiableCredentialModel findIssuedCredential(String userId, String credentialId)
            throws StatusListException {
        return session.users()
                .getIssuedVerifiableCredentialsStreamByUser(userId)
                .filter(issued -> credentialId.equals(issued.getId()))
                .findFirst()
                .orElseThrow(() -> new StatusListException("Issued credential not found", 404));
    }

    private void revokeStatusListEntry(StatusListMappingEntity mapping, String requestId) throws StatusListException {
        StatusEntry statusEntry = new StatusEntry(mapping.getIdx(), TokenStatus.INVALID);
        StatusListPayload revocationPayload = new StatusListPayload(mapping.getStatusListId(), List.of(statusEntry));
        getStatusListService().updateStatusList(revocationPayload, requestId);
        mapping.setTokenStatus(TokenStatus.INVALID);
        statusListRepository.save(mapping);
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
