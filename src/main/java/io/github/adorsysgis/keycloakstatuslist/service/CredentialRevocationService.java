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
import io.github.adorsysgis.keycloakstatuslist.model.IssuedCredentialStatusResponse.DanglingIssuedCredentials;
import io.github.adorsysgis.keycloakstatuslist.model.IssuedCredentialStatusResponse.IssuedCredentialLimit;
import io.github.adorsysgis.keycloakstatuslist.model.IssuedCredentialStatusResponse.IssuedCredentialStatus;
import io.github.adorsysgis.keycloakstatuslist.model.TokenStatus;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.apache.hc.core5.http.HttpStatus;
import org.jboss.logging.Logger;
import org.keycloak.constants.OID4VCIConstants;
import org.keycloak.models.ClientModel;
import org.keycloak.models.IssuedVerifiableCredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.oid4vc.IssuedVerifiableCredentialRepresentation;
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
     * Revokes a Keycloak-tracked issued credential. The caller must own the credential, or hold the
     * realm role {@code credential-offer-create} to revoke another user's credential in the same realm.
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
            StatusListMappingEntity mapping = resolveMappingForRevocation(user, realm, credentialId);
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
     * Lists issued credentials with status from the plugin mapping table.
     *
     * <p>Callers receive their own credentials unless they hold the realm role
     * {@code credential-offer-create} and pass {@code targetUser}. Callers without that role receive
     * {@code 403} if {@code target_user} is provided. {@code limits} describes the resolved holder's
     * configured quotas; an unknown {@code targetUser} yields an empty response. Issued credentials
     * without a {@code SUCCESS} status-list mapping are omitted from {@code credentials} and counted
     * in {@code dangling}.
     */
    public IssuedCredentialStatusResponse getIssuedCredentialStatuses(AuthResult authResult, String targetUser)
            throws StatusListException {
        UserModel caller = getAuthenticatedUser(authResult);
        RealmModel realm = session.getContext().getRealm();

        return resolveHolder(caller, realm, targetUser)
                .map(holder -> toStatusResponse(realm, holder))
                .orElseGet(() -> new IssuedCredentialStatusResponse(List.of()));
    }

    private IssuedCredentialStatusResponse toStatusResponse(RealmModel realm, UserModel holder) {
        String userId = holder.getId();
        List<IssuedVerifiableCredentialModel> issuedCredentials = session.users()
                .getIssuedVerifiableCredentialsStreamByUser(userId)
                .toList();
        List<String> credentialIds = issuedCredentials.stream()
                .map(IssuedVerifiableCredentialModel::getId)
                .filter(StringUtil::isNotBlank)
                .toList();
        List<IssuedCredentialLimit> limits = new CredentialIssuanceQuotaService(session, statusListRepository)
                .listLimits(realm, userId, credentialIds);
        Map<String, StatusListMappingEntity> mappings =
                statusListRepository.findSuccessfulMappingsByTokenIds(realm.getId(), userId, credentialIds);
        List<IssuedCredentialStatus> credentials = new ArrayList<>();
        int danglingCount = 0;
        for (IssuedVerifiableCredentialModel credential : issuedCredentials) {
            StatusListMappingEntity mapping = mappings.get(credential.getId());
            if (mapping == null) {
                danglingCount++;
                continue;
            }
            credentials.add(toIssuedCredentialStatus(credential, mapping, holder, realm));
        }
        return new IssuedCredentialStatusResponse(credentials, limits, DanglingIssuedCredentials.of(danglingCount));
    }

    private Optional<UserModel> resolveHolder(UserModel caller, RealmModel realm, String targetUser)
            throws StatusListException {
        if (StringUtil.isBlank(targetUser)) {
            return Optional.of(caller);
        }
        if (!isOfferAdmin(caller, realm)) {
            throw new StatusListException(
                    "Not authorized to list another user's issued credentials", HttpStatus.SC_FORBIDDEN);
        }

        return Optional.ofNullable(session.users().getUserByUsername(realm, targetUser.trim()));
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

    private StatusListMappingEntity resolveMappingForRevocation(UserModel caller, RealmModel realm, String credentialId)
            throws StatusListException {
        if (statusListRepository == null) {
            throw new StatusListException(
                    "Status list mapping repository is not available", HttpStatus.SC_INTERNAL_SERVER_ERROR);
        }

        if (isOfferAdmin(caller, realm)) {
            return resolveMappingAsOfferAdmin(realm.getId(), credentialId);
        }
        return resolveMappingAsOwner(realm.getId(), caller.getId(), credentialId);
    }

    private StatusListMappingEntity resolveMappingAsOwner(String realmId, String userId, String credentialId)
            throws StatusListException {
        IssuedVerifiableCredentialModel issuedCredential = findIssuedCredentialByUser(userId, credentialId)
                .orElseThrow(() -> new StatusListException("Issued credential not found", HttpStatus.SC_NOT_FOUND));

        String issuedCredentialId = issuedCredential.getId();
        if (StringUtil.isBlank(issuedCredentialId)) {
            throw new IllegalStateException("Issued credential is missing its Keycloak id");
        }

        return statusListRepository
                .findSuccessfulMappingByTokenId(realmId, userId, issuedCredentialId)
                .orElseThrow(() -> new StatusListException(
                        "Status list mapping not found for issued credential", HttpStatus.SC_NOT_FOUND));
    }

    private StatusListMappingEntity resolveMappingAsOfferAdmin(String realmId, String credentialId)
            throws StatusListException {
        StatusListMappingEntity mapping = statusListRepository
                .findSuccessfulMappingByTokenId(realmId, credentialId)
                .filter(candidate -> StringUtil.isNotBlank(candidate.getUserId()))
                .orElseThrow(() -> new StatusListException("Issued credential not found", HttpStatus.SC_NOT_FOUND));

        findIssuedCredentialByUser(mapping.getUserId(), credentialId)
                .orElseThrow(() -> new StatusListException("Issued credential not found", HttpStatus.SC_NOT_FOUND));

        return mapping;
    }

    private Optional<IssuedVerifiableCredentialModel> findIssuedCredentialByUser(String userId, String credentialId) {
        if (StringUtil.isBlank(userId)) {
            return Optional.empty();
        }

        return session.users()
                .getIssuedVerifiableCredentialsStreamByUser(userId)
                .filter(issued -> credentialId.equals(issued.getId()))
                .findFirst();
    }

    private boolean isOfferAdmin(UserModel user, RealmModel realm) {
        RoleModel offerAdminRole = realm.getRole(OID4VCIConstants.CREDENTIAL_OFFER_CREATE.getName());
        return offerAdminRole != null && user.hasRole(offerAdminRole);
    }

    private IssuedCredentialStatus toIssuedCredentialStatus(
            IssuedVerifiableCredentialModel credential,
            StatusListMappingEntity mapping,
            UserModel holder,
            RealmModel realm) {
        IssuedVerifiableCredentialRepresentation representation =
                ModelToRepresentation.toRepresentation(credential, session, realm);
        return new IssuedCredentialStatus(
                credential.getId(),
                credential.getVerifiableCredentialId(),
                representation.getCredentialType(),
                representation.getIssuedAt(),
                representation.getExpiresAt(),
                representation.getClientId(),
                resolveClientName(representation.getClientId(), realm),
                representation.getRevision(),
                resolveTokenStatus(mapping),
                holder.getId(),
                holder.getUsername());
    }

    /**
     * Matches Keycloak's account issued-credential enrichment: client.name, else public client id.
     */
    private String resolveClientName(String clientUuid, RealmModel realm) {
        if (clientUuid == null) {
            return null;
        }

        ClientModel client = realm.getClientById(clientUuid);
        if (client == null) {
            return null;
        }

        String name = client.getName();
        return StringUtil.isBlank(name) ? client.getClientId() : name;
    }

    private String resolveTokenStatus(StatusListMappingEntity mapping) {
        if (mapping == null || mapping.getTokenStatus() == null) {
            return "UNKNOWN";
        }

        return mapping.getTokenStatus().name();
    }
}
