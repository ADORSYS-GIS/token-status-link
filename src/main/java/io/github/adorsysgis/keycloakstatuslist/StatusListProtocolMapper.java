package io.github.adorsysgis.keycloakstatuslist;

import static io.github.adorsysgis.keycloakstatuslist.jpa.entity.StatusListMappingEntity.MappingStatus;

import io.github.adorsysgis.keycloakstatuslist.client.ApacheHttpStatusListClient;
import io.github.adorsysgis.keycloakstatuslist.client.StatusListHttpClient;
import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import io.github.adorsysgis.keycloakstatuslist.config.StatusListEndpointUriResolver;
import io.github.adorsysgis.keycloakstatuslist.exception.CredentialIssuanceQuotaException;
import io.github.adorsysgis.keycloakstatuslist.exception.StatusListException;
import io.github.adorsysgis.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import io.github.adorsysgis.keycloakstatuslist.jpa.repository.StatusListRepository;
import io.github.adorsysgis.keycloakstatuslist.model.Status;
import io.github.adorsysgis.keycloakstatuslist.model.StatusListClaim;
import io.github.adorsysgis.keycloakstatuslist.model.TokenStatus;
import io.github.adorsysgis.keycloakstatuslist.service.CircuitBreaker;
import io.github.adorsysgis.keycloakstatuslist.service.CredentialIssuanceQuotaService;
import io.github.adorsysgis.keycloakstatuslist.service.CryptoIdentityService;
import io.github.adorsysgis.keycloakstatuslist.service.CustomHttpClient;
import io.github.adorsysgis.keycloakstatuslist.service.IssuedCredentialIdResolver;
import io.github.adorsysgis.keycloakstatuslist.service.IssuedCredentialIdResolver.OpenidCredentialAuthorization;
import io.github.adorsysgis.keycloakstatuslist.service.RejectedIssuanceCleanup;
import io.github.adorsysgis.keycloakstatuslist.service.StatusListService;
import jakarta.persistence.EntityManager;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.apache.commons.collections4.ListUtils;
import org.apache.hc.core5.http.URIScheme;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.oid4vc.issuance.mappers.OID4VCMapper;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.utils.StringUtil;

/**
 * Protocol mapper for adding `status_list` claims to issued Verifiable
 * Credentials, as per the
 * <a href=
 * "https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-11.html#name-referenced-token">
 * Token Status List </a> specification.
 */
public class StatusListProtocolMapper extends OID4VCMapper {

    private static final Logger logger = Logger.getLogger(StatusListProtocolMapper.class);
    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty maxCredentialsPerUser = new ProviderConfigProperty();
        maxCredentialsPerUser.setName(StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER);
        maxCredentialsPerUser.setLabel("Max credentials per user");
        maxCredentialsPerUser.setHelpText(
                "Maximum number of non-revoked credentials of this type a holder may have. Leave empty or set to 0 for unlimited.");
        maxCredentialsPerUser.setType(ProviderConfigProperty.STRING_TYPE);
        maxCredentialsPerUser.setDefaultValue("0");
        CONFIG_PROPERTIES.add(maxCredentialsPerUser);
    }

    private final KeycloakSession session;
    private final StatusListService statusListService;
    private final StatusListRepository statusListRepository;
    private final IssuedCredentialIdResolver issuedCredentialIdResolver;
    private final CredentialIssuanceQuotaService credentialIssuanceQuotaService;
    private final RejectedIssuanceCleanup rejectedIssuanceCleanup;

    public StatusListProtocolMapper() {
        // An empty mapper constructor is required by Keycloak
        this.session = null;
        this.statusListService = null;
        this.statusListRepository = null;
        this.issuedCredentialIdResolver = null;
        this.credentialIssuanceQuotaService = null;
        this.rejectedIssuanceCleanup = null;
    }

    public StatusListProtocolMapper(KeycloakSession session) {
        this.session = session;
        this.statusListRepository = new StatusListRepository(session);
        // Only build the status list client when the feature is explicitly opted in for the realm and a
        // usable server URL is configured. This keeps the mapper constructible for realms where the feature
        // is disabled (the default) or misconfigured, so it never blocks credential-issuer metadata discovery.
        // Misconfiguration is instead reported on the issuance path, honoring status-list-mandatory.
        StatusListConfig config = new StatusListConfig(session.getContext().getRealm());
        this.statusListService =
                config.isEnabled() && isValidHttpUrl(config.getServerUrl()) ? createStatusListService(session) : null;
        this.issuedCredentialIdResolver = new IssuedCredentialIdResolver(session);
        this.credentialIssuanceQuotaService = new CredentialIssuanceQuotaService(session, statusListRepository);
        this.rejectedIssuanceCleanup = new RejectedIssuanceCleanup(session, statusListRepository);
    }

    /**
     * Builds a StatusListService for the given session (config, circuit breaker, HTTP client).
     * Wiring lives here so StatusListService stays agnostic of the concrete HTTP client implementation.
     */
    private static StatusListService createStatusListService(KeycloakSession session) {
        StatusListConfig config = new StatusListConfig(session.getContext().getRealm());
        CryptoIdentityService cryptoIdentityService = new CryptoIdentityService(session);

        CircuitBreaker circuitBreaker = null;
        if (config.getIssuanceTimeout() > 0) {
            circuitBreaker = CircuitBreaker.getInstance(config);
        }

        StatusListHttpClient httpClient = new ApacheHttpStatusListClient(
                config.getServerUrl(),
                cryptoIdentityService.getJwtToken(config),
                CustomHttpClient.getHttpClient(config),
                circuitBreaker);

        return new StatusListService(httpClient);
    }

    @Override
    public List<String> getMetadataAttributePath() {
        return ListUtils.union(getAttributePrefix(), List.of(Constants.STATUS_CLAIM_KEY));
    }

    @Override
    public ProtocolMapper create(KeycloakSession session) {
        return new StatusListProtocolMapper(session);
    }

    @Override
    public String getId() {
        return Constants.MAPPER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Status List Claim Mapper";
    }

    @Override
    public String getHelpText() {
        return """
                Adds a status list claim to issued verifiable credentials.
                The status list server URL is configured at the realm level.
                Optionally limits how many non-revoked credentials of this type a holder may have.
                """;
    }

    @Override
    public boolean includeInMetadata() {
        return false; // Exclude explicit mention in Credential Issuer Metadata
    }

    @Override
    protected List<ProviderConfigProperty> getIndividualConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    private StatusListConfig getStatusListConfig(RealmModel realm) {
        return new StatusListConfig(realm);
    }

    @Override
    public void close() {
        // No resources to close
    }

    @Override
    public void setClaim(VerifiableCredential verifiableCredential, UserSessionModel userSessionModel) {
        // No-op. W3C Verifiable Credentials are not supported by this mapper.
    }

    @Override
    public void setClaim(Map<String, Object> claims, UserSessionModel userSessionModel) {
        logger.debugf("Adding status list data to credential claims (TokenStatusList)");
        if (session == null) {
            logger.error("Keycloak session is not available.");
            return;
        }

        String clientId = session.getContext().getClient().getClientId();
        String realmId = session.getContext().getRealm().getId();
        logger.debugf("Setting claim for client: %s, realm: %s", clientId, realmId);

        StatusListConfig config = getStatusListConfig(session.getContext().getRealm());

        // Guard: Status list feature is disabled
        if (!config.isEnabled()) {
            logger.debugf("Status list is disabled for realm: %s", realmId);
            return;
        }

        // Guard: Server URL is invalid
        String serverUrl = config.getServerUrl();
        if (!isValidHttpUrl(serverUrl)) {
            logger.errorf("Invalid status list server URL for realm %s: %s", realmId, serverUrl);
            failIssuanceIfMandatory(config);
            return;
        }

        OpenidCredentialAuthorization authorization = issuedCredentialIdResolver.resolveOpenidCredential();
        String issuedCredentialId = authorization.issuedCredentialId().orElse(null);
        String tokenId = resolveTokenId(claims, authorization.issuedCredentialId());
        String userId = resolveHolderUserId(userSessionModel);
        String credentialConfigurationId =
                authorization.credentialConfigurationId().orElse(null);
        Status status;
        try {
            int maxCredentialsPerUser = credentialIssuanceQuotaService.resolveMax(
                    mapperModel, session.getContext().getRealm());
            credentialIssuanceQuotaService.requireHolderAndTypeWhenLimited(
                    userId, credentialConfigurationId, maxCredentialsPerUser);

            status = sendStatusAndStoreIndexMapping(
                    serverUrl,
                    userId,
                    tokenId,
                    credentialConfigurationId,
                    maxCredentialsPerUser,
                    config.getStatusListMaxEntries());
        } catch (RuntimeException e) {
            discardRejectedIssuance(realmId, issuedCredentialId);
            throw e;
        }

        if (status == null) {
            if (config.isMandatory()) {
                discardRejectedIssuance(realmId, issuedCredentialId);
            }
            failIssuanceIfMandatory(config);
            return;
        }

        logger.infof("Adding status claim of value: %s", status);
        claims.put(Constants.STATUS_CLAIM_KEY, status);
    }

    private void failIssuanceIfMandatory(StatusListConfig config) {
        if (config.isMandatory()) {
            logger.error("Status list is mandatory and publication failed; failing issuance");
            throw new RuntimeException("Status list publication failed and is mandatory");
        }

        logger.warn("Status list publication failed; proceeding without status claim");
    }

    private boolean isValidHttpUrl(String url) {
        if (url == null) {
            return false;
        }

        try {
            URI uri = new URI(url);
            String scheme = uri.getScheme();
            return URIScheme.HTTP.same(scheme) || URIScheme.HTTPS.same(scheme);
        } catch (URISyntaxException e) {
            logger.debugf("Invalid URL format: %s", url);
            return false;
        }
    }

    /**
     * Drops the Keycloak issued-credential row when this mapper rejects issuance, and marks any
     * {@code INIT} reservation for that id as {@code FAILURE}. The row is created at token time,
     * before mappers run, and has no failed status to mark.
     */
    private void discardRejectedIssuance(String realmId, String issuedCredentialId) {
        if (rejectedIssuanceCleanup == null) {
            logger.error("Cannot delete orphan issued credential: cleanup is not available");
            return;
        }
        rejectedIssuanceCleanup.discard(realmId, issuedCredentialId);
    }

    private String resolveTokenId(Map<String, Object> claims, Optional<String> issuedCredentialId) {
        /*
         * Keycloak records the IssuedVerifiableCredentialModel id in the
         * authenticated OID4VCI access token authorization details before protocol
         * mappers run. We store it only as the status-list correlation key; the
         * revocation endpoint still enforces ownership from Keycloak's issued
         * credential store.
         */
        if (issuedCredentialId != null && issuedCredentialId.isPresent()) {
            return issuedCredentialId.get();
        }

        if (claims.get(Constants.ID_CLAIM_KEY) instanceof String id && StringUtil.isNotBlank(id)) {
            return id;
        }

        return null;
    }

    private String resolveHolderUserId(UserSessionModel userSessionModel) {
        UserModel holder = userFrom(userSessionModel);
        if (holder == null) {
            holder = userFrom(session.getContext().getUserSession());
        }
        if (holder == null) {
            return null;
        }

        String userId = holder.getId();
        return StringUtil.isBlank(userId) ? null : userId;
    }

    private static UserModel userFrom(UserSessionModel userSession) {
        return userSession == null ? null : userSession.getUser();
    }

    /**
     * Send status to server to create status list entry and store index mapping in database.
     * List-id choice, quota check, and {@code INIT} reservation share one transaction that locks the
     * latest mapping for the realm, or the Keycloak realm row when no mapping exists yet.
     */
    public Status sendStatusAndStoreIndexMapping(
            String serverUrl,
            String userId,
            String tokenId,
            String credentialConfigurationId,
            int maxCredentialsPerUser,
            int maxEntries) {
        StatusListMappingEntity mapping = createInitialMapping(userId, tokenId, credentialConfigurationId);
        if (!reserveIndex(mapping, maxCredentialsPerUser, maxEntries)) {
            return null;
        }

        String uri = new StatusListEndpointUriResolver(serverUrl).statusListUrl(mapping.getStatusListId());
        logger.debugf("Configuration: listId=%s, uri=%s", mapping.getStatusListId(), uri);
        Status status = publishInitialStatus(mapping, uri);
        if (!persistCompletionStatus(mapping)) {
            return null;
        }

        return status;
    }

    private StatusListMappingEntity createInitialMapping(
            String userId, String tokenId, String credentialConfigurationId) {
        StatusListMappingEntity mapping = new StatusListMappingEntity();
        mapping.setUserId(userId);
        mapping.setTokenId(tokenId);
        mapping.setCredentialConfigurationId(credentialConfigurationId);
        mapping.setRealmId(session.getContext().getRealm().getId());
        mapping.setTokenStatus(TokenStatus.VALID);
        return mapping;
    }

    private boolean reserveIndex(StatusListMappingEntity mapping, int maxCredentialsPerUser, int maxEntries) {
        try {
            statusListRepository.withEntityManagerInTransaction(em -> {
                StatusListMappingEntity latest = statusListRepository.lockLatestMapping(em, mapping.getRealmId());
                mapping.setStatusListId(statusListRepository.getNextStatusListId(latest, maxEntries));
                logger.debugf(
                        "Booking next index for status list mapping: status_list_id=%s, userId=%s, tokenId=%s",
                        mapping.getStatusListId(), mapping.getUserId(), mapping.getTokenId());
                credentialIssuanceQuotaService.enforceWithinReservationTransaction(
                        em,
                        mapping.getRealmId(),
                        mapping.getUserId(),
                        mapping.getCredentialConfigurationId(),
                        maxCredentialsPerUser);
                persistInitialMapping(em, mapping);
            });
            return true;
        } catch (RuntimeException e) {
            if (e instanceof CredentialIssuanceQuotaException) {
                throw e;
            }
            logger.error("Failed to initiate index mapping", e);
            return false;
        }
    }

    private void persistInitialMapping(EntityManager entityManager, StatusListMappingEntity mapping) {
        Long idx = statusListRepository.getNextIndex(entityManager, mapping.getStatusListId());
        logger.debugf("Next available index is: %d", idx);

        mapping.setIdx(idx);
        mapping.setStatus(MappingStatus.INIT);

        entityManager.persist(mapping);
        entityManager.flush();
    }

    private Status publishInitialStatus(StatusListMappingEntity mapping, String uri) {
        try {
            logger.debugf("Sending token status for generated index: %d", mapping.getIdx());
            sendStatusToServer(mapping.getIdx(), mapping.getStatusListId());
            mapping.setStatus(MappingStatus.SUCCESS);
            return new Status(new StatusListClaim(mapping.getIdx(), uri));
        } catch (StatusListException | IOException e) {
            logger.error("Failed to send token status", e);
            mapping.setStatus(MappingStatus.FAILURE);
            return null;
        }
    }

    private boolean persistCompletionStatus(StatusListMappingEntity mapping) {
        try {
            logger.debugf("Persisting completion mapping status: %s", mapping.getStatus());
            statusListRepository.save(mapping);
            return true;
        } catch (RuntimeException e) {
            logger.error("Failed to persist completion mapping status", e);
            return false;
        }
    }

    private void sendStatusToServer(long idx, String statusListId) throws IOException, StatusListException {
        if (statusListService == null) {
            throw new StatusListException("statusListService unexpected null. Cannot send status to server");
        }

        // Prepare payload
        StatusListService.StatusListPayload payload = new StatusListService.StatusListPayload(
                statusListId, List.of(new StatusListService.StatusListPayload.StatusEntry(idx, TokenStatus.VALID)));

        // Publish or update status list on server
        statusListService.publishOrUpdate(payload);
    }

    public interface Constants {
        String MAPPER_ID = "oid4vc-status-list-claim-mapper";

        String ID_CLAIM_KEY = "id";
        String STATUS_CLAIM_KEY = "status";
    }
}
