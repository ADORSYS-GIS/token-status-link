package io.github.adorsysgis.keycloakstatuslist;

import static io.github.adorsysgis.keycloakstatuslist.jpa.entity.StatusListMappingEntity.MappingStatus;

import io.github.adorsysgis.keycloakstatuslist.client.ApacheHttpStatusListClient;
import io.github.adorsysgis.keycloakstatuslist.client.StatusListHttpClient;
import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import io.github.adorsysgis.keycloakstatuslist.config.StatusListEndpointUriResolver;
import io.github.adorsysgis.keycloakstatuslist.exception.StatusListException;
import io.github.adorsysgis.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import io.github.adorsysgis.keycloakstatuslist.jpa.repository.StatusListRepository;
import io.github.adorsysgis.keycloakstatuslist.model.Status;
import io.github.adorsysgis.keycloakstatuslist.model.StatusListClaim;
import io.github.adorsysgis.keycloakstatuslist.model.TokenStatus;
import io.github.adorsysgis.keycloakstatuslist.service.CircuitBreaker;
import io.github.adorsysgis.keycloakstatuslist.service.CryptoIdentityService;
import io.github.adorsysgis.keycloakstatuslist.service.CustomHttpClient;
import io.github.adorsysgis.keycloakstatuslist.service.IssuedCredentialIdResolver;
import io.github.adorsysgis.keycloakstatuslist.service.StatusListService;
import jakarta.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.apache.commons.collections4.ListUtils;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
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

    private final KeycloakSession session;
    private final StatusListService statusListService;
    private final StatusListRepository statusListRepository;
    private final IssuedCredentialIdResolver issuedCredentialIdResolver;

    public StatusListProtocolMapper() {
        // An empty mapper constructor is required by Keycloak
        this.session = null;
        this.statusListService = null;
        this.statusListRepository = null;
        this.issuedCredentialIdResolver = null;
    }

    public StatusListProtocolMapper(KeycloakSession session) {
        this.session = session;
        this.statusListRepository = new StatusListRepository(session);
        this.statusListService = createStatusListService(session);
        this.issuedCredentialIdResolver = new IssuedCredentialIdResolver(session);
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
            return;
        }

        // Build URI for status list
        String listId = statusListRepository.getNextStatusListId(realmId, config.getStatusListMaxEntries());
        StatusListEndpointUriResolver resolver = new StatusListEndpointUriResolver(serverUrl);
        URI uri = UriBuilder.fromUri(serverUrl)
                .path(resolver.statusListRetrievePath(listId))
                .build();
        logger.debugf("Configuration: listId=%s, uri=%s", listId, uri);

        String tokenId = resolveTokenId(claims);

        UserSessionModel userSession = session.getContext().getUserSession();
        String userId = userSession != null ? userSession.getUser().getId() : null;

        Status status = sendStatusAndStoreIndexMapping(listId, uri.toString(), userId, tokenId);

        if (status == null) {
            if (config.isMandatory()) {
                logger.error("Status list is mandatory and publication failed; failing issuance");
                throw new RuntimeException("Status list publication failed and is mandatory");
            }

            logger.warn("Status list publication failed; proceeding without status claim");
            return;
        }

        logger.infof("Adding status claim of value: %s", status);
        claims.put(Constants.STATUS_CLAIM_KEY, status);
    }

    private boolean isValidHttpUrl(String url) {
        try {
            URI uri = new URI(url);
            String scheme = uri.getScheme();
            return scheme != null && (scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"));
        } catch (URISyntaxException e) {
            logger.debugf("Invalid URL format: %s", url);
            return false;
        }
    }

    private String resolveTokenId(Map<String, Object> claims) {
        /*
         * Keycloak records the IssuedVerifiableCredentialModel id in the
         * authenticated OID4VCI access token authorization details before protocol
         * mappers run. We store it only as the status-list correlation key; the
         * revocation endpoint still enforces ownership from Keycloak's issued
         * credential store.
         */
        Optional<String> issuedCredentialId = issuedCredentialIdResolver.resolve();
        if (issuedCredentialId.isPresent()) {
            return issuedCredentialId.get();
        }

        if (claims.get(Constants.ID_CLAIM_KEY) instanceof String id && StringUtil.isNotBlank(id)) {
            return id;
        }

        return null;
    }

    /**
     * Send status to server to create status list entry and store index mapping in database.
     */
    public Status sendStatusAndStoreIndexMapping(String statusListId, String uri, String userId, String tokenId) {
        String realmId = session.getContext().getRealm().getId();
        StatusListMappingEntity mapping = new StatusListMappingEntity();
        mapping.setStatusListId(statusListId);
        mapping.setUserId(userId);
        mapping.setTokenId(tokenId);
        mapping.setRealmId(realmId);
        mapping.setTokenStatus(TokenStatus.VALID);

        try {
            logger.debugf(
                    "Booking next index for status list mapping: status_list_id=%s, userId=%s, tokenId=%s",
                    statusListId, userId, tokenId);

            statusListRepository.withEntityManagerInTransaction(em -> {
                Long idx = statusListRepository.getNextIndex(em, statusListId);
                logger.debugf("Next available index is: %d", idx);

                mapping.setIdx(idx);
                mapping.setStatus(MappingStatus.INIT);

                em.persist(mapping);
                em.flush();
            });
        } catch (Exception e) {
            logger.error("Failed to initiate index mapping", e);
            return null;
        }

        Status status = null;

        try {
            logger.debugf("Sending token status for generated index: %d", mapping.getIdx());

            sendStatusToServer(mapping.getIdx(), statusListId);
            mapping.setStatus(MappingStatus.SUCCESS);

            status = new Status(new StatusListClaim(mapping.getIdx(), uri));
        } catch (StatusListException | IOException e) {
            logger.error("Failed to send token status", e);
            mapping.setStatus(MappingStatus.FAILURE);
        }

        try {
            logger.debugf("Persisting completion mapping status: %s", mapping.getStatus());
            statusListRepository.save(mapping);
        } catch (Exception e) {
            logger.error("Failed to persist completion mapping status", e);
            return null;
        }

        return status;
    }

    private void sendStatusToServer(long idx, String statusListId) throws IOException, StatusListException {
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
