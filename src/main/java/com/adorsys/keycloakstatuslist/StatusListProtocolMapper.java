package com.adorsys.keycloakstatuslist;

import static com.adorsys.keycloakstatuslist.jpa.entity.StatusListMappingEntity.MappingStatus;

import com.adorsys.keycloakstatuslist.client.ApacheHttpStatusListClient;
import com.adorsys.keycloakstatuslist.client.StatusListHttpClient;
import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import com.adorsys.keycloakstatuslist.jpa.repository.StatusListRepository;
import com.adorsys.keycloakstatuslist.model.Status;
import com.adorsys.keycloakstatuslist.model.StatusListClaim;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.adorsys.keycloakstatuslist.service.CircuitBreaker;
import com.adorsys.keycloakstatuslist.service.CryptoIdentityService;
import com.adorsys.keycloakstatuslist.service.CustomHttpClient;
import com.adorsys.keycloakstatuslist.service.StatusListService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.collections4.ListUtils;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.oid4vci.CredentialScopeModel;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.oid4vc.issuance.mappers.OID4VCMapper;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Protocol mapper for adding `status_list` claims to issued Verifiable
 * Credentials, as per the
 * <a href=
 * "https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-11.html#name-referenced-token">
 * Token Status List </a> specification.
 */
public class StatusListProtocolMapper extends OID4VCMapper {

    private static final Logger logger = Logger.getLogger(StatusListProtocolMapper.class);
    private static final ObjectMapper JSON_MAPPER = new ObjectMapper();
    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty metadataClaimPaths = new ProviderConfigProperty();
        metadataClaimPaths.setName(Constants.METADATA_CLAIM_PATHS_KEY);
        metadataClaimPaths.setLabel("Metadata Claim Paths");
        metadataClaimPaths.setHelpText(
                "Comma-separated list of claim paths to extract from the issued credential "
                        + "and store as metadata (e.g. 'vct,sub.email'). "
                        + "Nested claims use dot notation.");
        metadataClaimPaths.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(metadataClaimPaths);

        ProviderConfigProperty includeCredentialTypes = new ProviderConfigProperty();
        includeCredentialTypes.setName(Constants.INCLUDE_CREDENTIAL_TYPES_KEY);
        includeCredentialTypes.setLabel("Include Credential Types");
        includeCredentialTypes.setHelpText(
                "When enabled, includes the credential types from the parent credential scope "
                        + "in the stored metadata under the 'type' key.");
        includeCredentialTypes.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        includeCredentialTypes.setDefaultValue(Constants.INCLUDE_CREDENTIAL_TYPES_DEFAULT);
        CONFIG_PROPERTIES.add(includeCredentialTypes);
    }

    private final KeycloakSession session;
    private final StatusListService statusListService;
    private final StatusListRepository statusListRepository;

    public StatusListProtocolMapper() {
        // An empty mapper constructor is required by Keycloak
        this.session = null;
        this.statusListService = null;
        this.statusListRepository = null;
    }

    public StatusListProtocolMapper(KeycloakSession session) {
        this.session = session;
        this.statusListRepository = new StatusListRepository(session);
        this.statusListService = createStatusListService(session);
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
        URI uri = UriBuilder.fromUri(serverUrl)
                .path(String.format(Constants.HTTP_ENDPOINT_RETRIEVE_PATH, listId))
                .build();
        logger.debugf("Configuration: listId=%s, uri=%s", listId, uri);

        // Get credential ID
        String tokenId = null;
        if (claims.get(Constants.ID_CLAIM_KEY) instanceof String id) {
            tokenId = id;
        }

        UserSessionModel userSession = session.getContext().getUserSession();
        String userId = userSession != null ? userSession.getUser().getId() : null;

        List<String> credentialTypes = isIncludeCredentialTypes() ? findCredentialTypes() : List.of();
        String metadata = extractMetadata(claims, credentialTypes);
        Status status = sendStatusAndStoreIndexMapping(listId, uri.toString(), userId, tokenId, metadata);

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

    /**
     * Send status to server to create status list entry and store index mapping in database.
     *
     * @param statusListId the status list identifier
     * @param uri the status list URI
     * @param userId the user ID of the credential holder
     * @param tokenId the credential/token identifier
     * @param metadata JSON string of extracted claim metadata, or null if no metadata configured
     * @return the Status claim to embed in the credential, or null on failure
     */
    public Status sendStatusAndStoreIndexMapping(
            String statusListId, String uri, String userId, String tokenId, String metadata) {
        StatusListMappingEntity mapping = new StatusListMappingEntity();
        mapping.setStatusListId(statusListId);
        mapping.setUserId(userId);
        mapping.setTokenId(tokenId);
        mapping.setRealmId(session.getContext().getRealm().getId());
        mapping.setMetadata(metadata);

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
            statusListRepository.withEntityManagerInTransaction(em -> em.merge(mapping));
        } catch (Exception e) {
            logger.error("Failed to persist completion mapping status", e);
        }

        return status;
    }

    /**
     * Extracts configured claim values from the credential claims and serializes them as a JSON string.
     *
     * @param claims the credential claims map
     * @return JSON string of extracted metadata, or null if no metadata is available
     */
    String extractMetadata(Map<String, Object> claims) {
        return extractMetadata(claims, List.of());
    }

    /**
     * Extracts configured claim values from the credential claims, optionally including
     * credential types, and serializes them as a JSON string.
     *
     * @param claims          the credential claims map
     * @param credentialTypes credential types from the parent scope to include under the "type" key
     * @return JSON string of extracted metadata, or null if no metadata is available
     */
    String extractMetadata(Map<String, Object> claims, List<String> credentialTypes) {
        Map<String, Object> metadata = new LinkedHashMap<>();

        if (mapperModel != null) {
            String claimPathsConfig = mapperModel.getConfig().get(Constants.METADATA_CLAIM_PATHS_KEY);
            if (claimPathsConfig != null && !claimPathsConfig.isBlank()) {
                List<String> paths = Arrays.stream(claimPathsConfig.split(","))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .toList();

                for (String path : paths) {
                    Object value = resolveClaimPath(claims, path);
                    if (value != null) {
                        metadata.put(path, value);
                    }
                }
            }
        }

        if (credentialTypes != null && !credentialTypes.isEmpty()) {
            metadata.put(Constants.CREDENTIAL_TYPES_METADATA_KEY, credentialTypes);
        }

        if (metadata.isEmpty()) {
            return null;
        }

        try {
            return JSON_MAPPER.writeValueAsString(metadata);
        } catch (JsonProcessingException e) {
            logger.warnf("Failed to serialize metadata: %s", e.getMessage());
            return null;
        }
    }

    /**
     * Checks whether the credential types inclusion flag is enabled in the mapper configuration.
     * Defaults to true if not explicitly configured.
     *
     * @return true if credential types should be included in metadata
     */
    private boolean isIncludeCredentialTypes() {
        if (mapperModel == null) {
            return true;
        }
        String value = mapperModel.getConfig().get(Constants.INCLUDE_CREDENTIAL_TYPES_KEY);
        return value == null || Boolean.parseBoolean(value);
    }

    /**
     * Finds the credential types configured on the parent credential scope of this mapper
     * by searching all client scopes in the realm for one containing this mapper.
     *
     * @return the supported credential types, or an empty list if the scope cannot be found
     */
    List<String> findCredentialTypes() {
        if (session == null || mapperModel == null) {
            return List.of();
        }
        String mapperId = mapperModel.getId();
        if (mapperId == null) {
            return List.of();
        }
        return session.getContext().getRealm()
                .getClientScopesStream()
                .filter(cs -> cs.getProtocolMapperById(mapperId) != null)
                .map(CredentialScopeModel::new)
                .findFirst()
                .map(CredentialScopeModel::getSupportedCredentialTypes)
                .orElse(List.of());
    }

    /**
     * Resolves a dot-separated claim path against a nested map structure.
     *
     * @param claims the root claims map
     * @param path dot-separated path (e.g. "sub.email")
     * @return the resolved value, or null if any segment is missing or not a map
     */
    @SuppressWarnings("unchecked")
    static Object resolveClaimPath(Map<String, Object> claims, String path) {
        String[] segments = path.split("\\.");
        Object current = claims;
        for (String segment : segments) {
            if (current instanceof Map<?, ?> map) {
                current = map.get(segment);
            } else {
                return null;
            }
        }
        return current;
    }

    private void sendStatusToServer(long idx, String statusListId) throws IOException, StatusListException {
        // Prepare payload
        StatusListService.StatusListPayload payload = new StatusListService.StatusListPayload(
                statusListId,
                List.of(new StatusListService.StatusListPayload.StatusEntry(idx, TokenStatus.VALID.getValue())));

        // Publish or update status list on server
        statusListService.publishOrUpdate(payload);
    }

    public interface Constants {
        String MAPPER_ID = "oid4vc-status-list-claim-mapper";

        String ID_CLAIM_KEY = "id";
        String STATUS_CLAIM_KEY = "status";
        String METADATA_CLAIM_PATHS_KEY = "metadata.claim.paths";
        String INCLUDE_CREDENTIAL_TYPES_KEY = "include.credential.types";
        String INCLUDE_CREDENTIAL_TYPES_DEFAULT = "true";
        String CREDENTIAL_TYPES_METADATA_KEY = "type";

        String HTTP_ENDPOINT_RETRIEVE_PATH = "/statuslists/%s";
    }
}
