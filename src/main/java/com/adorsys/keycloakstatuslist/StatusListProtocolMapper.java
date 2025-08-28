package com.adorsys.keycloakstatuslist;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.jpa.entity.StatusListCounterEntity;
import com.adorsys.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import com.adorsys.keycloakstatuslist.model.Status;
import com.adorsys.keycloakstatuslist.model.StatusListClaim;
import com.adorsys.keycloakstatuslist.service.CryptoIdentityService;
import com.adorsys.keycloakstatuslist.service.CustomHttpClient;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.core.UriBuilder;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPatch;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.oid4vc.issuance.mappers.OID4VCMapper;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * Protocol mapper for adding `status_list` claims to issued Verifiable Credentials, as per the
 * <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-11.html#name-referenced-token">
 * Token Status List </a> specification.
 */
public class StatusListProtocolMapper extends OID4VCMapper {

    private static final Logger logger = Logger.getLogger(StatusListProtocolMapper.class);
    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    private final KeycloakSession session;
    private final CryptoIdentityService cryptoIdentityService;

    protected interface Constants {
        String MAPPER_ID = "oid4vc-status-list-claim-mapper";
        String CONFIG_LIST_ID_PROPERTY = "status.list.list_id";

        String ID_CLAIM_KEY = "id";
        String STATUS_CLAIM_KEY = "status";
        String TOKEN_STATUS_VALID = "VALID";

        String BEARER_PREFIX = "Bearer ";
        String HTTP_ENDPOINT_PUBLISH_PATH = "/statuslists/publish";
        String HTTP_ENDPOINT_UPDATE_PATH = "/statuslists/update";
        String HTTP_ENDPOINT_RETRIEVE_PATH = "/statuslists/%s";
    }

    public StatusListProtocolMapper() {
        // An empty mapper constructor is required by Keycloak
        this.session = null;
        this.cryptoIdentityService = null;
    }

    public StatusListProtocolMapper(KeycloakSession session) {
        this.session = session;
        this.cryptoIdentityService = new CryptoIdentityService(session);
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

    public StatusListConfig getStatusListConfig(RealmModel realm) {
        return new StatusListConfig(realm);
    }

    @Override
    public void setClaimsForCredential(VerifiableCredential verifiableCredential, UserSessionModel userSessionModel) {
        // No-op. W3C Verifiable Credentials are not supported by this mapper.
    }

    @Override
    public void setClaimsForSubject(Map<String, Object> claims, UserSessionModel userSessionModel) {
        logger.debugf("Adding status list data to credential claims (TokenStatusList)");
        Objects.requireNonNull(session, "Keycloak session is required");

        String clientId = session.getContext().getClient().getClientId();
        String realmId = session.getContext().getRealm().getId();
        logger.infof("Setting claim for client: %s, realm: %s", clientId, realmId);

        StatusListConfig config = getStatusListConfig(session.getContext().getRealm());

        // Guard: Status list feature is disabled
        if (!config.isEnabled()) {
            logger.debugf("Status list is disabled for realm: %s", realmId);
            return;
        }

        // Guard: Server URL missing or empty
        String serverUrl = config.getServerUrl();
        if (serverUrl == null || serverUrl.trim().isEmpty()) {
            logger.errorf("Status list server URL is not configured for realm: %s", realmId);
            return;
        }

        // Guard: Server URL is invalid
        if (!isValidHttpUrl(serverUrl)) {
            logger.errorf("Invalid status list server URL for realm %s: %s", realmId, serverUrl);
            return;
        }

        // Build URI for status list
        Map<String, String> mapperConfig = mapperModel.getConfig();
        String listId = mapperConfig.getOrDefault(Constants.CONFIG_LIST_ID_PROPERTY, realmId);
        URI uri = UriBuilder.fromUri(serverUrl)
                .path(String.format(Constants.HTTP_ENDPOINT_RETRIEVE_PATH, listId))
                .build();
        logger.debugf("Configuration: listId=%s, uri=%s", listId, uri);

        // Retrieve next available index
        Long idx = getNextIndex(session);
        if (idx == null) {
            logger.error("Failed to get next index");
            return;
        }

        // Get credential ID
        String tokenId = null;
        if (claims.get(Constants.ID_CLAIM_KEY) instanceof String id) {
            tokenId = id;
        }

        UserSessionModel userSession = session.getContext().getUserSession();
        String userId = userSession != null ? userSession.getUser().getId() : null;

        Status status = storeIndexMapping(listId, idx, uri.toString(), userId, tokenId, session, config);
        if (status == null) {
            logger.error("Failed to send status to server. Status claim not mapped");
            return;
        }

        logger.infof("Adding status claim of value: %s", status.toMap());
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

    private static void withEntityManagerInTransaction(KeycloakSession session, Consumer<EntityManager> action) {
        KeycloakModelUtils.runJobInTransaction(session.getKeycloakSessionFactory(), s -> {
            EntityManager em = s.getProvider(JpaConnectionProvider.class).getEntityManager();
            if (em == null) {
                logger.error("EntityManager is null for JpaConnectionProvider");
                s.getTransactionManager().setRollbackOnly();
                return;
            }
            action.accept(em);
        });
    }

    private Long getNextIndex(KeycloakSession session) {
        logger.debugf("Getting next index for realm: %s", session.getContext().getRealm().getId());
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        if (em == null) {
            logger.error("EntityManager is null for JpaConnectionProvider");
            return null;
        }

        try {
            String query = String.format("SELECT nextval('%s')", StatusListCounterEntity.SEQUENCE_NAME);
            return (Long) em.createNativeQuery(query).getSingleResult();
        } catch (Exception e) {
            logger.error("Failed to get next index", e);
            return null;
        }
    }

    private Status storeIndexMapping(String statusListId, Long idx, String uri, String userId, String tokenId,
                                     KeycloakSession session, StatusListConfig realmConfig) {
        logger.debugf("Storing index mapping: status_list_id=%s, idx=%d, userId=%s, tokenId=%s",
                statusListId, idx, userId, tokenId);
        AtomicReference<Status> status = new AtomicReference<>();

        withEntityManagerInTransaction(session, em -> {
            try {
                StatusListMappingEntity mapping = new StatusListMappingEntity();
                mapping.setStatusListId(statusListId);
                mapping.setIdx(idx);
                mapping.setUserId(userId);
                mapping.setTokenId(tokenId);
                mapping.setRealmId(session.getContext().getRealm().getId());
                em.persist(mapping);
                em.flush();

                sendStatusToServer(idx, statusListId, realmConfig);
                StatusListClaim statusList = new StatusListClaim(String.valueOf(idx), uri);
                status.set(new Status(statusList));
            } catch (Exception e) {
                logger.error("Failed to store index mapping", e);
                session.getTransactionManager().setRollbackOnly();
            }
        });

        return status.get();
    }

    private void sendStatusToServer(long idx, String statusListId, StatusListConfig realmConfig) throws IOException {
        Objects.requireNonNull(cryptoIdentityService);

        // Generate authentication token
        String jwtToken = cryptoIdentityService.getJwtToken(realmConfig);
        logger.infof("Dangeroussss: JWT Bearer Token: %s", jwtToken);
        if (jwtToken == null || jwtToken.isEmpty()) {
            logger.error("JWT token is required for status server authentication but is missing or empty.");
            throw new IllegalArgumentException("JWT token is required for status server authentication.");
        }

        // Prepare payload
        StatusListPayload payload = new StatusListPayload(
                statusListId,
                List.of(new StatusListPayload.StatusEntry((int) idx, Constants.TOKEN_STATUS_VALID))
        );

        // Publish or update status list on server
        publishOrUpdateNewList(payload, jwtToken, realmConfig);
    }

    private void publishOrUpdateNewList(
            StatusListPayload payload,
            String bearerToken,
            StatusListConfig realmConfig
    ) throws IOException {
        String serverUrl = realmConfig.getServerUrl();

        try (CloseableHttpClient httpClient = CustomHttpClient.getHttpClient(realmConfig)) {
            boolean statusListExists = checkStatusListExists(httpClient, serverUrl, payload.listId);
            UriBuilder uriBuilder = UriBuilder.fromUri(serverUrl);
            HttpUriRequestBase httpRequest = statusListExists
                    ? new HttpPatch(uriBuilder.path(Constants.HTTP_ENDPOINT_UPDATE_PATH).build())
                    : new HttpPost(uriBuilder.path(Constants.HTTP_ENDPOINT_PUBLISH_PATH).build());

            httpRequest.setHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON);
            httpRequest.setHeader(HttpHeaders.AUTHORIZATION, Constants.BEARER_PREFIX + bearerToken);

            String jsonPayload = JsonSerialization.mapper.writeValueAsString(payload);
            logger.infof("Sending payload: %s", jsonPayload);
            httpRequest.setEntity(new StringEntity(jsonPayload, StandardCharsets.UTF_8, false));

            httpClient.execute(httpRequest, response -> {
                if (response.getCode() < 200 || response.getCode() >= 300) {
                    logger.errorf("Failed to %s status list %s: %d %s",
                            statusListExists ? "update" : "publish",
                            payload.listId, response.getCode(), response.getReasonPhrase());
                    throw new IOException("Non-success response: " + response.getCode());
                } else {
                    logger.infof("Successfully %s status list %s on server.",
                            statusListExists ? "updated" : "published", payload.listId);
                    return null;
                }
            });
        } catch (Exception e) {
            logger.errorf("Error publishing or updating status list on server: %s", e.getMessage());
            throw e;
        }
    }

    private boolean checkStatusListExists(
            CloseableHttpClient httpClient,
            String serverUrl,
            String statusListId
    ) throws IOException {
        String endpoint = UriBuilder.fromUri(serverUrl)
                .path(String.format(Constants.HTTP_ENDPOINT_RETRIEVE_PATH, statusListId))
                .build()
                .toString();

        HttpGet httpGet = new HttpGet(endpoint);

        return httpClient.execute(httpGet, response -> {
            if (response.getCode() == 404) {
                logger.infof("Status list %s does not exist on server.", statusListId);
                return false;
            } else if (response.getCode() == 200) {
                logger.infof("Status list %s exists on server.", statusListId);
                return true;
            } else {
                String reason = response.getReasonPhrase();
                logger.errorf("Failed to verify existence of status list %s: %d %s", statusListId,
                        response.getCode(), reason);
                throw new IOException("Failed to verify status list existence: " + response.getCode());
            }
        });
    }

    public record StatusListPayload(
            @JsonProperty("list_id") String listId,
            List<StatusEntry> status
    ) {
        public record StatusEntry(int index, String status) {
        }
    }
}
