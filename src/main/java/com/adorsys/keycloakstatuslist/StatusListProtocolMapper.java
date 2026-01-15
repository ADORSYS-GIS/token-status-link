package com.adorsys.keycloakstatuslist;

import com.adorsys.keycloakstatuslist.client.ApacheHttpStatusListClient;
import com.adorsys.keycloakstatuslist.client.StatusListHttpClient;
import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import com.adorsys.keycloakstatuslist.model.Status;
import com.adorsys.keycloakstatuslist.model.StatusListClaim;
import com.adorsys.keycloakstatuslist.service.CircuitBreaker;
import com.adorsys.keycloakstatuslist.service.CryptoIdentityService;
import com.adorsys.keycloakstatuslist.service.CustomHttpClient;
import com.adorsys.keycloakstatuslist.service.StatusListService;
import jakarta.persistence.EntityManager;

import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

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

/**
 * Protocol mapper for adding `status_list` claims to issued Verifiable Credentials, as per the <a
 * href=
 * "https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-11.html#name-referenced-token">
 * Token Status List </a> specification.
 */
public class StatusListProtocolMapper extends OID4VCMapper {

    private static final Logger logger = Logger.getLogger(StatusListProtocolMapper.class);
    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();
    
    // Cache StatusListService per realm to share circuit breaker across all token issuance requests
    private static final Map<String, StatusListService> serviceCache = new ConcurrentHashMap<>();

    private final KeycloakSession session;
    private final CryptoIdentityService cryptoIdentityService;
    private final StatusListService statusListService;

    public StatusListProtocolMapper() {
        // An empty mapper constructor is required by Keycloak
        this.session = null;
        this.cryptoIdentityService = null;
        this.statusListService = null;
    }

    public StatusListProtocolMapper(KeycloakSession session) {
        this.session = session;
        this.cryptoIdentityService = new CryptoIdentityService(session);
        
        // Get or create cached StatusListService for this realm
        // This ensures circuit breaker is shared across all token issuance requests
        String realmId = session.getContext().getRealm().getId();
        this.statusListService = serviceCache.computeIfAbsent(realmId, key -> {
            StatusListConfig config = new StatusListConfig(session.getContext().getRealm());
            
            // Create circuit breaker if enabled
            CircuitBreaker circuitBreaker = null;
            if (config.isCircuitBreakerEnabled()) {
                circuitBreaker = new CircuitBreaker(
                        "StatusListCircuitBreaker-" + realmId,
                        config.getCircuitBreakerFailureThreshold(),
                        config.getCircuitBreakerTimeoutThreshold(),
                        config.getCircuitBreakerWindowSeconds(),
                        config.getCircuitBreakerCooldownSeconds()
                );
            }
            
            // Create HTTP client with custom timeouts for issuance path
            StatusListHttpClient httpClient = new ApacheHttpStatusListClient(
                    config.getServerUrl(),
                    cryptoIdentityService.getJwtToken(config),
                    CustomHttpClient.getHttpClient(
                            config.getIssuanceConnectTimeout(),
                            config.getIssuanceReadTimeout()
                    ),
                    circuitBreaker
            );
            
            return new StatusListService(httpClient);
        });
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
    public void setClaimsForCredential(
            VerifiableCredential verifiableCredential, UserSessionModel userSessionModel) {
        // No-op. W3C Verifiable Credentials are not supported by this mapper.
    }

    @Override
    public void setClaimsForSubject(Map<String, Object> claims, UserSessionModel userSessionModel) {
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

        // Get list ID from mapper config
        Map<String, String> mapperConfig = mapperModel.getConfig();
        String listId = mapperConfig.getOrDefault(Constants.CONFIG_LIST_ID_PROPERTY, realmId);
        logger.debugf("Configuration: listId=%s", listId);

        // Get credential ID
        String tokenId = null;
        if (claims.get(Constants.ID_CLAIM_KEY) instanceof String id) {
            tokenId = id;
        }

        UserSessionModel userSession = session.getContext().getUserSession();
        String userId = userSession != null ? userSession.getUser().getId() : null;

        // Store index mapping and publish status - service handles HTTP details
        Status status = storeIndexMappingAndPublish(listId, userId, tokenId, session);

        if (status == null) {
            logger.error("Failed to register and publish status. Status claim not mapped");
            return;
        }

        logger.infof("Adding status claim of value: %s", status.toMap());
        claims.put(Constants.STATUS_CLAIM_KEY, status);
    }

    private boolean isValidHttpUrl(String url) {
        try {
            java.net.URI uri = new java.net.URI(url);
            String scheme = uri.getScheme();
            return scheme != null
                    && (scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"));
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

    private Status storeIndexMappingAndPublish(String statusListId, String userId, String tokenId,
                                             KeycloakSession session) {
        logger.debugf("Storing index mapping: status_list_id=%s, userId=%s, tokenId=%s",
                statusListId, userId, tokenId);
        AtomicReference<Long> generatedIdx = new AtomicReference<>();

        // 1. Database operation - INSIDE transaction (fast, no HTTP blocking)
        try {
            withEntityManagerInTransaction(
                    session,
                    em -> {
                        try {
                            StatusListMappingEntity mapping = new StatusListMappingEntity();
                            mapping.setStatusListId(statusListId);
                            mapping.setUserId(userId);
                            mapping.setTokenId(tokenId);
                            mapping.setRealmId(session.getContext().getRealm().getId());

                            em.persist(mapping);
                            em.flush();

                            Long idx = mapping.getIdx();
                            logger.debugf("Stored mapping with generated index: %d", idx);
                            generatedIdx.set(idx);
                        } catch (Exception e) {
                            logger.error("Failed to store index mapping", e);
                            session.getTransactionManager().setRollbackOnly();
                            throw e; // Re-throw to prevent HTTP call if DB fails
                        }
                    });
        } catch (Exception e) {
            logger.error("Failed to store index mapping and publish status", e);
            return null;
        }

        // 2. HTTP call - OUTSIDE transaction (after commit)
        try {
            Status publishedStatus = statusListService.registerAndPublishStatus(
                    statusListId, generatedIdx.get());
            return publishedStatus;
        } catch (Exception e) {
            logger.errorf(
                    "Failed to publish status to server for listId: %s, index: %d. " +
                            "Index is stored in DB, but status list server update failed. " +
                            "Token issuance will proceed with stored index: %s",
                    statusListId, generatedIdx.get(), e.getMessage(), e);

            String uri = statusListService.getStatusListUri(statusListId);
            StatusListClaim statusList = new StatusListClaim(generatedIdx.get(), uri);
            return new Status(statusList);
        }
    }

    protected interface Constants {
        String MAPPER_ID = "oid4vc-status-list-claim-mapper";
        String CONFIG_LIST_ID_PROPERTY = "status.list.list_id";

        String ID_CLAIM_KEY = "id";
        String STATUS_CLAIM_KEY = "status";
    }
}
