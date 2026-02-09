package com.adorsys.keycloakstatuslist;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import com.adorsys.keycloakstatuslist.model.Status;
import com.adorsys.keycloakstatuslist.model.StatusListClaim;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.adorsys.keycloakstatuslist.service.CryptoIdentityService;
import com.adorsys.keycloakstatuslist.service.CustomHttpClient;
import com.adorsys.keycloakstatuslist.service.StatusListService;
import com.adorsys.keycloakstatuslist.service.http.CloseableHttpClientAdapter;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.TypedQuery;
import jakarta.ws.rs.core.UriBuilder;
import org.apache.commons.collections4.ListUtils;
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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import static com.adorsys.keycloakstatuslist.jpa.entity.StatusListMappingEntity.MappingStatus;

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

    public StatusListProtocolMapper() {
        // An empty mapper constructor is required by Keycloak
        this.session = null;
        this.statusListService = null;
    }

    public StatusListProtocolMapper(KeycloakSession session) {
        this.session = session;
        CryptoIdentityService cryptoIdentityService = new CryptoIdentityService(session);
        StatusListConfig config = new StatusListConfig(session.getContext().getRealm());
        this.statusListService = new StatusListService(
                config.getServerUrl(),
                cryptoIdentityService.getJwtToken(config),
                new CloseableHttpClientAdapter(CustomHttpClient.getHttpClient())
        );
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
        // TODO(status-list-server#128): Use configured list ID
        // Map<String, String> mapperConfig = mapperModel.getConfig();
        // mapperConfig.getOrDefault(Constants.CONFIG_LIST_ID_PROPERTY, realmId);
        String listId = UUID.randomUUID().toString();
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

        Status status = sendStatusAndStoreIndexMapping(listId, uri.toString(), userId, tokenId);

        if (status == null) {
            if (config.isMandatory()) {
                    logger.error("Status list is mandatory and publication failed; failing issuance");
                throw new RuntimeException("Status list publication failed and is mandatory");
            }

            logger.warn("Status list publication failed; proceeding without status claim");
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

    /**
     * Get the next available index for the given status list ID, using a pessimistic lock to
     * prevent race conditions. Must be run within a transaction.
     */
    private Long getNextIndex(EntityManager em, String statusListId) {
        String q = """                
                SELECT m FROM StatusListMappingEntity m
                WHERE m.statusListId = :listId ORDER BY m.idx DESC
                """;

        TypedQuery<StatusListMappingEntity> query = em.createQuery(q, StatusListMappingEntity.class);
        query.setParameter("listId", statusListId);
        query.setMaxResults(1);
        query.setLockMode(LockModeType.PESSIMISTIC_WRITE);

        List<StatusListMappingEntity> max = query.getResultList();
        return (max.isEmpty()) ? 0 : max.get(0).getIdx() + 1;
    }

    /**
     * Send status to server to create status list entry and store index mapping in database.
     */
    public Status sendStatusAndStoreIndexMapping(
            String statusListId, String uri, String userId, String tokenId
    ) {
        StatusListMappingEntity mapping = new StatusListMappingEntity();
        mapping.setStatusListId(statusListId);
        mapping.setUserId(userId);
        mapping.setTokenId(tokenId);
        mapping.setRealmId(session.getContext().getRealm().getId());

        try {
            logger.debugf("Booking next index for status list mapping: status_list_id=%s, userId=%s, tokenId=%s",
                    statusListId, userId, tokenId);

            withEntityManagerInTransaction(session, em -> {
                Long idx = getNextIndex(em, statusListId);
                logger.debugf("Next available index is: %d", idx);

                mapping.setIdx(getNextIndex(em, statusListId));
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
            withEntityManagerInTransaction(session, em -> em.merge(mapping));
        } catch (Exception e) {
            logger.error("Failed to persist completion mapping status", e);
        }

        return status;
    }

    private void sendStatusToServer(long idx, String statusListId) throws IOException, StatusListException {
        // Prepare payload
        StatusListService.StatusListPayload payload =
                new StatusListService.StatusListPayload(
                        statusListId,
                        List.of(
                                new StatusListService.StatusListPayload.StatusEntry(
                                        idx, TokenStatus.VALID.getValue())));

        // Publish or update status list on server
        statusListService.publishOrUpdate(payload);
    }

    public interface Constants {
        String MAPPER_ID = "oid4vc-status-list-claim-mapper";
        String CONFIG_LIST_ID_PROPERTY = "status.list.list_id";

        String ID_CLAIM_KEY = "id";
        String STATUS_CLAIM_KEY = "status";

        String HTTP_ENDPOINT_RETRIEVE_PATH = "/statuslists/%s";
    }
}
