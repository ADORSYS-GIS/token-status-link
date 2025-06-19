package com.adorsys.keycloakstatuslist;

import org.keycloak.models.*;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.jboss.logging.Logger;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.io.entity.StringEntity;

import com.adorsys.keycloakstatuslist.model.Status;
import com.adorsys.keycloakstatuslist.model.StatusListClaim;
import com.adorsys.keycloakstatuslist.model.StatusListCounterEntity;
import com.adorsys.keycloakstatuslist.model.StatusListMappingEntity;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class StatusListProtocolMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper {

    private static final Logger logger = Logger.getLogger(StatusListProtocolMapper.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    protected interface Constants {
        String PROVIDER_ID = "status-list-protocol-mapper";
        String BASE_URI_PROPERTY = "status.list.base_uri";
        String LIST_ID_PROPERTY = "status.list.list_id";
        String TOKEN_CLAIM_NAME_PROPERTY = OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME;
        String JWT_TOKEN_PROPERTY = "jwt.token";
        String DEFAULT_BASE_URI = "https://statuslist.eudi-adorsys.com";
        String DEFAULT_LIST_ID = "07499bc3-7e65-46b9-b7dd-ca37c4807420";
        String DEFAULT_JWT_TOKEN = "";
        String STATUS_ERROR_CLAIM = "status_error";
        String STATUS_ERROR_MESSAGE = "Failed to generate index";
        String COUNTER_ID = "global";
        String HTTP_ENDPOINT_PATH = "/statuslists/publish";
        String CONTENT_TYPE_JSON = "application/json";
        String AUTHORIZATION_HEADER = "Authorization";
        String BEARER_PREFIX = "Bearer ";
    }

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        addConfigProperty(
                Constants.BASE_URI_PROPERTY,
                "Status List Base URI",
                ProviderConfigProperty.STRING_TYPE,
                "The base URI for the status list (e.g., https://example.com/statuslists)",
                Constants.DEFAULT_BASE_URI);
        addConfigProperty(
                Constants.LIST_ID_PROPERTY,
                "Status List ID",
                ProviderConfigProperty.STRING_TYPE,
                "The list ID to append to the base URI should be unique (e.g., 07499bc3-7e65-46b9-b7dd-ca37c4807420)",
                Constants.DEFAULT_LIST_ID);
        addConfigProperty(
                Constants.JWT_TOKEN_PROPERTY,
                "JWT Bearer",
                ProviderConfigProperty.STRING_TYPE,
                "JWT token for authenticating with the registered status list server",
                Constants.DEFAULT_JWT_TOKEN);
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(CONFIG_PROPERTIES, StatusListProtocolMapper.class);
    }

    private static void addConfigProperty(String name, String label, String type, String helpText,
            String defaultValue) {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName(name);
        property.setLabel(label);
        property.setType(type);
        property.setHelpText(helpText);
        property.setDefaultValue(defaultValue);
        CONFIG_PROPERTIES.add(property);
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Status List Claim Mapper";
    }

    @Override
    public String getId() {
        return Constants.PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "Adds a status list claim with a counter-based idx and configurable URI to the token";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
            KeycloakSession session, ClientSessionContext clientSessionCtx) {
        String clientId = clientSessionCtx.getClientSession().getClient().getClientId();
        String realmId = session.getContext().getRealm().getId();
        logger.infof("Setting claim for client: %s, realm: %s", clientId, realmId);

        Map<String, String> config = mappingModel.getConfig();
        String baseUri = config.getOrDefault(Constants.BASE_URI_PROPERTY, Constants.DEFAULT_BASE_URI);
        String listId = config.getOrDefault(Constants.LIST_ID_PROPERTY, Constants.DEFAULT_LIST_ID);
        String uri = String.format("%s/%s", baseUri, listId);
        logger.debugf("Configuration: baseUri=%s, listId=%s, uri=%s", baseUri, listId, uri);

        long idx = getNextIndex(session);
        if (idx == -1) {
            logger.error("Failed to get next index, adding error claim");
            token.getOtherClaims().put(Constants.STATUS_ERROR_CLAIM, Constants.STATUS_ERROR_MESSAGE);
            return;
        }

        String userId = userSession != null ? userSession.getUser().getId() : null;
        storeIndexMapping(listId, idx, userId, token.getId(), session, config);

        StatusListClaim statusList = new StatusListClaim(String.valueOf(idx), uri);
        Status status = new Status(statusList);
        String claimName = config.get(Constants.TOKEN_CLAIM_NAME_PROPERTY);
        logger.infof("Adding claim '%s' with value: %s", claimName, status.toMap());
        token.getOtherClaims().put(claimName, status.toMap());
    }

    protected long getNextIndex(KeycloakSession session) {
        logger.debugf("Getting next index for realm: %s", session.getContext().getRealm().getId());
        EntityManager em = getEntityManager(session);
        if (em == null) {
            return -1;
        }

        long[] nextIndex = { -1 };
        executeInTransaction(session, () -> {
            try {
                logger.debugf("Querying StatusListCounterEntity with ID '%s'", Constants.COUNTER_ID);
                StatusListCounterEntity counter = em.find(StatusListCounterEntity.class, Constants.COUNTER_ID,
                        LockModeType.PESSIMISTIC_WRITE);
                if (counter == null) {
                    logger.info("No counter found, creating new StatusListCounterEntity");
                    counter = new StatusListCounterEntity();
                    counter.setId(Constants.COUNTER_ID);
                    counter.setCurrentIndex(0);
                    em.persist(counter);
                    em.flush();
                    logger.debug("Persisted new counter entity");
                }
                nextIndex[0] = counter.getCurrentIndex();
                counter.setCurrentIndex(nextIndex[0] + 1);
                logger.debugf("Assigned next index: %d, updated counter to: %d", nextIndex[0],
                        counter.getCurrentIndex());
            } catch (Exception e) {
                logger.error("Failed to get or update next index", e);
                session.getTransactionManager().setRollbackOnly();
                nextIndex[0] = -1;
            }
        });

        return nextIndex[0];
    }

    protected void storeIndexMapping(String statusListId, long idx, String userId, String tokenId,
            KeycloakSession session,
            Map<String, String> config) {
        logger.debugf("Storing index mapping: status_list_id=%s, idx=%d, userId=%s, tokenId=%s", statusListId, idx,
                userId, tokenId);
        EntityManager em = getEntityManager(session);
        if (em == null) {
            return;
        }

        executeInTransaction(session, () -> {
            try {
                StatusListMappingEntity mapping = new StatusListMappingEntity();
                mapping.setStatusListId(statusListId);
                mapping.setIdx(idx);
                mapping.setUserId(userId);
                mapping.setTokenId(tokenId);
                mapping.setRealmId(session.getContext().getRealm().getId());
                em.persist(mapping);
                em.flush();

                sendStatusToServer(idx, statusListId, config);
            } catch (Exception e) {
                logger.error("Failed to store index mapping", e);
                session.getTransactionManager().setRollbackOnly();
            }
        });
    }

    private EntityManager getEntityManager(KeycloakSession session) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        if (em == null) {
            logger.error("EntityManager is null for JpaConnectionProvider");
            session.getTransactionManager().setRollbackOnly();
        }
        return em;
    }

    private void executeInTransaction(KeycloakSession session, Runnable operation) {
        session.getTransactionManager().enlist(new KeycloakTransaction() {
            private boolean rollbackOnly = false;
            private boolean active = false;

            @Override
            public void begin() {
                active = true;
                logger.debug("Starting transaction");
            }

            @Override
            public void commit() {
                if (active && !rollbackOnly) {
                    logger.debug("Committing transaction");
                }
                active = false;
            }

            @Override
            public void rollback() {
                if (active) {
                    logger.warn("Transaction rolled back");
                }
                active = false;
            }

            @Override
            public void setRollbackOnly() {
                rollbackOnly = true;
            }

            @Override
            public boolean getRollbackOnly() {
                return rollbackOnly;
            }

            @Override
            public boolean isActive() {
                return active;
            }
        });

        operation.run();
    }

    private void sendStatusToServer(long idx, String statusListId, Map<String, String> config) throws IOException {
        String baseUri = config.get(Constants.BASE_URI_PROPERTY);
        String endpoint = baseUri + Constants.HTTP_ENDPOINT_PATH;
        String jwtToken = config.getOrDefault(Constants.JWT_TOKEN_PROPERTY, Constants.DEFAULT_JWT_TOKEN);

        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpPost httpPost = new HttpPost(endpoint);
            Map<String, Object> statusObject = Map.of(
                    "status", "VALID",
                    "index", idx);
            List<Map<String, Object>> statuses = List.of(statusObject);
            Map<String, Object> payload = Map.of(
                    "list_id", statusListId,
                    "status", statuses);

            String jsonPayload = objectMapper.writeValueAsString(payload);
            logger.infof("Sending POST to %s with payload: %s", endpoint, jsonPayload);

            if (!jwtToken.isEmpty()) {
                httpPost.setHeader(Constants.AUTHORIZATION_HEADER, Constants.BEARER_PREFIX + jwtToken);
            }
            httpPost.setHeader("Content-Type", Constants.CONTENT_TYPE_JSON);
            httpPost.setEntity(new StringEntity(jsonPayload, StandardCharsets.UTF_8, false));

            httpClient.execute(httpPost, response -> {
                if (response.getCode() < 200 || response.getCode() >= 300) {
                    logger.warnf("Failed to send status to %s for idx %d: %d %s",
                            endpoint, idx, response.getCode(), response.getReasonPhrase());
                } else {
                    logger.debugf("Successfully sent status to %s for idx %d", endpoint, idx);
                }
                return null;
            });
        } catch (IOException e) {
            logger.warnf("Error sending status to %s for idx %d: %s", endpoint, idx, e.getMessage());
            throw e;
        }
    }
}