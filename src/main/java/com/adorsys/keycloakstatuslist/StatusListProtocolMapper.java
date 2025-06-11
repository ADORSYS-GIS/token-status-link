package com.adorsys.keycloakstatuslist;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakTransaction;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
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
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class StatusListProtocolMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper {
    private static final Logger logger = Logger.getLogger(StatusListProtocolMapper.class);
    public static final String PROVIDER_ID = "status-list-protocol-mapper";
    public static final String BASE_URI_PROPERTY = "status.list.base_uri";
    public static final String LIST_ID_PROPERTY = "status.list.list_id";
    public static final List<ProviderConfigProperty> configProperties = new ArrayList<>();
    private final ObjectMapper objectMapper = new ObjectMapper();

    static {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName(BASE_URI_PROPERTY);
        property.setLabel("Status List Base URI");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("The base URI for the status list (e.g., https://example.com/statuslists)");
        property.setDefaultValue("https://statuslist.eudi-adorsys.com");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(LIST_ID_PROPERTY);
        property.setLabel("Status List ID");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("The list ID to append to the base URI should be unique(e.g., 07499bc3-7e65-46b9-b7dd-ca37c4807420)");
        property.setDefaultValue("07499bc3-7e65-46b9-b7dd-ca37c4807420");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME);
        property.setLabel("Token Claim Name");
        property.setType(ProviderConfigProperty.STRING_TYPE);   
        property.setDefaultValue("status");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName("jwt token");
        property.setLabel("JWT bearer");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("This is the jwt token for authenticating with the registerred status list server.");
        property.setDefaultValue("");
        configProperties.add(property);

        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, StatusListProtocolMapper.class);
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
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "Adds a status list claim with a counter-based idx and configurable URI to the token";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
            KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        logger.infof("setClaim invoked for client: %s, realm: %s",
                clientSessionCtx.getClientSession().getClient().getClientId(),
                keycloakSession.getContext().getRealm().getId());

        String baseUri = mappingModel.getConfig().get(BASE_URI_PROPERTY);
        String listId = mappingModel.getConfig().get(LIST_ID_PROPERTY);
        String uri = String.format("%s/%s", baseUri, listId);
        logger.debugf("Claim configuration: baseUri=%s, listId=%s, uri=%s", baseUri, listId, uri);

        long idx = getNextIndex(keycloakSession);
        if (idx == -1) {
            logger.error("Failed to get next index, adding error claim");
            token.getOtherClaims().put("status_error", "Failed to generate index");
            return;
        }

        String userId = userSession != null ? userSession.getUser().getId() : null;
        storeIndexMapping(idx, userId, token.getId(), listId, keycloakSession);

        StatusList statusList = new StatusList(String.valueOf(idx), uri);
        Status status = new Status(statusList);

        String claimName = mappingModel.getConfig().getOrDefault(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, "status");
        logger.infof("Adding claim '%s' with value: %s", claimName, status.toMap());
        token.getOtherClaims().put(claimName, status.toMap());
    }

    protected long getNextIndex(KeycloakSession session) {
        logger.debugf("Getting next index for realm: %s", session.getContext().getRealm().getId());
        final long[] nextIndex = { -1 };
        session.getTransactionManager().enlist(new KeycloakTransaction() {
            private boolean rollbackOnly = false;
            private boolean active = false;

            @Override
            public void begin() {
                active = true;

            }

            @Override
            public void commit() {
                if (active && !rollbackOnly) {

                }
                active = false;
            }

            @Override
            public void rollback() {
                if (active) {

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

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        if (em == null) {
            logger.error("EntityManager is null for JpaConnectionProvider");
            session.getTransactionManager().setRollbackOnly();
            return -1;
        }

        try {
            logger.debug("Querying StatusListCounterEntity with ID 'global'");
            StatusListCounterEntity counter = em.find(StatusListCounterEntity.class, "global",
                    LockModeType.PESSIMISTIC_WRITE);
            if (counter == null) {
                logger.info("No counter found, creating new StatusListCounterEntity");
                counter = new StatusListCounterEntity();
                counter.setId("global");
                counter.setCurrentIndex(0);
                em.persist(counter);
                em.flush();
                logger.debug("Persisted new counter entity");
            }
            nextIndex[0] = counter.getCurrentIndex();
            counter.setCurrentIndex(nextIndex[0] + 1);
            logger.debugf("Assigned next index: %d, updated counter to: %d", nextIndex[0], counter.getCurrentIndex());
        } catch (Exception e) {
            logger.error("Failed to get or update next index", e);
            session.getTransactionManager().setRollbackOnly();
            return -1;
        }
        return nextIndex[0];
    }

    protected void storeIndexMapping(long idx, String userId, String tokenId, String listId, KeycloakSession session) {
        logger.debugf("Storing index mapping: idx=%d, userId=%s, tokenId=%s, listId=%s", idx, userId, tokenId, listId);

        session.getTransactionManager().enlist(new org.keycloak.models.KeycloakTransaction() {
            private boolean rollbackOnly = false; // Local state to track rollback
            private boolean active = false;

            @Override
            public void begin() {
                active = true;
                logger.debug("Starting transaction for storeIndexMapping");
            }

            @Override
            public void commit() {
                if (active && !rollbackOnly) {
            logger.infof("Successfully persisted StatusListMappingEntity for idx=%d", idx);
                }
                active = false;
            }

            @Override
            public void rollback() {
                if (active) {

                    logger.warn("Transaction rolled back for storeIndexMapping");
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

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        if (em == null) {
            logger.error("EntityManager is null for JpaConnectionProvider");
            session.getTransactionManager().setRollbackOnly();
            return;
        }

        try {
            StatusListMappingEntity mapping = new StatusListMappingEntity();
            mapping.setIdx(idx);
            mapping.setUserId(userId);
            mapping.setTokenId(tokenId);
            mapping.setRealmId(session.getContext().getRealm().getId());
            em.persist(mapping);
            em.flush();
            logger.infof("Successfully persisted StatusListMappingEntity for idx=%d", idx);

            try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
                HttpPost httpPost = new HttpPost("http://localhost:8000/statuslists/publish");
                // The array of status objects
                Map<String, Object> statusObject = Map.of(
                        "status", "VALID",
                        "index", idx);
                List<Map<String, Object>> statuses = List.of(statusObject);

                // The full payload with list_id and the array of statuses
                Map<String, Object> payload = Map.of(
                        "list_id", listId,
                        "status", statuses);

                String jsonPayload = objectMapper.writeValueAsString(payload);
                logger.info("Sending POST to /statuslists/publish with payload: " + jsonPayload);

                // Add Authorization header with Bearer token
                String accessToken = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImdvbmR3YW5hLWRpZ2l0YWwtcG9sZS1jeHliYSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3NDk1NjUxMjEsImV4cCI6MTc0OTY1MTUyMX0.0EHCqKI6WZjKF8OcmkzZjTizeOTVx4-tPHQlRMjPm75eX8fQVpyyXeFd8LAKmwiVknCYmI0etACyOKAzyFOk5g"; // retrieval
                httpPost.setHeader("Authorization", "Bearer " + accessToken);
                httpPost.setHeader("Content-Type", "application/json");
                httpPost.setEntity(new StringEntity(jsonPayload, StandardCharsets.UTF_8, false));
                httpClient.execute(httpPost, response -> {
                    if (response.getCode() < 200 || response.getCode() >= 300) {
                        logger.warnf("Failed to send status to statuslist-server.com for idx %d: %d %s",
                                idx, response.getCode(), response.getReasonPhrase());
                    } else {
                        logger.debugf("Successfully sent status to statuslist-server.com for idx %d", idx);
                    }
                    return null;
                });
            } catch (IOException e) {
                logger.warnf("Error sending status to statuslist-server.com for idx %d: %s", idx, e.getMessage());
            }
        } catch (Exception e) {
            logger.error("Failed to store index mapping", e);
            session.getTransactionManager().setRollbackOnly();
        }
    }
}