package com.adorsys.keycloakstatuslist;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
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

public class StatusListProtocolMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper {
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
        property.setDefaultValue("https://example.com/statuslists");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(LIST_ID_PROPERTY);
        property.setLabel("Status List ID");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("The list ID to append to the base URI (e.g., 1)");
        property.setDefaultValue("1");
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
        logger.infof("setClaim invoked for client: %s", clientSessionCtx.getClientSession().getClient().getClientId());

        // Run Liquibase migration to ensure tables exist
        LiquibaseMigrationRunner.runMigration(keycloakSession);

        String baseUri = mappingModel.getConfig().getOrDefault(BASE_URI_PROPERTY, "https://example.com/statuslists");
        String listId = mappingModel.getConfig().getOrDefault(LIST_ID_PROPERTY, "1");
        String uri = String.format("%s/%s", baseUri, listId);

        // Get next index
        long idx = getNextIndex(keycloakSession);
        if (idx == -1) {
            logger.error("Failed to get next index, skipping claim addition");
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

    private long getNextIndex(KeycloakSession keycloakSession) {
        logger.debugf("Getting next index for realm: %s", keycloakSession.getContext().getRealm().getId());
        final long[] nextIndex = {-1};

        // Enlist transaction
        keycloakSession.getTransactionManager().enlist(new org.keycloak.models.KeycloakTransaction() {
            @Override
            public void begin() {
                logger.debug("Transaction begun for getNextIndex");
            }

            @Override
            public void commit() {
                logger.debug("Transaction committed for getNextIndex");
            }

            @Override
            public void rollback() {
                logger.warn("Transaction rolled back for getNextIndex");
            }

            @Override
            public void setRollbackOnly() {
                keycloakSession.getTransactionManager().setRollbackOnly();
            }

            @Override
            public boolean getRollbackOnly() {
                return keycloakSession.getTransactionManager().getRollbackOnly();
            }

            @Override
            public boolean isActive() {
                return keycloakSession.getTransactionManager().isActive();
            }
        });

        EntityManager em = keycloakSession.getProvider(JpaConnectionProvider.class).getEntityManager();
        if (em == null) {
            logger.error("EntityManager is null for JpaConnectionProvider");
            keycloakSession.getTransactionManager().setRollbackOnly();
            return -1;
        }

        try {
            logger.debug("Attempting to find StatusListCounterEntity with ID 'global'");
            StatusListCounterEntity counter = em.find(StatusListCounterEntity.class, "global", LockModeType.PESSIMISTIC_WRITE);
            if (counter == null) {
                logger.info("No counter found, creating new StatusListCounterEntity with ID 'global'");
                counter = new StatusListCounterEntity();
                counter.setId("global");
                counter.setCurrentIndex(0);
                em.persist(counter);
                em.flush(); // Ensure persistence before proceeding
                logger.debug("Persisted new counter entity");
            }
            nextIndex[0] = counter.getCurrentIndex();
            counter.setCurrentIndex(nextIndex[0] + 1);
            logger.debugf("Assigned next index: %d, updated counter to: %d", nextIndex[0], counter.getCurrentIndex());
        } catch (Exception e) {
            logger.error("Failed to get or update next index", e);
            keycloakSession.getTransactionManager().setRollbackOnly();
            return -1;
        }
        return nextIndex[0];
    }

    private void storeIndexMapping(long idx, String userId, String tokenId, String listId, KeycloakSession keycloakSession) {
        logger.debugf("Storing index mapping: idx=%d, userId=%s, tokenId=%s, listId=%s", idx, userId, tokenId, listId);

        // Enlist transaction
        keycloakSession.getTransactionManager().enlist(new org.keycloak.models.KeycloakTransaction() {
            @Override
            public void begin() {
                logger.debug("Transaction begun for storeIndexMapping");
            }

            @Override
            public void commit() {
                logger.debug("Transaction committed for storeIndexMapping");
            }

            @Override
            public void rollback() {
                logger.warn("Transaction rolled back for storeIndexMapping");
            }

            @Override
            public void setRollbackOnly() {
                keycloakSession.getTransactionManager().setRollbackOnly();
            }

            @Override
            public boolean getRollbackOnly() {
                return keycloakSession.getTransactionManager().getRollbackOnly();
            }

            @Override
            public boolean isActive() {
                return keycloakSession.getTransactionManager().isActive();
            }
        });

        EntityManager em = keycloakSession.getProvider(JpaConnectionProvider.class).getEntityManager();
        if (em == null) {
            logger.error("EntityManager is null for JpaConnectionProvider");
            keycloakSession.getTransactionManager().setRollbackOnly();
            return;
        }

        try {
            StatusListMappingEntity mapping = new StatusListMappingEntity();
            mapping.setIdx(idx);
            mapping.setUserId(userId);
            mapping.setTokenId(tokenId);
            mapping.setRealmId(keycloakSession.getContext().getRealm().getId());
            em.persist(mapping);
            em.flush(); // Ensure persistence
            logger.debug("Persisted StatusListMappingEntity successfully");

            // Send status to external server
            try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
                HttpPost httpPost = new HttpPost("https://statuslist-server.com");
                Map<String, Object> payload = Map.of(
                    "status", "VALID",
                    "index", idx,
                    "list_id", listId
                );
                String jsonPayload = objectMapper.writeValueAsString(payload);
                httpPost.setEntity(new StringEntity(jsonPayload, null, "application/json", false));
                httpClient.execute(httpPost, response -> {
                    if (response.getCode() != 200) {
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
            keycloakSession.getTransactionManager().setRollbackOnly();
        }
    }
}