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
import org.apache.hc.client5.http.config.RequestConfig;
import java.util.concurrent.TimeUnit;

import com.adorsys.keycloakstatuslist.model.Status;
import com.adorsys.keycloakstatuslist.model.StatusListClaim;
import com.adorsys.keycloakstatuslist.model.StatusListCounterEntity;
import com.adorsys.keycloakstatuslist.model.StatusListMappingEntity;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import java.util.function.Consumer;

public class StatusListProtocolMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper {

    private static final Logger logger = Logger.getLogger(StatusListProtocolMapper.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();

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

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;
    static {
        List<ProviderConfigProperty> props = new ArrayList<>();
        addConfigProperty(props,
                Constants.BASE_URI_PROPERTY,
                "Status List Base URI",
                ProviderConfigProperty.STRING_TYPE,
                "The base URI for the status list (e.g., https://example.com/statuslists)",
                Constants.DEFAULT_BASE_URI);
        addConfigProperty(props,
                Constants.LIST_ID_PROPERTY,
                "Status List ID",
                ProviderConfigProperty.STRING_TYPE,
                "The list ID to append to the base URI should be unique (e.g., 07499bc3-7e65-46b9-b7dd-ca37c4807420)",
                Constants.DEFAULT_LIST_ID);
        addConfigProperty(props,
                Constants.JWT_TOKEN_PROPERTY,
                "JWT Bearer",
                ProviderConfigProperty.STRING_TYPE,
                "JWT token for authenticating with the registered status list server",
                Constants.DEFAULT_JWT_TOKEN);
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(props, StatusListProtocolMapper.class);
        CONFIG_PROPERTIES = java.util.Collections.unmodifiableList(props);
    }

    private static void addConfigProperty(List<ProviderConfigProperty> props, String name, String label, String type, String helpText,
            String defaultValue) {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName(name);
        property.setLabel(label);
        property.setType(type);
        property.setHelpText(helpText);
        property.setDefaultValue(defaultValue);
        props.add(property);
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

        String claimName = config.get(Constants.TOKEN_CLAIM_NAME_PROPERTY);
        if (claimName == null || claimName.isEmpty()) {
            logger.error("Claim name is missing in the configuration, adding error claim");
            token.getOtherClaims().put(Constants.STATUS_ERROR_CLAIM, Constants.STATUS_ERROR_MESSAGE);
            return;
        }

        long idx = getNextIndex(session);
        if (idx == -1) {
            logger.error("Failed to get next index, adding error claim");
            token.getOtherClaims().put(Constants.STATUS_ERROR_CLAIM, Constants.STATUS_ERROR_MESSAGE);
            return;
        }

        String userId = userSession != null ? userSession.getUser().getId() : null;
        storeIndexMapping(listId, idx, userId, token.getId(), session, config);

        StatusListClaim statusList = new StatusListClaim((int) idx, uri);
        Status status = new Status(statusList);
        logger.infof("Adding claim '%s' with value: %s", claimName, status.toMap());
        token.getOtherClaims().put(claimName, status.toMap());
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

    protected long getNextIndex(KeycloakSession session) {
        logger.debugf("Getting next index for realm: %s", session.getContext().getRealm().getId());
        long[] nextIndex = { -1 };
        withEntityManagerInTransaction(session, em -> {
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

                sendStatusToServer(idx, statusListId, config);
            } catch (Exception e) {
                logger.error("Failed to store index mapping", e);
                session.getTransactionManager().setRollbackOnly();
            }
        });
    }

    private void sendStatusToServer(long idx, String statusListId, Map<String, String> config) throws IOException {
        String baseUri = config.get(Constants.BASE_URI_PROPERTY);
        String endpoint = baseUri + Constants.HTTP_ENDPOINT_PATH;
        String jwtToken = config.getOrDefault(Constants.JWT_TOKEN_PROPERTY, Constants.DEFAULT_JWT_TOKEN);
        if (jwtToken == null || jwtToken.isEmpty()) {
            logger.error("JWT token is required for status server authentication but is missing or empty.");
            throw new IllegalArgumentException("JWT token is required for status server authentication.");
        }

        int maxRetries = 3;
        int attempt = 0;
        int connectTimeoutSec = 5;
        int responseTimeoutSec = 10;
        boolean success = false;
        Exception lastException = null;

        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(connectTimeoutSec, TimeUnit.SECONDS)
                .setResponseTimeout(responseTimeoutSec, TimeUnit.SECONDS)
                .build();

        while (attempt < maxRetries && !success) {
            attempt++;
            final int currentAttempt = attempt;
            try (CloseableHttpClient httpClient = HttpClients.custom()
                    .setDefaultRequestConfig(requestConfig)
                    .build()) {
                HttpPost httpPost = new HttpPost(endpoint);
                Map<String, Object> statusObject = Map.of(
                        "status", "VALID",
                        "index", idx);
                List<Map<String, Object>> statuses = List.of(statusObject);
                Map<String, Object> payload = Map.of(
                        "list_id", statusListId,
                        "status", statuses);

                String jsonPayload = objectMapper.writeValueAsString(payload);
                logger.infof("[Attempt %d/%d] Sending POST to %s with payload: %s", currentAttempt, maxRetries, endpoint, jsonPayload);

                if (!jwtToken.isEmpty()) {
                    httpPost.setHeader(Constants.AUTHORIZATION_HEADER, Constants.BEARER_PREFIX + jwtToken);
                }
                httpPost.setHeader("Content-Type", Constants.CONTENT_TYPE_JSON);
                httpPost.setEntity(new StringEntity(jsonPayload, StandardCharsets.UTF_8, false));

                httpClient.execute(httpPost, response -> {
                    if (response.getCode() < 200 || response.getCode() >= 300) {
                        logger.warnf("[Attempt %d/%d] Failed to send status to %s for idx %d: %d %s",
                                currentAttempt, maxRetries, endpoint, idx, response.getCode(), response.getReasonPhrase());
                        throw new IOException("Non-success response: " + response.getCode());
                    } else {
                        logger.debugf("Successfully sent status to %s for idx %d", endpoint, idx);
                    }
                    return null;
                });
                success = true;
            } catch (Exception e) {
                lastException = e;
                logger.warnf("[Attempt %d/%d] Error sending status to %s for idx %d: %s", currentAttempt, maxRetries, endpoint, idx, e.getMessage());
                if (attempt < maxRetries) {
                    try {
                        Thread.sleep(1000L * attempt); // Exponential backoff
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
        }
        if (!success && lastException != null) {
            logger.errorf("All attempts to send status to %s for idx %d failed.", endpoint, idx);
            if (lastException instanceof IOException) {
                throw (IOException) lastException;
            } else {
                throw new IOException("Failed to send status after retries", lastException);
            }
        }
    }
}
