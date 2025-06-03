package com.adorsys.keycloakstatuslist;

import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.Provider;

import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.jboss.logging.Logger;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Map;

public class StatusListIndexStorageProvider implements Provider {

    private static final Logger logger = Logger.getLogger(StatusListIndexStorageProvider.class);
    private final KeycloakSession session;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public StatusListIndexStorageProvider(KeycloakSession session) {
        this.session = session;
    }

    public long getNextIndex(KeycloakSession keycloakSession) {
        final long[] nextIndex = {0};
        keycloakSession.getTransactionManager().enlist(new KeycloakTransaction() {
            @Override
            public void begin() {
                // Transaction begins automatically
            }

            @Override
            public void commit() {
                // Handled by TransactionManager
            }

            @Override
            public void rollback() {
                // Handled by TransactionManager
            }

            @Override
            public void run() {
                EntityManager em = keycloakSession.getProvider(org.keycloak.connections.jpa.JpaConnectionProvider.class).getEntityManager();
                StatusListCounterEntity counter = em.find(StatusListCounterEntity.class, "global", LockModeType.PESSIMISTIC_WRITE);
                if (counter == null) {
                    counter = new StatusListCounterEntity();
                    counter.setId("global");
                    counter.setCurrentIndex(0);
                    em.persist(counter);
                }
                nextIndex[0] = counter.getCurrentIndex();
                counter.setCurrentIndex(nextIndex[0] + 1);
            }
        });
        keycloakSession.getTransactionManager().commit();
        return nextIndex[0];
    }

    public void storeIndexMapping(long idx, String userId, String tokenId, String listId, KeycloakSession keycloakSession) {
        keycloakSession.getTransactionManager().enlist(new KeycloakTransaction() {
            @Override
            public void begin() {
                // Transaction begins automatically
            }

            @Override
            public void commit() {
                // Handled by TransactionManager
            }

            @Override
            public void rollback() {
                // Handled by TransactionManager
            }

            @Override
            public void run() {
                EntityManager em = keycloakSession.getProvider(org.keycloak.connections.jpa.JpaConnectionProvider.class).getEntityManager();
                StatusListMappingEntity mapping = new StatusListMappingEntity();
                mapping.setIdx(idx);
                mapping.setUserId(userId);
                mapping.setTokenId(tokenId);
                mapping.setRealmId(keycloakSession.getContext().getRealm().getId());
                em.persist(mapping);

                // Send status to statuslist-server.com
                try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
                    HttpPost httpPost = new HttpPost("https://statuslist-server.com");
                    Map<String, Object> payload = Map.of(
                        "status", "VALID",
                        "index", idx,
                        "list_id", listId
                    );
                    String jsonPayload = objectMapper.writeValueAsString(payload);
                    httpPost.setEntity(new StringEntity(jsonPayload, "application/json"));
                    httpClient.execute(httpPost, response -> {
                        if (response.getCode() != 200) {
                            logger.warnf("Failed to send status to statuslist-server.com for idx %d: %d %s",
                                idx, response.getCode(), response.getReasonPhrase());
                        }
                        return null;
                    });
                } catch (IOException e) {
                    logger.errorf("Error sending status to statuslist-server.com for idx %d: %s", idx, e.getMessage());
                }
            }
        });
        keycloakSession.getTransactionManager().commit();
    }

    @Override
    public void close() {
        // No resources to close
    }
}