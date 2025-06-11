package com.adorsys.keycloakstatuslist;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakTransaction;
import org.keycloak.provider.Provider;
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
import java.util.Map;

public class StatusListIndexStorageProvider implements Provider {
    private static final Logger logger = Logger.getLogger(StatusListIndexStorageProvider.class);
    private final KeycloakSession session;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public StatusListIndexStorageProvider(KeycloakSession session) {
        this.session = session;
        logger.info("StatusListIndexStorageProvider instantiated for realm: " + session.getContext().getRealm().getId());
    }

    public long getNextIndex(KeycloakSession keycloakSession) {
        logger.debug("Getting next index for realm: " + keycloakSession.getContext().getRealm().getId());
        final long[] nextIndex = {0};
        keycloakSession.getTransactionManager().enlist(new KeycloakTransaction() {
            private boolean active = true;
            private boolean rollbackOnly = false;

            @Override
            public void begin() {
                active = true;
                logger.debug("Transaction begun for getNextIndex");
            }

            @Override
            public void commit() {
                if (active) {
                    active = false;
                    logger.debug("Transaction committed for getNextIndex");
                }
            }

            @Override
            public void rollback() {
                if (active) {
                    active = false;
                    rollbackOnly = false;
                    logger.warn("Transaction rolled back for getNextIndex");
                }
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

            public void run() {
                EntityManager em = keycloakSession.getProvider(JpaConnectionProvider.class).getEntityManager();
                if (em == null) {
                    logger.error("EntityManager is null for JpaConnectionProvider");
                    setRollbackOnly();
                    return;
                }
                StatusListCounterEntity counter = em.find(StatusListCounterEntity.class, "global", LockModeType.PESSIMISTIC_WRITE);
                if (counter == null) {
                    logger.info("Creating new StatusListCounterEntity");
                    counter = new StatusListCounterEntity();
                    counter.setId("global");
                    counter.setCurrentIndex(0);
                    em.persist(counter);
                }
                nextIndex[0] = counter.getCurrentIndex();
                counter.setCurrentIndex(nextIndex[0] + 1);
                logger.debug("Next index: " + nextIndex[0]);
            }
        });
        return nextIndex[0];
    }

    public void storeIndexMapping(long idx, String userId, String tokenId, String listId, KeycloakSession keycloakSession, String server_endpoint) {
        logger.debug("Storing index mapping: idx=" + idx + ", userId=" + userId + ", tokenId=" + tokenId + ", listId=" + listId);
        keycloakSession.getTransactionManager().enlist(new KeycloakTransaction() {
            private boolean active = true;
            private boolean rollbackOnly = false;

            @Override
            public void begin() {
                active = true;
                logger.debug("Transaction begun for storeIndexMapping");
            }

            @Override
            public void commit() {
                if (active) {
                    active = false;
                    logger.debug("Transaction committed for storeIndexMapping");
                }
            }

            @Override
            public void rollback() {
                if (active) {
                    active = false;
                    rollbackOnly = false;
                    logger.warn("Transaction rolled back for storeIndexMapping");
                }
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

            // public void run() {
            //     EntityManager em = keycloakSession.getProvider(JpaConnectionProvider.class).getEntityManager();
            //     if (em == null) {
            //         logger.error("EntityManager is null for JpaConnectionProvider");
            //         setRollbackOnly();
            //         return;
            //     }
            //     StatusListMappingEntity mapping = new StatusListMappingEntity();
            //     mapping.setIdx(idx);
            //     mapping.setUserId(userId);
            //     mapping.setTokenId(tokenId);
            //     mapping.setRealmId(keycloakSession.getContext().getRealm().getId());
            //     em.persist(mapping);
            //     logger.debug("Persisted StatusListMappingEntity");

            //     // Send status to statuslist server
            //     try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            //         HttpPost httpPost = new HttpPost(server_endpoint);
            //         Map<String, Object> payload = Map.of(
            //             "status", "VALID",
            //             "index", idx,
            //             "list_id", listId
            //         );
            //         String jsonPayload = objectMapper.writeValueAsString(payload);
            //         httpPost.setEntity(new StringEntity(jsonPayload, null, "application/json", active));
            //         httpClient.execute(httpPost, response -> {
            //             if (response.getCode() != 200) {
            //                 logger.warnf("Failed to send status to statuslist-server.com for idx %d: %d %s",
            //                     idx, response.getCode(), response.getReasonPhrase());
            //             } else {
            //                 logger.debug("Successfully sent status to statuslist-server.com for idx " + idx);
            //             }
            //             return null;
            //         });
            //     } catch (IOException e) {
            //         logger.errorf("Error sending status to statuslist-server.com for idx %d: %s", idx, e.getMessage());
            //     }
            // }
        });
    }

    @Override
    public void close() {
        logger.debug("Closing StatusListIndexStorageProvider");
    }
}