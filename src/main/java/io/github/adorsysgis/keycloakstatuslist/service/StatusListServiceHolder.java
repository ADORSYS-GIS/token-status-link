package io.github.adorsysgis.keycloakstatuslist.service;

import io.github.adorsysgis.keycloakstatuslist.client.ApacheHttpStatusListClient;
import io.github.adorsysgis.keycloakstatuslist.client.StatusListHttpClient;
import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.Provider;

/**
 * Session-scoped holder for the shared {@link StatusListService} and its HTTP client.
 *
 * <p>One client is created per session, shared by the mapper and the revocation service, and
 * released once when the session ends via {@link KeycloakSession#enlistForClose(Provider)}.
 */
public class StatusListServiceHolder implements Provider {

    /** Session attribute under which the shared holder is stored. */
    public static final String SESSION_ATTRIBUTE = StatusListServiceHolder.class.getName() + ".instance";

    private final StatusListService statusListService;

    private StatusListServiceHolder(StatusListService statusListService) {
        this.statusListService = statusListService;
    }

    /**
     * Returns the session's shared {@link StatusListService}, creating and enlisting it on first use.
     */
    public static StatusListService getOrCreate(KeycloakSession session) {
        StatusListServiceHolder holder = session.getAttribute(SESSION_ATTRIBUTE, StatusListServiceHolder.class);
        if (holder == null) {
            holder = new StatusListServiceHolder(build(session));
            session.setAttribute(SESSION_ATTRIBUTE, holder);
            session.enlistForClose(holder);
        }
        return holder.statusListService;
    }

    /**
     * Builds a {@link StatusListService} with a self-owned HTTP client for the given session.
     */
    private static StatusListService build(KeycloakSession session) {
        StatusListConfig config = new StatusListConfig(session.getContext().getRealm());
        CryptoIdentityService cryptoIdentityService = new CryptoIdentityService(session);

        CircuitBreaker circuitBreaker = null;
        if (config.getIssuanceTimeout() > 0) {
            circuitBreaker = CircuitBreaker.getInstance(config);
        }

        StatusListHttpClient httpClient = new ApacheHttpStatusListClient(
                config.getServerUrl(), cryptoIdentityService.getJwtToken(config), config, circuitBreaker);

        return new StatusListService(httpClient);
    }

    @Override
    public void close() {
        statusListService.close();
    }
}
