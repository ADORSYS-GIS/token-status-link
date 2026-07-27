package com.adorsys.keycloakstatuslist.resource;

import com.adorsys.keycloakstatuslist.client.ApacheHttpStatusListClient;
import com.adorsys.keycloakstatuslist.client.StatusListHttpClient;
import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.service.CircuitBreaker;
import com.adorsys.keycloakstatuslist.service.CryptoIdentityService;
import com.adorsys.keycloakstatuslist.service.CustomHttpClient;
import com.adorsys.keycloakstatuslist.service.StatusListService;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

/**
 * Realm resource provider that exposes the status list admin endpoint
 * under the realm's REST API at /realms/{realm}/status-list-admin.
 */
public class StatusListAdminResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public StatusListAdminResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        StatusListService statusListService = createStatusListService(session);
        return new StatusListAdminResource(session, statusListService);
    }

    /**
     * Builds a StatusListService for the given session (config, circuit breaker, HTTP client).
     */
    private static StatusListService createStatusListService(KeycloakSession session) {
        StatusListConfig config = new StatusListConfig(session.getContext().getRealm());
        CryptoIdentityService cryptoIdentityService = new CryptoIdentityService(session);

        CircuitBreaker circuitBreaker = null;
        if (config.getIssuanceTimeout() > 0) {
            circuitBreaker = CircuitBreaker.getInstance(config);
        }

        StatusListHttpClient httpClient = new ApacheHttpStatusListClient(
                config.getServerUrl(),
                cryptoIdentityService.getJwtToken(config),
                CustomHttpClient.getHttpClient(config),
                circuitBreaker);

        return new StatusListService(httpClient);
    }

    @Override
    public void close() {
        // No resources to close
    }
}
