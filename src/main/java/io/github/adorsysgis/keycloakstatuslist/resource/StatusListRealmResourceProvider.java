package io.github.adorsysgis.keycloakstatuslist.resource;

import io.github.adorsysgis.keycloakstatuslist.service.CredentialRevocationService;
import jakarta.ws.rs.Path;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resource.RealmResourceProvider;

/**
 * Realm-scoped JAX-RS resource that exposes the plugin's inbound endpoints.
 *
 * <p>The provider is mounted under {@code /realms/{realm}/status-list} and contributes two sub-resources:
 *
 * <ul>
 *   <li>{@code POST /revoke} - revokes an issued credential via the status list server</li>
 *   <li>{@code GET /issued-credential-status} - lists the authenticated user's issued credentials with their status</li>
 * </ul>
 */
public class StatusListRealmResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;
    private final CredentialRevocationService revocationService;
    private final StatusListRealmResourceProviderFactory factory;

    public StatusListRealmResourceProvider(
            KeycloakSession session,
            CredentialRevocationService revocationService,
            StatusListRealmResourceProviderFactory factory) {
        this.session = session;
        this.revocationService = revocationService;
        this.factory = factory;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Path("revoke")
    public Object revoke() {
        triggerBackgroundRegistration();
        return new CredentialRevocationEndpoint(session, revocationService);
    }

    @Path("issued-credential-status")
    public Object issuedCredentialStatus() {
        triggerBackgroundRegistration();
        return new IssuedCredentialStatusEndpoint(session, revocationService);
    }

    private void triggerBackgroundRegistration() {
        RealmModel realm = session.getContext().getRealm();
        if (realm != null) {
            KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();
            factory.triggerBackgroundRegistration(sessionFactory, realm.getName());
        }
    }

    @Override
    public void close() {}
}
