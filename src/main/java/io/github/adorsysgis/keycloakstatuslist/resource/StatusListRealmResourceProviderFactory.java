package io.github.adorsysgis.keycloakstatuslist.resource;

import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import io.github.adorsysgis.keycloakstatuslist.service.CredentialRevocationService;
import io.github.adorsysgis.keycloakstatuslist.service.RealmAsIssuerRegistrationService;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Factory for {@link StatusListRealmResourceProvider}.
 *
 * <p>This factory hooks realm lifecycle events and delegates realm registration as "Issuers" on the
 * external status list server to {@link RealmAsIssuerRegistrationService}.
 */
public class StatusListRealmResourceProviderFactory implements RealmResourceProviderFactory {

    private static final Logger logger = Logger.getLogger(StatusListRealmResourceProviderFactory.class);

    public static final String PROVIDER_ID = "status-list";

    private RealmAsIssuerRegistrationService registrationService;

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        CredentialRevocationService revocationService = new CredentialRevocationService(session);
        return new StatusListRealmResourceProvider(session, revocationService);
    }

    @Override
    public void init(org.keycloak.Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        registrationService = createRegistrationService(factory);
        factory.register(event -> {
            if (event instanceof PostMigrationEvent) {
                logger.info("Initializing realms as issuers on status list server");
                registrationService.triggerBackgroundRegistration();
            } else if (event instanceof RealmModel.RealmPostCreateEvent realmEvent) {
                RealmModel realm = realmEvent.getCreatedRealm();
                logger.infof("New realm created: %s. Scheduling issuer registration", realm.getName());
                registrationService.triggerBackgroundRegistration(realm.getId());
            } else if (event instanceof RealmModel.RealmAttributeUpdateEvent attributeEvent
                    && StatusListConfig.STATUS_LIST_ENABLED.equals(attributeEvent.getAttributeName())
                    && Boolean.parseBoolean(attributeEvent.getAttributeValue())) {
                RealmModel realm = attributeEvent.getRealm();
                logger.infof("Status list enabled for realm %s. Scheduling issuer registration", realm.getName());
                registrationService.triggerBackgroundRegistration(realm.getId());
            }
        });
    }

    @Override
    public void close() {
        if (registrationService != null) {
            registrationService.close();
        }
    }

    /**
     * Creates the registration service; overridable in tests to inject a version whose
     * scheduling and HTTP clients are observable.
     */
    protected RealmAsIssuerRegistrationService createRegistrationService(KeycloakSessionFactory factory) {
        return new RealmAsIssuerRegistrationService(factory);
    }
}
