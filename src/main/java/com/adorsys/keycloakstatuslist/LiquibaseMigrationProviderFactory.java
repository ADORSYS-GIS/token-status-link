package com.adorsys.keycloakstatuslist;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderFactory;
import org.jboss.logging.Logger;

public class LiquibaseMigrationProviderFactory implements ProviderFactory<LiquibaseMigrationProvider> {
    private static final Logger logger = Logger.getLogger(LiquibaseMigrationProviderFactory.class);
    private static volatile boolean migrated = false;

    @Override
    public LiquibaseMigrationProvider create(KeycloakSession session) {
        System.out.println("DEBUG: Creating LiquibaseMigrationProvider");
        return new LiquibaseMigrationProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
        System.out.println("DEBUG: Initializing LiquibaseMigrationProviderFactory");
        logger.debug("Initializing LiquibaseMigrationProviderFactory");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        System.out.println("DEBUG: Entering postInit, migrated=" + migrated);
        if (migrated) {
            System.out.println("DEBUG: Migration already executed, skipping");
            logger.debug("Liquibase migration already executed, skipping");
            return;
        }
        synchronized (LiquibaseMigrationProviderFactory.class) {
            System.out.println("DEBUG: Inside synchronized block, migrated=" + migrated);
            if (migrated) {
                return;
            }
            KeycloakSession session = factory.create();
            try {
                System.out.println("DEBUG: Starting migration");
                LiquibaseMigrationProvider provider = create(session);
                provider.executeMigration();
                migrated = true;
                System.out.println("DEBUG: Migration completed, migrated set to true");
            } finally {
                session.close();
            }
        }
    }

    @Override
    public void close() {
        System.out.println("DEBUG: Closing LiquibaseMigrationProviderFactory");
    }

    @Override
    public String getId() {
        return "liquibase-migration-runner";
    }
}