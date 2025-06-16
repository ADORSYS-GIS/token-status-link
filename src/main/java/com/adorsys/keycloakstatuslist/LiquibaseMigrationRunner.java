package com.adorsys.keycloakstatuslist;

import org.keycloak.Config;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.jboss.logging.Logger;
import liquibase.Liquibase;
import liquibase.database.Database;
import liquibase.database.DatabaseFactory;
import liquibase.database.jvm.JdbcConnection;
import liquibase.resource.ClassLoaderResourceAccessor;

import java.sql.Connection;

/**
 * Runs Liquibase migrations during Keycloak startup to create database tables for status list indices and mappings.
 * Registered as a ProviderFactory via META-INF/services, executed in postInit to ensure schema setup for StatusListProtocolMapper.
 */
public class LiquibaseMigrationRunner implements Provider, ProviderFactory<LiquibaseMigrationRunner> {
    private static final Logger logger = Logger.getLogger(LiquibaseMigrationRunner.class);
    private static volatile boolean migrated = false;
    private final KeycloakSession session;

    // Constructor for provider instance
    public LiquibaseMigrationRunner(KeycloakSession session) {
        this.session = session;
    }

    // Default constructor for factory
    public LiquibaseMigrationRunner() {
        this.session = null;
    }

    @Override
    public LiquibaseMigrationRunner create(KeycloakSession session) {
        return new LiquibaseMigrationRunner(session);
    }

    @Override
    public void init(Config.Scope config) {
        logger.debug("Initializing LiquibaseMigrationRunner");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        if (migrated) {
            logger.debug("Liquibase migration already executed, skipping");
            return;
        }
        synchronized (LiquibaseMigrationRunner.class) {
            if (migrated) {
                return;
            }
            logger.info("Executing Liquibase migration for status list tables");
            KeycloakSession session = factory.create();
            try {
                JpaConnectionProvider jpaConnectionProvider = session.getProvider(JpaConnectionProvider.class);
                Connection connection = jpaConnectionProvider.getEntityManager().unwrap(Connection.class);
                if (connection == null) {
                    logger.error("Failed to obtain database connection from JpaConnectionProvider");
                    throw new RuntimeException("Database connection is null");
                }
                Database database = DatabaseFactory.getInstance().findCorrectDatabaseImplementation(new JdbcConnection(connection));
                try (Liquibase liquibase = new Liquibase("db/changelog/db.changelog-master.yaml",
                        new ClassLoaderResourceAccessor(LiquibaseMigrationRunner.class.getClassLoader()), database)) {
                    liquibase.update("");
                    logger.info("Liquibase migration completed successfully");
                    migrated = true;
                }
            } catch (Exception e) {
                logger.error("Failed to execute Liquibase migration", e);
                throw new RuntimeException("Liquibase migration failed", e);
            } finally {
                session.close();
            }
        }
    }

    @Override
    public void close() {
        // No resources to close
    }

    @Override
    public String getId() {
        return "liquibase-migration-runner";
    }
}
