package com.adorsys.keycloakstatuslist;

import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.Provider;
import org.jboss.logging.Logger;
import liquibase.Liquibase;
import liquibase.database.Database;
import liquibase.database.DatabaseFactory;
import liquibase.database.jvm.JdbcConnection;
import liquibase.resource.ClassLoaderResourceAccessor;

import java.sql.Connection;
import jakarta.persistence.EntityManager;
import org.keycloak.connections.jpa.JpaConnectionProvider;

public class LiquibaseMigrationProvider implements Provider {
    private static final Logger logger = Logger.getLogger(LiquibaseMigrationProvider.class);
    private final KeycloakSession session;
    private static final String CHANGELOG_PATH = "db/changelog/db.changelog-master.yaml";

    public LiquibaseMigrationProvider(KeycloakSession session) {
        this.session = session;
        System.out.println("DEBUG: Initialized LiquibaseMigrationProvider");
    }

    public void executeMigration() {
        System.out.println("DEBUG: Starting Liquibase migration for status list tables on node " + System.getProperty("jboss.node.name", "unknown"));
        logger.infof("Executing Liquibase migration for status list tables on node %s", System.getProperty("jboss.node.name", "unknown"));
        try {
            JpaConnectionProvider jpaConnectionProvider = session.getProvider(JpaConnectionProvider.class);
            EntityManager em = jpaConnectionProvider.getEntityManager();
            Connection connection = em.unwrap(Connection.class);
            if (connection == null) {
                System.out.println("DEBUG: Database connection is null");
                logger.error("Failed to obtain database connection from JpaConnectionProvider");
                throw new RuntimeException("Database connection is null");
            }
            System.out.println("DEBUG: Connection acquired, URL=" + connection.getMetaData().getURL());
            ClassLoaderResourceAccessor resourceAccessor = new ClassLoaderResourceAccessor(getClass().getClassLoader());
            if (getClass().getClassLoader().getResourceAsStream(CHANGELOG_PATH) == null) {
                System.out.println("DEBUG: Changelog file not found at " + CHANGELOG_PATH);
                logger.errorf("Changelog file %s not found", CHANGELOG_PATH);
                throw new RuntimeException("Missing Liquibase changelog file");
            }
            System.out.println("DEBUG: Changelog file found at " + CHANGELOG_PATH);
            Database database = DatabaseFactory.getInstance()
                    .findCorrectDatabaseImplementation(new JdbcConnection(connection));
            System.out.println("DEBUG: Initialized Liquibase database for schema: " + database.getDefaultSchemaName());
            try (Liquibase liquibase = new Liquibase(CHANGELOG_PATH, resourceAccessor, database)) {
                System.out.println("DEBUG: Executing Liquibase update");
                liquibase.forceReleaseLocks();
                liquibase.update("");
                System.out.println("DEBUG: Liquibase migration completed successfully");
                logger.info("Liquibase migration completed successfully");
            }
        } catch (Exception e) {
            System.out.println("DEBUG: Migration failed with exception: " + e.getMessage());
            logger.errorf("Liquibase migration failed: %s", e.getMessage(), e);
            throw new RuntimeException("Liquibase migration failed", e);
        }
    }

    @Override
    public void close() {
        System.out.println("DEBUG: Closing LiquibaseMigrationProvider");
    }
}