package com.adorsys.keycloakstatuslist;

import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.jboss.logging.Logger;
import liquibase.Liquibase;
import liquibase.database.Database;
import liquibase.database.DatabaseFactory;
import liquibase.database.jvm.JdbcConnection;
import liquibase.resource.ClassLoaderResourceAccessor;

import jakarta.persistence.EntityManager;
import java.sql.Connection;

public class LiquibaseMigrationRunner {
    private static final Logger logger = Logger.getLogger(LiquibaseMigrationRunner.class);
    private static volatile boolean migrated = false;

    public static void runMigration(KeycloakSession session) {
        if (migrated) {
            logger.debug("Liquibase migration already executed, skipping");
            return;
        }
        synchronized (LiquibaseMigrationRunner.class) {
            if (migrated) {
                return;
            }
            logger.info("Executing Liquibase migration for status list tables");
            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
            try (Connection connection = em.unwrap(Connection.class)) {
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
            }
        }
    }
}