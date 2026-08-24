package com.adorsys.keycloakstatuslist.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import java.io.File;
import java.io.IOException;
import java.util.List;
import org.jboss.logging.Logger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.util.JsonSerialization;
import org.testcontainers.Testcontainers;

abstract class BaseKeycloakIntegrationTest {

    private static final Logger logger = Logger.getLogger(BaseKeycloakIntegrationTest.class);

    static final String REALM = "status-list-it";
    static final String ALICE = "alice";
    static final String BOB = "bob";
    static final String PASSWORD = "password";
    static final String CLIENT_ID = "openid4vc-rest-api";
    static final String CLIENT_SECRET = "secret";
    static final String CREDENTIAL_CONFIGURATION_ID = "IdentityCredential";

    static RecordingStatusListServer statusListServer;
    static KeycloakContainer keycloak;
    static Oid4vciTestClient oid4vci;

    @BeforeAll
    static void startKeycloak() throws Exception {
        CryptoIntegration.init(BaseKeycloakIntegrationTest.class.getClassLoader());
        statusListServer = RecordingStatusListServer.start();
        Testcontainers.exposeHostPorts(statusListServer.port());

        keycloak = new KeycloakContainer(
                        "quay.io/keycloak/keycloak:" + System.getProperty("keycloak.version", "26.7.0"))
                .withProviderLibsFrom(List.of(pluginJar()))
                .withRealmImportFiles("/realms/status-list-it-realm.json")
                .withFeaturesEnabled("oid4vc-vci", "oid4vc-vci-rest-credential-offer", "oid4vc-vci-preauth-code")
                .withEnv("KC_LOG_LEVEL", "INFO,com.adorsys.keycloakstatuslist:DEBUG")
                .withEnv("JAVA_OPTS_APPEND", "-Xms512m -Xmx1536m");
        keycloak.start();

        oid4vci = new Oid4vciTestClient(keycloak, REALM, CLIENT_ID, CLIENT_SECRET, CREDENTIAL_CONFIGURATION_ID);
        configureStatusListRealm();
        grantCredential(ALICE);
        grantCredential(BOB);
    }

    @AfterAll
    static void stopServers() {
        if (keycloak != null) {
            keycloak.stop();
        }
        if (statusListServer != null) {
            statusListServer.close();
        }
    }

    static RealmResource realm() {
        return keycloak.getKeycloakAdminClient().realm(REALM);
    }

    private static void configureStatusListRealm() {
        RealmRepresentation realm = realm().toRepresentation();
        realm.getAttributes().put(StatusListConfig.STATUS_LIST_ENABLED, "true");
        realm.getAttributes().put(StatusListConfig.STATUS_LIST_MANDATORY, "true");
        realm.getAttributes().put(StatusListConfig.STATUS_LIST_SERVER_URL, statusListServer.externalUrl());
        realm.getAttributes().put(StatusListConfig.STATUS_LIST_ISSUANCE_TIMEOUT, "10000");
        realm.getAttributes().put(StatusListConfig.STATUS_LIST_REGISTRATION_TIMEOUT, "10000");
        realm().update(realm);
    }

    private static void grantCredential(String username) throws Exception {
        String userId = realm().users().searchByUsername(username, true).stream()
                .findFirst()
                .orElseThrow(() -> new AssertionError("Test user not found: " + username))
                .getId();

        int statusCode = oid4vci.grantCredential(userId);
        assertTrue(
                (statusCode >= 200 && statusCode < 300) || statusCode == 409,
                "credential grant should be created or already exist, got HTTP " + statusCode);
    }

    static void assertStatusListValue(IssuedCredentialFixture credential, int expectedStatus) {
        assertEquals(
                expectedStatus,
                statusListServer
                        .statusFor(credential.statusListId(), credential.statusIndex())
                        .orElseThrow());
    }

    static void assertCredentialStatus(String accessToken, String credentialId, String expectedStatus)
            throws IOException, InterruptedException {
        var statuses = oid4vci.issuedCredentialStatuses(accessToken).path("credentials");
        assertNotNull(statuses, "status endpoint must return credentials");
        for (var credential : statuses) {
            if (credentialId.equals(credential.path("credentialId").asText())) {
                assertEquals(expectedStatus, credential.path("status").asText());
                return;
            }
        }
        throw new AssertionError("Credential status not found for " + credentialId + ": "
                + JsonSerialization.mapper.writeValueAsString(statuses));
    }

    private static File pluginJar() {
        File pluginJar =
                new File(System.getProperty("plugin.jar", "target/keycloak-token-status-plugin-1.0.0-SNAPSHOT.jar"));
        if (!pluginJar.exists()) {
            String message =
                    "Shaded plugin jar not found at " + pluginJar + ". Run './mvnw package -DskipTests' first.";
            logger.error(message);
            throw new IllegalStateException(message);
        }
        return pluginJar;
    }
}
