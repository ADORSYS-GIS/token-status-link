package io.github.adorsysgis.keycloakstatuslist.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import jakarta.ws.rs.core.Response;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.util.JsonSerialization;
import org.testcontainers.Testcontainers;

abstract class BaseKeycloakIntegrationTest {

    private static final String DEFAULT_KEYCLOAK_VERSION = "26.7.2";
    private static final String KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:";
    static final String REALM = "status-list-it";
    static final String PASSWORD = "password";
    static final String CLIENT_ID = "openid4vc-rest-api";
    static final String CLIENT_SECRET = "secret";
    static final String CREDENTIAL_CONFIGURATION_ID = "IdentityCredential";
    private static final AtomicInteger USER_COUNTER = new AtomicInteger();

    static RecordingStatusListServer statusListServer;
    static KeycloakContainer keycloak;
    static Oid4vciTestClient oid4vci;

    @BeforeAll
    static void startKeycloak() throws Exception {
        CryptoIntegration.init(BaseKeycloakIntegrationTest.class.getClassLoader());
        statusListServer = RecordingStatusListServer.start();
        Testcontainers.exposeHostPorts(statusListServer.port());

        keycloak = new KeycloakContainer(KEYCLOAK_IMAGE + keycloakVersion())
                .withDefaultProviderClasses()
                .withProviderLibsFrom(providerLibs())
                .withRealmImportFiles("/realms/status-list-it-realm.json")
                .withFeaturesEnabled("oid4vc-vci", "oid4vc-vci-rest-credential-offer", "oid4vc-vci-preauth-code")
                .withEnv("KC_LOG_LEVEL", "INFO,io.github.adorsysgis.keycloakstatuslist:DEBUG")
                .withEnv("JAVA_OPTS_APPEND", "-Xms512m -Xmx1536m");
        keycloak.start();

        oid4vci = new Oid4vciTestClient(keycloak, REALM, CLIENT_ID, CLIENT_SECRET, CREDENTIAL_CONFIGURATION_ID);
        configureStatusListRealm();
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

    static TestUser credentialHolder(String prefix) throws Exception {
        String username = prefix + "-" + USER_COUNTER.incrementAndGet();
        createUser(username);
        grantCredential(username);
        return new TestUser(username, oid4vci.userAccessToken(username, PASSWORD));
    }

    private static void createUser(String username) {
        CredentialRepresentation password = new CredentialRepresentation();
        password.setType(CredentialRepresentation.PASSWORD);
        password.setValue(PASSWORD);
        password.setTemporary(false);

        UserRepresentation user = new UserRepresentation();
        user.setUsername(username);
        user.setEmail(username + "@example.test");
        user.setEmailVerified(true);
        user.setFirstName(username);
        user.setLastName("Holder");
        user.setEnabled(true);
        user.setRequiredActions(List.of());
        user.singleAttribute("birthdate", "1990-01-01");
        user.setCredentials(List.of(password));

        try (Response response = realm().users().create(user)) {
            assertEquals(201, response.getStatus(), "test user should be created");
        }

        String userId = userId(username);
        RoleRepresentation credentialOfferCreate =
                realm().roles().get("credential-offer-create").toRepresentation();
        realm().users().get(userId).roles().realmLevel().add(List.of(credentialOfferCreate));
    }

    private static void grantCredential(String username) throws Exception {
        String userId = userId(username);

        int statusCode = oid4vci.grantCredential(userId);
        assertTrue(
                (statusCode >= 200 && statusCode < 300) || statusCode == 409,
                "credential grant should be created or already exists, got HTTP " + statusCode);
    }

    private static String userId(String username) {
        return realm().users().searchByUsername(username, true).stream()
                .findFirst()
                .orElseThrow(() -> new AssertionError("Test user not found: " + username))
                .getId();
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

    private static String keycloakVersion() {
        return System.getProperty("keycloak.version", DEFAULT_KEYCLOAK_VERSION);
    }

    private static List<File> providerLibs() throws IOException {
        Path libsDir = Path.of(System.getProperty("provider.libs.dir", "target/provider-libs"));
        if (!Files.isDirectory(libsDir)) {
            throw new IllegalStateException("Provider dependencies not found at " + libsDir);
        }

        try (Stream<Path> libs = Files.list(libsDir)) {
            List<java.io.File> jars = libs.filter(path -> path.toString().endsWith(".jar"))
                    .map(Path::toFile)
                    .toList();
            if (jars.isEmpty()) {
                throw new IllegalStateException("No provider dependency jars found at " + libsDir);
            }
            return jars;
        }
    }

    record TestUser(String username, String accessToken) {}
}
