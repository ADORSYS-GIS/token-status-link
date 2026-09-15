package io.github.adorsysgis.keycloakstatuslist.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import io.github.adorsysgis.keycloakstatuslist.exception.CredentialIssuanceQuotaException;
import io.github.adorsysgis.keycloakstatuslist.model.IssuedCredentialStatusResponse;
import io.github.adorsysgis.keycloakstatuslist.model.TokenStatus;
import io.github.adorsysgis.keycloakstatuslist.service.CredentialIssuanceQuotaService;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.RealmRepresentation;

class KeycloakStatusListFlowIT extends BaseKeycloakIntegrationTest {

    @Test
    void issuedCredentialEmbedsStatusClaim() throws Exception {
        TestUser user = credentialHolder("status-claim");

        IssuedCredentialFixture credential = oid4vci.issueCredential(user.username(), user.accessToken());

        assertTrue(credential.statusIndex() >= 0, "credential status claim must contain status_list.idx");
        assertTrue(
                credential.statusUri().startsWith(statusListServer.externalUrl()),
                "status claim must point to the configured status list server");
        assertStatusListValue(credential, TokenStatus.VALID.getCode());
        assertCredentialStatus(user.accessToken(), credential.id(), TokenStatus.VALID.name());
    }

    @Test
    void userCanRevokeIssuedCredentialWithBearerToken() throws Exception {
        TestUser user = credentialHolder("revoker");
        IssuedCredentialFixture credential = oid4vci.issueCredential(user.username(), user.accessToken());

        var response = oid4vci.revokeCredential(user.accessToken(), credential.id(), "integration test");

        assertEquals(200, response.statusCode());
        assertTrue(oid4vci.readJson(response).path("success").asBoolean(false));
        assertStatusListValue(credential, TokenStatus.INVALID.getCode());
        assertCredentialStatus(user.accessToken(), credential.id(), TokenStatus.INVALID.name());
    }

    @Test
    void userCannotRevokeAnotherUsersCredential() throws Exception {
        TestUser owner = credentialHolder("owner");
        TestUser otherUser = credentialHolder("other-user");
        IssuedCredentialFixture ownerCredential = oid4vci.issueCredential(owner.username(), owner.accessToken());

        var response = oid4vci.revokeCredential(otherUser.accessToken(), ownerCredential.id(), "not mine");

        assertEquals(404, response.statusCode());
        assertFalse(oid4vci.readJson(response).path("success").asBoolean(true));
        assertStatusListValue(ownerCredential, TokenStatus.VALID.getCode());
        assertCredentialStatus(owner.accessToken(), ownerCredential.id(), TokenStatus.VALID.name());
    }

    @Test
    void offerAdminCanRevokeAnotherUsersCredential() throws Exception {
        TestUser owner = credentialHolder("admin-revoke-owner");
        TestUser admin = offerAdmin("offer-admin");
        IssuedCredentialFixture ownerCredential = oid4vci.issueCredential(owner.username(), owner.accessToken());

        var response = oid4vci.revokeCredential(admin.accessToken(), ownerCredential.id(), "admin revocation");

        assertEquals(200, response.statusCode());
        assertTrue(oid4vci.readJson(response).path("success").asBoolean(false));
        assertStatusListValue(ownerCredential, TokenStatus.INVALID.getCode());
        assertCredentialStatus(owner.accessToken(), ownerCredential.id(), TokenStatus.INVALID.name());
    }

    @Test
    void offerAdminCanListAnotherUsersIssuedCredentials() throws Exception {
        TestUser owner = credentialHolder("list-owner");
        TestUser other = credentialHolder("list-other");
        TestUser admin = offerAdmin("list-admin");
        IssuedCredentialFixture ownerCredential = oid4vci.issueCredential(owner.username(), owner.accessToken());
        IssuedCredentialFixture otherCredential = oid4vci.issueCredential(other.username(), other.accessToken());

        var adminOwnStatuses =
                oid4vci.issuedCredentialStatuses(admin.accessToken()).path("credentials");
        assertFalse(containsCredential(adminOwnStatuses, ownerCredential.id()));
        assertFalse(containsCredential(adminOwnStatuses, otherCredential.id()));

        var filtered = oid4vci.issuedCredentialStatuses(admin.accessToken(), owner.username())
                .path("credentials");
        assertTrue(containsCredential(filtered, ownerCredential.id()));
        assertFalse(containsCredential(filtered, otherCredential.id()));
        assertEquals(owner.username(), fieldFor(filtered, ownerCredential.id(), "username"));
        assertEquals(CREDENTIAL_CONFIGURATION_ID, fieldFor(filtered, ownerCredential.id(), "credentialType"));
        assertEquals(CLIENT_ID, fieldFor(filtered, ownerCredential.id(), "clientName"));

        var otherStatuses =
                oid4vci.issuedCredentialStatuses(other.accessToken()).path("credentials");
        assertFalse(containsCredential(otherStatuses, ownerCredential.id()));
        assertTrue(containsCredential(otherStatuses, otherCredential.id()));
    }

    @Test
    void holderCannotListAnotherUsersIssuedCredentialsViaTargetUser() throws Exception {
        TestUser owner = credentialHolder("holder-target-owner");
        TestUser other = credentialHolder("holder-target-other");

        var response = oid4vci.issuedCredentialStatusesResponse(other.accessToken(), owner.username());
        assertEquals(403, response.statusCode());
        assertFalse(oid4vci.readJson(response).path("success").asBoolean(true));
    }

    @Test
    void revocationRequiresBearerToken() throws Exception {
        TestUser user = credentialHolder("unauthenticated");
        IssuedCredentialFixture credential = oid4vci.issueCredential(user.username(), user.accessToken());

        var response = oid4vci.revokeCredential(null, credential.id(), "missing token");

        assertEquals(401, response.statusCode());
        assertFalse(oid4vci.readJson(response).path("success").asBoolean(true));
        assertStatusListValue(credential, TokenStatus.VALID.getCode());
    }

    @Test
    void issuanceIsRejectedWhenHolderReachesConfiguredMaxForCredentialType() throws Exception {
        setMaxCredentialsPerUser("1");
        try {
            TestUser holder = credentialHolder("quota-holder");
            TestUser otherHolder = credentialHolder("quota-other");

            IssuedCredentialFixture first = oid4vci.issueCredential(holder.username(), holder.accessToken());
            assertCredentialStatus(holder.accessToken(), first.id(), TokenStatus.VALID.name());
            assertLimit(holder.accessToken(), CREDENTIAL_CONFIGURATION_ID, 1, 1, 0);

            var rejected = oid4vci.requestIssuedCredential(holder.username(), holder.accessToken());
            assertQuotaRejection(rejected);

            IssuedCredentialFixture otherCredential =
                    oid4vci.issueCredential(otherHolder.username(), otherHolder.accessToken());
            assertCredentialStatus(otherHolder.accessToken(), otherCredential.id(), TokenStatus.VALID.name());

            var revokeResponse = oid4vci.revokeCredential(holder.accessToken(), first.id(), "free quota slot");
            assertEquals(200, revokeResponse.statusCode());
            assertLimit(holder.accessToken(), CREDENTIAL_CONFIGURATION_ID, 1, 0, 1);

            IssuedCredentialFixture reissued = oid4vci.issueCredential(holder.username(), holder.accessToken());
            assertCredentialStatus(holder.accessToken(), reissued.id(), TokenStatus.VALID.name());
            assertLimit(holder.accessToken(), CREDENTIAL_CONFIGURATION_ID, 1, 1, 0);
        } finally {
            setMaxCredentialsPerUser(null);
        }
    }

    @Test
    void concurrentIssuanceRespectsConfiguredMaxOfOne() throws Exception {
        setMaxCredentialsPerUser("1");
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            TestUser holder = credentialHolder("quota-race");
            CountDownLatch start = new CountDownLatch(1);

            Callable<Oid4vciTestClient.CredentialIssuanceAttempt> attempt = () -> {
                assertTrue(start.await(30, TimeUnit.SECONDS), "workers should start together");
                return oid4vci.requestIssuedCredential(holder.username(), holder.accessToken());
            };

            Future<Oid4vciTestClient.CredentialIssuanceAttempt> first = executor.submit(attempt);
            Future<Oid4vciTestClient.CredentialIssuanceAttempt> second = executor.submit(attempt);
            start.countDown();

            List<Oid4vciTestClient.CredentialIssuanceAttempt> attempts = new ArrayList<>();
            attempts.add(first.get(60, TimeUnit.SECONDS));
            attempts.add(second.get(60, TimeUnit.SECONDS));

            long successes = attempts.stream()
                    .filter(a ->
                            a.response().statusCode() >= 200 && a.response().statusCode() < 300)
                    .count();
            long conflicts = attempts.stream()
                    .filter(a -> a.response().statusCode() == 409)
                    .count();

            assertEquals(1, successes, "exactly one concurrent issuance should succeed: " + attempts);
            assertEquals(1, conflicts, "exactly one concurrent issuance should return 409: " + attempts);
            attempts.stream()
                    .filter(a -> a.response().statusCode() == 409)
                    .forEach(KeycloakStatusListFlowIT::assertQuotaRejection);
            assertLimit(holder.accessToken(), CREDENTIAL_CONFIGURATION_ID, 1, 1, 0);
        } finally {
            executor.shutdownNow();
            setMaxCredentialsPerUser(null);
        }
    }

    private static void assertQuotaRejection(Oid4vciTestClient.CredentialIssuanceAttempt attempt) {
        assertEquals(
                409,
                attempt.response().statusCode(),
                "quota rejection should be HTTP 409 Conflict, got HTTP "
                        + attempt.response().statusCode() + ": "
                        + attempt.response().body());
        try {
            var body = oid4vci.readJson(attempt.response());
            assertEquals(
                    CredentialIssuanceQuotaException.ERROR_LIMIT_REACHED,
                    body.path("error").asText(),
                    "quota rejection body: " + attempt.response().body());
            assertEquals(
                    CredentialIssuanceQuotaService.LIMIT_REACHED_MESSAGE,
                    body.path("error_description").asText(),
                    "quota rejection body: " + attempt.response().body());
        } catch (Exception e) {
            throw new AssertionError(
                    "Failed to parse quota rejection body: "
                            + attempt.response().body(),
                    e);
        }
    }

    private static void assertLimit(
            String accessToken, String credentialConfigurationId, int max, int activeCount, int remaining)
            throws Exception {
        var limits = oid4vci.issuedCredentialStatuses(accessToken).path("limits");
        for (var limit : limits) {
            if (credentialConfigurationId.equals(
                    limit.path("credentialConfigurationId").asText())) {
                assertEquals(max, limit.path("max").asInt());
                assertEquals(activeCount, limit.path("activeCount").asInt());
                assertEquals(remaining, limit.path("remaining").asInt());
                assertEquals(
                        IssuedCredentialStatusResponse.OVERFLOW_POLICY_REJECT,
                        limit.path("overflowPolicy").asText());
                return;
            }
        }
        throw new AssertionError("Quota metadata not found for " + credentialConfigurationId + ": " + limits);
    }

    /**
     * Uses the realm fallback instead of updating the OID4VC protocol mapper. Mutating that mapper
     * through the admin API can drop the client scope from credential-configuration lookup and later
     * issuances then fail with HTTP 409 Duplicate resource.
     */
    private static void setMaxCredentialsPerUser(String max) {
        RealmRepresentation realm = realm().toRepresentation();
        if (max == null) {
            realm.getAttributes().remove(StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER);
        } else {
            realm.getAttributes().put(StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER, max);
        }
        realm().update(realm);
    }

    private static boolean containsCredential(JsonNode statuses, String credentialId) {
        if (statuses == null || !statuses.isArray()) {
            return false;
        }
        for (JsonNode credential : statuses) {
            if (credentialId.equals(credential.path("credentialId").asText())) {
                return true;
            }
        }
        return false;
    }

    private static String fieldFor(JsonNode statuses, String credentialId, String field) {
        for (JsonNode credential : statuses) {
            if (credentialId.equals(credential.path("credentialId").asText())) {
                return credential.path(field).asText();
            }
        }
        throw new AssertionError("Credential not found: " + credentialId);
    }
}
