package io.github.adorsysgis.keycloakstatuslist.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import io.github.adorsysgis.keycloakstatuslist.model.IssuedCredentialStatusResponse;
import io.github.adorsysgis.keycloakstatuslist.model.TokenStatus;
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
        setIssuanceQuota("1", null);
        try {
            TestUser holder = credentialHolder("quota-holder");
            TestUser otherHolder = credentialHolder("quota-other");

            IssuedCredentialFixture first = oid4vci.issueCredential(holder.username(), holder.accessToken());
            assertCredentialStatus(holder.accessToken(), first.id(), TokenStatus.VALID.name());
            assertLimit(
                    holder.accessToken(),
                    CREDENTIAL_CONFIGURATION_ID,
                    1,
                    1,
                    0,
                    IssuedCredentialStatusResponse.OVERFLOW_POLICY_REJECT);

            var rejected = oid4vci.requestIssuedCredential(holder.username(), holder.accessToken());
            assertTrue(
                    rejected.response().statusCode() >= 400,
                    "second issuance should be rejected, got HTTP "
                            + rejected.response().statusCode() + ": "
                            + rejected.response().body());

            IssuedCredentialFixture otherCredential =
                    oid4vci.issueCredential(otherHolder.username(), otherHolder.accessToken());
            assertCredentialStatus(otherHolder.accessToken(), otherCredential.id(), TokenStatus.VALID.name());

            var revokeResponse = oid4vci.revokeCredential(holder.accessToken(), first.id(), "free quota slot");
            assertEquals(200, revokeResponse.statusCode());
            assertLimit(
                    holder.accessToken(),
                    CREDENTIAL_CONFIGURATION_ID,
                    1,
                    0,
                    1,
                    IssuedCredentialStatusResponse.OVERFLOW_POLICY_REJECT);

            IssuedCredentialFixture reissued = oid4vci.issueCredential(holder.username(), holder.accessToken());
            assertCredentialStatus(holder.accessToken(), reissued.id(), TokenStatus.VALID.name());
            assertLimit(
                    holder.accessToken(),
                    CREDENTIAL_CONFIGURATION_ID,
                    1,
                    1,
                    0,
                    IssuedCredentialStatusResponse.OVERFLOW_POLICY_REJECT);
        } finally {
            setIssuanceQuota(null, null);
        }
    }

    @Test
    void issuanceRevokesOldestWhenOverflowPolicyIsRevokeOldest() throws Exception {
        setIssuanceQuota("1", IssuedCredentialStatusResponse.OVERFLOW_POLICY_REVOKE_OLDEST);
        try {
            TestUser holder = credentialHolder("quota-revoke-oldest");
            TestUser otherHolder = credentialHolder("quota-revoke-other");

            IssuedCredentialFixture first = oid4vci.issueCredential(holder.username(), holder.accessToken());
            assertCredentialStatus(holder.accessToken(), first.id(), TokenStatus.VALID.name());
            assertStatusListValue(first, TokenStatus.VALID.getCode());
            assertLimit(
                    holder.accessToken(),
                    CREDENTIAL_CONFIGURATION_ID,
                    1,
                    1,
                    0,
                    IssuedCredentialStatusResponse.OVERFLOW_POLICY_REVOKE_OLDEST);

            IssuedCredentialFixture second = oid4vci.issueCredential(holder.username(), holder.accessToken());
            assertCredentialStatus(holder.accessToken(), first.id(), TokenStatus.INVALID.name());
            assertCredentialStatus(holder.accessToken(), second.id(), TokenStatus.VALID.name());
            assertStatusListValue(first, TokenStatus.INVALID.getCode());
            assertStatusListValue(second, TokenStatus.VALID.getCode());
            assertLimit(
                    holder.accessToken(),
                    CREDENTIAL_CONFIGURATION_ID,
                    1,
                    1,
                    0,
                    IssuedCredentialStatusResponse.OVERFLOW_POLICY_REVOKE_OLDEST);

            IssuedCredentialFixture otherCredential =
                    oid4vci.issueCredential(otherHolder.username(), otherHolder.accessToken());
            assertCredentialStatus(otherHolder.accessToken(), otherCredential.id(), TokenStatus.VALID.name());
            assertStatusListValue(otherCredential, TokenStatus.VALID.getCode());
        } finally {
            setIssuanceQuota(null, null);
        }
    }

    private static void assertLimit(
            String accessToken,
            String credentialConfigurationId,
            int max,
            int activeCount,
            int remaining,
            String overflowPolicy)
            throws Exception {
        JsonNode limits = oid4vci.issuedCredentialStatuses(accessToken).path("limits");
        for (int i = 0; i < limits.size(); i++) {
            JsonNode limit = limits.get(i);
            if (credentialConfigurationId.equals(
                    limit.path("credentialConfigurationId").asText())) {
                assertEquals(max, limit.path("max").asInt());
                assertEquals(activeCount, limit.path("activeCount").asInt());
                assertEquals(remaining, limit.path("remaining").asInt());
                assertEquals(overflowPolicy, limit.path("overflowPolicy").asText());
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
    private static void setIssuanceQuota(String max, String overflowPolicy) {
        RealmRepresentation realm = realm().toRepresentation();
        putOrRemoveAttribute(realm, StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER, max);
        putOrRemoveAttribute(realm, StatusListConfig.STATUS_LIST_OVERFLOW_POLICY, overflowPolicy);
        realm().update(realm);
    }

    private static void putOrRemoveAttribute(RealmRepresentation realm, String key, String value) {
        if (value == null) {
            realm.getAttributes().remove(key);
        } else {
            realm.getAttributes().put(key, value);
        }
    }
}
