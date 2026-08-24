package com.adorsys.keycloakstatuslist.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.adorsys.keycloakstatuslist.model.TokenStatus;
import org.junit.jupiter.api.Test;

class KeycloakStatusListFlowIT extends BaseKeycloakIntegrationTest {

    @Test
    void issuedCredentialEmbedsStatusClaim() throws Exception {
        String aliceToken = oid4vci.userAccessToken(ALICE, PASSWORD);

        IssuedCredentialFixture credential = oid4vci.issueCredential(ALICE, aliceToken);

        assertTrue(credential.statusIndex() >= 0, "credential status claim must contain status_list.idx");
        assertTrue(
                credential.statusUri().startsWith(statusListServer.externalUrl()),
                "status claim must point to the configured status list server");
        assertStatusListValue(credential, TokenStatus.VALID.getCode());
        assertCredentialStatus(aliceToken, credential.id(), TokenStatus.VALID.name());
    }

    @Test
    void userCanRevokeIssuedCredentialWithBearerToken() throws Exception {
        String aliceToken = oid4vci.userAccessToken(ALICE, PASSWORD);
        IssuedCredentialFixture credential = oid4vci.issueCredential(ALICE, aliceToken);

        var response = oid4vci.revokeCredential(aliceToken, credential.id(), "integration test");

        assertEquals(200, response.statusCode());
        assertTrue(oid4vci.readJson(response).path("success").asBoolean(false));
        assertStatusListValue(credential, TokenStatus.INVALID.getCode());
        assertCredentialStatus(aliceToken, credential.id(), TokenStatus.INVALID.name());
    }

    @Test
    void userCannotRevokeAnotherUsersCredential() throws Exception {
        String aliceToken = oid4vci.userAccessToken(ALICE, PASSWORD);
        String bobToken = oid4vci.userAccessToken(BOB, PASSWORD);
        IssuedCredentialFixture aliceCredential = oid4vci.issueCredential(ALICE, aliceToken);

        var response = oid4vci.revokeCredential(bobToken, aliceCredential.id(), "not mine");

        assertEquals(404, response.statusCode());
        assertFalse(oid4vci.readJson(response).path("success").asBoolean(true));
        assertStatusListValue(aliceCredential, TokenStatus.VALID.getCode());
        assertCredentialStatus(aliceToken, aliceCredential.id(), TokenStatus.VALID.name());
    }

    @Test
    void revocationRequiresBearerToken() throws Exception {
        String aliceToken = oid4vci.userAccessToken(ALICE, PASSWORD);
        IssuedCredentialFixture credential = oid4vci.issueCredential(ALICE, aliceToken);

        var response = oid4vci.revokeCredential(null, credential.id(), "missing token");

        assertEquals(401, response.statusCode());
        assertFalse(oid4vci.readJson(response).path("success").asBoolean(true));
        assertStatusListValue(credential, TokenStatus.VALID.getCode());
    }
}
