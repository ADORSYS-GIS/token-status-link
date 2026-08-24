package io.github.adorsysgis.keycloakstatuslist.integration;

import com.fasterxml.jackson.databind.JsonNode;

record IssuedCredentialFixture(String id, String credential, JsonNode statusClaim, String credentialAccessToken) {

    long statusIndex() {
        return statusClaim.path("status_list").path("idx").asLong(-1);
    }

    String statusUri() {
        return statusClaim.path("status_list").path("uri").asText();
    }

    String statusListId() {
        String uri = statusUri();
        return uri.substring(uri.lastIndexOf('/') + 1);
    }
}
