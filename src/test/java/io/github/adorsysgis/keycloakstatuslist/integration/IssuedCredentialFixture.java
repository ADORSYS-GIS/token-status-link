package io.github.adorsysgis.keycloakstatuslist.integration;

import com.fasterxml.jackson.databind.JsonNode;
import java.net.URI;

record IssuedCredentialFixture(String id, String credential, JsonNode statusClaim, String credentialAccessToken) {

    long statusIndex() {
        return statusClaim.path("status_list").path("idx").asLong(-1);
    }

    String statusUri() {
        return statusClaim.path("status_list").path("uri").asText();
    }

    String statusListId() {
        String uri = statusUri();
        URI parsedUri;
        try {
            parsedUri = URI.create(uri);
        } catch (IllegalArgumentException e) {
            throw new AssertionError("Status URI must be a valid URI: " + uri, e);
        }

        String path = parsedUri.getPath();
        if (path == null || path.isBlank() || path.endsWith("/")) {
            throw new AssertionError("Status URI must include a status list id in its path: " + uri);
        }

        return path.substring(path.lastIndexOf('/') + 1);
    }
}
