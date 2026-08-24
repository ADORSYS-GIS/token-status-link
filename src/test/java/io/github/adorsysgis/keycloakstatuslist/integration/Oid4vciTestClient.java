package io.github.adorsysgis.keycloakstatuslist.integration;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.keycloak.OID4VCConstants.OPENID_CREDENTIAL;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.protocol.oid4vc.model.CredentialOfferURI;
import org.keycloak.protocol.oid4vc.model.CredentialRequest;
import org.keycloak.protocol.oid4vc.model.CredentialsOffer;
import org.keycloak.protocol.oid4vc.model.OID4VCAuthorizationDetail;
import org.keycloak.protocol.oid4vc.model.PreAuthorizedCodeGrant;
import org.keycloak.protocol.oid4vc.model.ProofType;
import org.keycloak.protocol.oid4vc.model.Proofs;
import org.keycloak.util.JsonSerialization;

final class Oid4vciTestClient {

    private final KeycloakContainer keycloak;
    private final String realm;
    private final String clientId;
    private final String clientSecret;
    private final String credentialConfigurationId;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    Oid4vciTestClient(
            KeycloakContainer keycloak,
            String realm,
            String clientId,
            String clientSecret,
            String credentialConfigurationId) {
        this.keycloak = keycloak;
        this.realm = realm;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.credentialConfigurationId = credentialConfigurationId;
    }

    String userAccessToken(String username, String password) throws IOException, InterruptedException {
        return postForm(
                        tokenEndpoint(),
                        Map.of(
                                OAuth2Constants.GRANT_TYPE,
                                OAuth2Constants.PASSWORD,
                                OAuth2Constants.CLIENT_ID,
                                clientId,
                                OAuth2Constants.CLIENT_SECRET,
                                clientSecret,
                                OAuth2Constants.USERNAME,
                                username,
                                OAuth2Constants.PASSWORD,
                                password,
                                OAuth2Constants.SCOPE,
                                "openid"))
                .path(OAuth2Constants.ACCESS_TOKEN)
                .asText();
    }

    int grantCredential(String userId) throws IOException, InterruptedException {
        ObjectNode grant = JsonSerialization.mapper.createObjectNode();
        grant.put("credentialScopeName", credentialConfigurationId);

        return send(HttpRequest.newBuilder()
                        .uri(URI.create(adminRealmEndpoint("/users/" + userId + "/vc/credentials")))
                        .headers(headers(
                                bearer(keycloak.getKeycloakAdminClient()
                                        .tokenManager()
                                        .getAccessTokenString()),
                                "Content-Type",
                                "application/json"))
                        .POST(HttpRequest.BodyPublishers.ofString(grant.toString()))
                        .build())
                .statusCode();
    }

    IssuedCredentialFixture issueCredential(String username, String userAccessToken) throws Exception {
        CredentialsOffer credentialOffer = fetchCredentialOffer(username, userAccessToken);
        String preAuthorizedCode = credentialOffer.getPreAuthorizedCode();
        assertNotNull(preAuthorizedCode, "credential offer must include a pre-authorized code");

        JsonNode tokenResponse = postForm(
                tokenEndpoint(),
                Map.of(
                        OAuth2Constants.GRANT_TYPE,
                        PreAuthorizedCodeGrant.PRE_AUTH_GRANT_TYPE,
                        PreAuthorizedCodeGrant.CODE_REQUEST_PARAM,
                        preAuthorizedCode,
                        OAuth2Constants.CLIENT_ID,
                        clientId,
                        OAuth2Constants.CLIENT_SECRET,
                        clientSecret));
        String credentialAccessToken =
                tokenResponse.path(OAuth2Constants.ACCESS_TOKEN).asText(null);
        String credentialIdentifier = tokenResponse
                .path("authorization_details")
                .path(0)
                .path("credential_identifiers")
                .path(0)
                .asText(null);
        assertNotNull(credentialAccessToken, "credential token response must contain an access token");
        assertNotNull(credentialIdentifier, "credential token response must contain a credential identifier");

        CredentialRequest request = new CredentialRequest()
                .setCredentialIdentifier(credentialIdentifier)
                .setProofs(Proofs.create(ProofType.JWT, walletProofJwt(credentialAccessToken)));

        JsonNode credentialResponse = postJson(
                realmEndpoint("/protocol/oid4vc/credential"),
                JsonSerialization.mapper.writeValueAsString(request),
                bearer(credentialAccessToken));
        String credential = extractCredential(credentialResponse);
        assertNotNull(credential, "credential endpoint must return a credential: " + credentialResponse);

        JsonNode credentialPayload = decodeJwtPayload(credential.split("~", 2)[0]);
        JsonNode statusClaim = credentialPayload.path("status");
        assertTrue(!statusClaim.isMissingNode(), "issued credential must embed status claim");

        return new IssuedCredentialFixture(
                issuedCredentialId(credentialAccessToken), credential, statusClaim, credentialAccessToken);
    }

    HttpResponse<String> revokeCredential(String bearerToken, String credentialId, String reason)
            throws IOException, InterruptedException {
        Map<String, String> headers = bearerToken == null ? Map.of() : bearer(bearerToken);
        return postFormResponse(
                realmEndpoint("/protocol/openid-connect/revoke"),
                Map.of(
                        "mode", "issued_credential_revocation",
                        "credential_id", credentialId,
                        "reason", reason),
                headers);
    }

    JsonNode issuedCredentialStatuses(String bearerToken) throws IOException, InterruptedException {
        return readJson(send(HttpRequest.newBuilder()
                .uri(URI.create(realmEndpoint("/protocol/openid-connect/issued-credential-status")))
                .headers(headers(bearer(bearerToken)))
                .GET()
                .build()));
    }

    JsonNode readJson(HttpResponse<String> response) throws IOException {
        return response.body().isBlank()
                ? JsonSerialization.mapper.createObjectNode()
                : JsonSerialization.mapper.readTree(response.body());
    }

    private CredentialsOffer fetchCredentialOffer(String username, String accessToken)
            throws IOException, InterruptedException {
        CredentialOfferURI offerUri = getJson(
                KeycloakUriBuilder.fromUri(realmEndpoint("/protocol/oid4vc/create-credential-offer"))
                        .queryParam("credential_configuration_id", credentialConfigurationId)
                        .queryParam("target_user", username)
                        .queryParam("pre_authorized", "true")
                        .build()
                        .toString(),
                bearer(accessToken),
                CredentialOfferURI.class);

        assertNotNull(offerUri.getIssuer(), "credential offer URI response must include issuer");
        assertNotNull(offerUri.getNonce(), "credential offer URI response must include nonce");
        return getJson(offerUri.getCredentialOfferUri(), bearer(accessToken), CredentialsOffer.class);
    }

    private String walletProofJwt(String credentialAccessToken) throws Exception {
        String nonce = postJson(realmEndpoint("/protocol/oid4vc/nonce"), "", bearer(credentialAccessToken))
                .path("c_nonce")
                .asText(null);
        assertNotNull(nonce, "nonce endpoint must return c_nonce");
        return WalletProofFactory.jwt(clientId, realmEndpoint(""), nonce);
    }

    private String issuedCredentialId(String credentialAccessToken) throws IOException {
        JsonNode tokenPayload = decodeJwtPayload(credentialAccessToken);
        for (JsonNode authorizationDetail : tokenPayload.path("authorization_details")) {
            if (OPENID_CREDENTIAL.equals(authorizationDetail.path("type").asText())) {
                String issuedCredentialId = authorizationDetail
                        .path(OID4VCAuthorizationDetail.ISSUED_CREDENTIAL_ID)
                        .asText(null);
                if (issuedCredentialId != null && !issuedCredentialId.isBlank()) {
                    return issuedCredentialId;
                }
            }
        }
        throw new AssertionError("Credential access token must identify the issued credential");
    }

    private JsonNode getJson(String url, Map<String, String> headers) throws IOException, InterruptedException {
        return readSuccessfulJson(send(HttpRequest.newBuilder()
                .uri(URI.create(url))
                .headers(headers(headers))
                .GET()
                .build()));
    }

    private <T> T getJson(String url, Map<String, String> headers, Class<T> type)
            throws IOException, InterruptedException {
        return JsonSerialization.mapper.treeToValue(getJson(url, headers), type);
    }

    private JsonNode postJson(String url, String json, Map<String, String> headers)
            throws IOException, InterruptedException {
        return readSuccessfulJson(send(HttpRequest.newBuilder()
                .uri(URI.create(url))
                .headers(headers(headers, "Content-Type", "application/json"))
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build()));
    }

    private JsonNode postForm(String url, Map<String, String> form) throws IOException, InterruptedException {
        return readSuccessfulJson(postFormResponse(url, form, Map.of()));
    }

    private HttpResponse<String> postFormResponse(String url, Map<String, String> form, Map<String, String> headers)
            throws IOException, InterruptedException {
        return send(HttpRequest.newBuilder()
                .uri(URI.create(url))
                .headers(headers(headers, "Content-Type", "application/x-www-form-urlencoded"))
                .POST(HttpRequest.BodyPublishers.ofString(formEncode(form)))
                .build());
    }

    private HttpResponse<String> send(HttpRequest request) throws IOException, InterruptedException {
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private JsonNode readSuccessfulJson(HttpResponse<String> response) throws IOException {
        assertTrue(
                response.statusCode() >= 200 && response.statusCode() < 300,
                "HTTP request failed with status " + response.statusCode() + ": " + response.body());
        return readJson(response);
    }

    private JsonNode decodeJwtPayload(String jwt) throws IOException {
        String[] parts = jwt.split("\\.");
        assertTrue(parts.length >= 2, "expected JWT with at least header and payload");
        return JsonSerialization.mapper.readTree(Base64.getUrlDecoder().decode(parts[1]));
    }

    private String extractCredential(JsonNode credentialResponse) {
        String credential = credentialResponse.path("credential").asText(null);
        if (credential != null) {
            return credential;
        }

        JsonNode credentials = credentialResponse.path("credentials");
        if (credentials.isArray() && !credentials.isEmpty()) {
            return firstTextValue(credentials.get(0), "credential");
        }

        return null;
    }

    private String firstTextValue(JsonNode node, String... fieldNames) {
        for (String fieldName : fieldNames) {
            JsonNode value = node.path(fieldName);
            if (value.isTextual() && !value.asText().isBlank()) {
                return value.asText();
            }
        }
        return null;
    }

    private String[] headers(Map<String, String> headers, String... additionalHeaders) {
        List<String> flattened = new ArrayList<>();
        headers.forEach((name, value) -> {
            flattened.add(name);
            flattened.add(value);
        });
        for (String additionalHeader : additionalHeaders) {
            flattened.add(additionalHeader);
        }
        return flattened.toArray(String[]::new);
    }

    private Map<String, String> bearer(String token) {
        return Map.of("Authorization", "Bearer " + token);
    }

    private String tokenEndpoint() {
        return realmEndpoint("/protocol/openid-connect/token");
    }

    private String realmEndpoint(String path) {
        return KeycloakUriBuilder.fromUri(keycloak.getAuthServerUrl())
                .path("/realms/{realm}")
                .path(path)
                .build(realm)
                .toString();
    }

    private String adminRealmEndpoint(String path) {
        return KeycloakUriBuilder.fromUri(keycloak.getAuthServerUrl())
                .path("/admin/realms/{realm}")
                .path(path)
                .build(realm)
                .toString();
    }

    private String formEncode(Map<String, String> form) {
        return form.entrySet().stream()
                .map(entry -> urlEncode(entry.getKey()) + "=" + urlEncode(entry.getValue()))
                .reduce((left, right) -> left + "&" + right)
                .orElse("");
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
