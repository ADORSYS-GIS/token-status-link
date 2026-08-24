package com.adorsys.keycloakstatuslist.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.keycloak.OID4VCConstants.OPENID_CREDENTIAL;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.protocol.oid4vc.model.OID4VCAuthorizationDetail;
import org.keycloak.util.JsonSerialization;
import org.testcontainers.Testcontainers;

class KeycloakStatusListFlowIT {

    private static final String REALM = "status-list-it";
    private static final String USERNAME = "alice";
    private static final String PASSWORD = "password";
    private static final String CLIENT_ID = "openid4vc-rest-api";
    private static final String CLIENT_SECRET = "secret";
    private static final String CREDENTIAL_CONFIGURATION_ID = "IdentityCredential";

    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    private static RecordingStatusListServer statusListServer;
    private static KeycloakContainer keycloak;

    @BeforeAll
    static void startKeycloak() throws Exception {
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

        configureRealm();
        grantUserCredential();
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

    @Test
    void issuedCredentialEmbedsStatusClaimAndCanBeRevokedWithUsersBearerToken() throws Exception {
        String userAccessToken = requestUserAccessToken();
        IssuedCredential issuedCredential = issueCredential(userAccessToken);

        JsonNode statusList = issuedCredential.statusClaim().path("status_list");
        long statusIndex = statusList.path("idx").asLong(-1);
        String statusUri = statusList.path("uri").asText();
        String statusListId = statusUri.substring(statusUri.lastIndexOf('/') + 1);

        assertTrue(statusIndex >= 0, "credential status claim must contain a status_list.idx");
        assertTrue(
                statusUri.startsWith(statusListServer.externalUrl()),
                "status claim must point to the configured server");
        assertEquals(0, statusListServer.statusFor(statusListId, statusIndex).orElseThrow());

        String credentialId = findIssuedCredentialId(issuedCredential.credentialAccessToken());
        revokeIssuedCredential(userAccessToken, credentialId);

        assertEquals(1, statusListServer.statusFor(statusListId, statusIndex).orElseThrow());
    }

    private static IssuedCredential issueCredential(String userAccessToken) throws Exception {
        String credentialOfferUri = createCredentialOffer(userAccessToken);
        JsonNode credentialOffer = getJson(credentialOfferUri, bearer(userAccessToken));
        String preAuthorizedCode = credentialOffer
                .path("grants")
                .path("urn:ietf:params:oauth:grant-type:pre-authorized_code")
                .path("pre-authorized_code")
                .asText(null);
        assertNotNull(preAuthorizedCode, "credential offer must include a pre-authorized code");

        JsonNode tokenResponse = postForm(
                realmUrl("/protocol/openid-connect/token"),
                Map.of(
                        "grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                        "pre-authorized_code", preAuthorizedCode,
                        "client_id", CLIENT_ID,
                        "client_secret", CLIENT_SECRET),
                Map.of());

        String credentialAccessToken = tokenResponse.path("access_token").asText(null);
        String credentialIdentifier = tokenResponse
                .path("authorization_details")
                .path(0)
                .path("credential_identifiers")
                .path(0)
                .asText(null);
        assertNotNull(credentialAccessToken, "credential token response must contain an access token");
        assertNotNull(credentialIdentifier, "credential token response must contain a credential identifier");

        String nonce = postJson(realmUrl("/protocol/oid4vc/nonce"), "", Map.of())
                .path("c_nonce")
                .asText(null);
        assertNotNull(nonce, "nonce endpoint must return c_nonce");

        ObjectNode request = JsonSerialization.mapper.createObjectNode();
        request.put("credential_identifier", credentialIdentifier);
        request.putObject("proofs").putArray("jwt").add(createProofJwt(nonce));

        JsonNode credentialResponse =
                postJson(realmUrl("/protocol/oid4vc/credential"), request.toString(), bearer(credentialAccessToken));
        String credential = extractCredential(credentialResponse);
        assertNotNull(credential, "credential endpoint must return a credential: " + credentialResponse);

        JsonNode credentialPayload = decodeJwtPayload(credential.split("~", 2)[0]);
        JsonNode statusClaim = credentialPayload.path("status");
        assertFalse(statusClaim.isMissingNode(), "issued credential must embed status claim");

        return new IssuedCredential(credentialAccessToken, statusClaim);
    }

    private static String createCredentialOffer(String userAccessToken) throws Exception {
        URI uri = URI.create(realmUrl("/protocol/oid4vc/create-credential-offer")
                + "?credential_configuration_id="
                + urlEncode(CREDENTIAL_CONFIGURATION_ID)
                + "&target_user="
                + urlEncode(USERNAME)
                + "&pre_authorized=true");

        JsonNode response = getJson(uri.toString(), bearer(userAccessToken));
        String issuer = response.path("issuer").asText(null);
        String nonce = response.path("nonce").asText(null);
        assertNotNull(issuer, "credential offer response must include issuer");
        assertNotNull(nonce, "credential offer response must include nonce");
        return issuer.endsWith("/") ? issuer + nonce : issuer + "/" + nonce;
    }

    private static String findIssuedCredentialId(String credentialAccessToken) throws Exception {
        JsonNode tokenPayload = decodeJwtPayload(credentialAccessToken);
        for (JsonNode authorizationDetail : tokenPayload.path("authorization_details")) {
            if (!OPENID_CREDENTIAL.equals(authorizationDetail.path("type").asText())) {
                continue;
            }

            String issuedCredentialId = authorizationDetail
                    .path(OID4VCAuthorizationDetail.ISSUED_CREDENTIAL_ID)
                    .asText(null);
            if (issuedCredentialId != null && !issuedCredentialId.isBlank()) {
                return issuedCredentialId;
            }
        }

        throw new AssertionError("Credential access token must identify the issued credential");
    }

    private static void revokeIssuedCredential(String userAccessToken, String credentialId) throws Exception {
        JsonNode response = postForm(
                realmUrl("/protocol/openid-connect/revoke"),
                Map.of(
                        "mode", "issued_credential_revocation",
                        "credential_id", credentialId,
                        "reason", "integration test"),
                bearer(userAccessToken));

        assertTrue(response.path("success").asBoolean(false), "revocation endpoint must report success");
    }

    private static void configureRealm() throws Exception {
        String adminToken = requestAdminAccessToken();
        ObjectNode realm = (ObjectNode) getJson(adminUrl("/realms/" + REALM), bearer(adminToken));
        ObjectNode attributes = realm.withObject("/attributes");
        attributes.put("status-list-enabled", "true");
        attributes.put("status-list-mandatory", "true");
        attributes.put("status-list-server-url", statusListServer.externalUrl());
        attributes.put("status-list-issuance-timeout", "10000");
        attributes.put("status-list-registration-timeout", "10000");

        putJson(adminUrl("/realms/" + REALM), realm.toString(), bearer(adminToken));
    }

    private static void grantUserCredential() throws Exception {
        String adminToken = requestAdminAccessToken();
        JsonNode users = getJson(
                adminUrl("/realms/" + REALM + "/users?username=" + urlEncode(USERNAME) + "&exact=true"),
                bearer(adminToken));
        String userId = users.path(0).path("id").asText(null);
        assertNotNull(userId, "test user must exist");

        ObjectNode grant = JsonSerialization.mapper.createObjectNode();
        grant.put("credentialScopeName", CREDENTIAL_CONFIGURATION_ID);
        HttpResponse<String> response = send(HttpRequest.newBuilder()
                .uri(URI.create(adminUrl("/realms/" + REALM + "/users/" + userId + "/vc/credentials")))
                .headers(headers(bearer(adminToken), "Content-Type", "application/json"))
                .POST(HttpRequest.BodyPublishers.ofString(grant.toString()))
                .build());

        assertTrue(
                (response.statusCode() >= 200 && response.statusCode() < 300) || response.statusCode() == 409,
                "credential grant should be created or already exist, got HTTP " + response.statusCode());
    }

    private static String requestAdminAccessToken() throws Exception {
        return postForm(
                        keycloak.getAuthServerUrl() + "/realms/master/protocol/openid-connect/token",
                        Map.of(
                                "grant_type",
                                "password",
                                "client_id",
                                "admin-cli",
                                "username",
                                keycloak.getAdminUsername(),
                                "password",
                                keycloak.getAdminPassword()),
                        Map.of())
                .path("access_token")
                .asText();
    }

    private static String requestUserAccessToken() throws Exception {
        return postForm(
                        realmUrl("/protocol/openid-connect/token"),
                        Map.of(
                                "grant_type", "password",
                                "client_id", CLIENT_ID,
                                "client_secret", CLIENT_SECRET,
                                "username", USERNAME,
                                "password", PASSWORD,
                                "scope", "openid"),
                        Map.of())
                .path("access_token")
                .asText();
    }

    private static String createProofJwt(String nonce) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        KeyPair keyPair = generator.generateKeyPair();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

        ObjectNode header = JsonSerialization.mapper.createObjectNode();
        header.put("alg", "ES256");
        header.put("typ", "openid4vci-proof+jwt");
        ObjectNode jwk = header.putObject("jwk");
        jwk.put("kty", "EC");
        jwk.put("crv", "P-256");
        jwk.put("x", base64Url(unsignedCoordinate(publicKey.getW().getAffineX())));
        jwk.put("y", base64Url(unsignedCoordinate(publicKey.getW().getAffineY())));

        ObjectNode payload = JsonSerialization.mapper.createObjectNode();
        payload.put("iss", CLIENT_ID);
        payload.put("aud", realmUrl(""));
        payload.put("iat", Instant.now().getEpochSecond());
        payload.put("nonce", nonce);

        String signingInput = base64Url(header.toString().getBytes(StandardCharsets.UTF_8)) + "."
                + base64Url(payload.toString().getBytes(StandardCharsets.UTF_8));
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        return signingInput + "." + base64Url(derToJose(signature.sign(), 32));
    }

    private static byte[] derToJose(byte[] derSignature, int partLength) {
        if (derSignature.length < 8 || derSignature[0] != 0x30) {
            throw new IllegalArgumentException("Invalid DER ECDSA signature");
        }

        int offset = derSignature[1] > 0 ? 2 : 3;
        BigInteger r = readDerInteger(derSignature, offset);
        offset += 2 + derSignature[offset + 1];
        BigInteger s = readDerInteger(derSignature, offset);

        byte[] jose = new byte[partLength * 2];
        copyUnsigned(r, jose, 0, partLength);
        copyUnsigned(s, jose, partLength, partLength);
        return jose;
    }

    private static BigInteger readDerInteger(byte[] derSignature, int offset) {
        if (derSignature[offset] != 0x02) {
            throw new IllegalArgumentException("Invalid DER ECDSA integer");
        }
        int length = derSignature[offset + 1] & 0xff;
        return new BigInteger(1, java.util.Arrays.copyOfRange(derSignature, offset + 2, offset + 2 + length));
    }

    private static void copyUnsigned(BigInteger value, byte[] target, int offset, int length) {
        byte[] bytes = unsignedCoordinate(value);
        System.arraycopy(bytes, 0, target, offset + length - bytes.length, bytes.length);
    }

    private static byte[] unsignedCoordinate(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == 32) {
            return bytes;
        }

        byte[] unsigned = new byte[32];
        int copyStart = Math.max(0, bytes.length - 32);
        int copyLength = Math.min(bytes.length, 32);
        System.arraycopy(bytes, copyStart, unsigned, 32 - copyLength, copyLength);
        return unsigned;
    }

    private static JsonNode getJson(String url, Map<String, String> headers) throws Exception {
        return readSuccessfulJson(send(HttpRequest.newBuilder()
                .uri(URI.create(url))
                .headers(headers(headers))
                .GET()
                .build()));
    }

    private static JsonNode postJson(String url, String json, Map<String, String> headers) throws Exception {
        return readSuccessfulJson(send(HttpRequest.newBuilder()
                .uri(URI.create(url))
                .headers(headers(headers, "Content-Type", "application/json"))
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build()));
    }

    private static void putJson(String url, String json, Map<String, String> headers) throws Exception {
        HttpResponse<String> response = send(HttpRequest.newBuilder()
                .uri(URI.create(url))
                .headers(headers(headers, "Content-Type", "application/json"))
                .PUT(HttpRequest.BodyPublishers.ofString(json))
                .build());
        assertTrue(
                response.statusCode() >= 200 && response.statusCode() < 300,
                "PUT " + url + " failed with HTTP " + response.statusCode() + ": " + response.body());
    }

    private static JsonNode postForm(String url, Map<String, String> form, Map<String, String> headers)
            throws Exception {
        return readSuccessfulJson(send(HttpRequest.newBuilder()
                .uri(URI.create(url))
                .headers(headers(headers, "Content-Type", "application/x-www-form-urlencoded"))
                .POST(HttpRequest.BodyPublishers.ofString(formEncode(form)))
                .build()));
    }

    private static HttpResponse<String> send(HttpRequest request) throws Exception {
        return HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private static JsonNode readSuccessfulJson(HttpResponse<String> response) throws Exception {
        assertTrue(
                response.statusCode() >= 200 && response.statusCode() < 300,
                "HTTP request failed with status " + response.statusCode() + ": " + response.body());
        return response.body().isBlank()
                ? JsonSerialization.mapper.createObjectNode()
                : JsonSerialization.mapper.readTree(response.body());
    }

    private static JsonNode decodeJwtPayload(String jwt) throws IOException {
        String[] parts = jwt.split("\\.");
        assertTrue(parts.length >= 2, "expected JWT with at least header and payload");
        return JsonSerialization.mapper.readTree(Base64.getUrlDecoder().decode(parts[1]));
    }

    private static String firstTextValue(JsonNode node, String... fieldNames) {
        for (String fieldName : fieldNames) {
            JsonNode value = node.path(fieldName);
            if (value.isTextual() && !value.asText().isBlank()) {
                return value.asText();
            }
        }
        return null;
    }

    private static String extractCredential(JsonNode credentialResponse) {
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

    private static String[] headers(Map<String, String> headers, String... additionalHeaders) {
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

    private static Map<String, String> bearer(String token) {
        return Map.of("Authorization", "Bearer " + token);
    }

    private static String realmUrl(String path) {
        return keycloak.getAuthServerUrl() + "/realms/" + REALM + path;
    }

    private static String adminUrl(String path) {
        return keycloak.getAuthServerUrl() + "/admin" + path;
    }

    private static String formEncode(Map<String, String> form) {
        return form.entrySet().stream()
                .map(entry -> urlEncode(entry.getKey()) + "=" + urlEncode(entry.getValue()))
                .reduce((left, right) -> left + "&" + right)
                .orElse("");
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static File pluginJar() {
        File pluginJar =
                new File(System.getProperty("plugin.jar", "target/keycloak-token-status-plugin-1.0.0-SNAPSHOT.jar"));
        if (!pluginJar.exists()) {
            throw new IllegalStateException(
                    "Shaded plugin jar not found at " + pluginJar + ". Run './mvnw package -DskipTests' first.");
        }
        return pluginJar;
    }

    private record IssuedCredential(String credentialAccessToken, JsonNode statusClaim) {}

    private static final class RecordingStatusListServer implements AutoCloseable {

        private final HttpServer server;
        private final Map<String, Map<Long, Integer>> statuses = new ConcurrentHashMap<>();

        private RecordingStatusListServer(HttpServer server) {
            this.server = server;
        }

        static RecordingStatusListServer start() throws IOException {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            RecordingStatusListServer statusListServer = new RecordingStatusListServer(server);
            server.createContext("/", statusListServer::handle);
            server.start();
            return statusListServer;
        }

        int port() {
            return server.getAddress().getPort();
        }

        String externalUrl() {
            return "http://host.testcontainers.internal:" + port();
        }

        Optional<Integer> statusFor(String statusListId, long index) {
            return Optional.ofNullable(statuses.get(statusListId)).map(statusesByIndex -> statusesByIndex.get(index));
        }

        private void handle(HttpExchange exchange) throws IOException {
            try (exchange) {
                String method = exchange.getRequestMethod();
                String path = exchange.getRequestURI().getPath();

                if ("GET".equals(method) && "/health".equals(path)) {
                    respond(exchange, 200, "{\"status\":\"UP\"}");
                    return;
                }

                if ("POST".equals(method) && "/api/v1/credentials".equals(path)) {
                    respond(exchange, 201, "{}");
                    return;
                }

                if ("GET".equals(method) && path.startsWith("/api/v1/status-lists/")) {
                    String statusListId = path.substring(path.lastIndexOf('/') + 1);
                    respond(exchange, statuses.containsKey(statusListId) ? 200 : 404, "");
                    return;
                }

                if (("PUT".equals(method) || "PATCH".equals(method))
                        && path.startsWith("/api/v1/status-lists/")
                        && path.endsWith("/statuses")) {
                    String statusListId =
                            path.substring("/api/v1/status-lists/".length(), path.length() - "/statuses".length());
                    recordStatuses(statusListId, exchange.getRequestBody().readAllBytes());
                    respond(exchange, 204, "");
                    return;
                }

                respond(exchange, 404, "");
            }
        }

        private void recordStatuses(String statusListId, byte[] body) throws IOException {
            JsonNode payload = JsonSerialization.mapper.readTree(body);
            Map<Long, Integer> statusesByIndex =
                    statuses.computeIfAbsent(statusListId, ignored -> new ConcurrentHashMap<>());
            for (JsonNode status : payload.path("statuses")) {
                statusesByIndex.put(
                        status.path("index").asLong(), status.path("status").asInt());
            }
        }

        private void respond(HttpExchange exchange, int statusCode, String body) throws IOException {
            byte[] response = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            if (statusCode == 204) {
                exchange.sendResponseHeaders(statusCode, -1);
                return;
            }
            exchange.sendResponseHeaders(statusCode, response.length);
            exchange.getResponseBody().write(response);
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }
}
