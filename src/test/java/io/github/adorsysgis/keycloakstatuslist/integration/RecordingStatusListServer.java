package io.github.adorsysgis.keycloakstatuslist.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.keycloak.util.JsonSerialization;

final class RecordingStatusListServer implements AutoCloseable {

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
                if (recordStatuses(statusListId, exchange.getRequestBody().readAllBytes())) {
                    respond(exchange, 204, "");
                } else {
                    respond(exchange, 400, "{\"error\":\"invalid_status_payload\"}");
                }
                return;
            }

            respond(exchange, 404, "");
        }
    }

    private boolean recordStatuses(String statusListId, byte[] body) throws IOException {
        JsonNode payload = JsonSerialization.mapper.readTree(body);
        JsonNode statusUpdates = payload.path("statuses");
        if (!statusUpdates.isArray()) {
            return false;
        }

        Map<Long, Integer> validatedStatuses = new HashMap<>();
        for (JsonNode status : statusUpdates) {
            JsonNode index = status.get("index");
            JsonNode statusValue = status.get("status");
            if (index == null || !index.canConvertToLong() || statusValue == null || !statusValue.canConvertToInt()) {
                return false;
            }
            validatedStatuses.put(index.asLong(), statusValue.asInt());
        }

        statuses.computeIfAbsent(statusListId, ignored -> new ConcurrentHashMap<>())
                .putAll(validatedStatuses);
        return true;
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
