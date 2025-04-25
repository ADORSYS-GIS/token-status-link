package com.adorsys.demo;

import com.adorsys.keycloakstatuslist.client.StatusListClient;

public class LocalPublisher {
    public static void main(String[] args) {
        String serverUrl = "http://0.0.0.0:8000/";
        String authToken = "test-token";
        StatusListClient client = new StatusListClient(serverUrl, authToken);

        // fake a token status update
        client.publishTokenStatus("local-token-123", "LOGIN");
        System.out.println("✔ published to " + serverUrl);
    }
} 