package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;

import java.util.HashMap;
import java.util.Map;

import org.keycloak.common.util.Time;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Service for retrieving active keys and generating JWT tokens.
 */
public class CryptoIdentityService {

    private static final int DEFAULT_AUTH_TOKEN_LIFETIME = 600; // 10 minutes in seconds

    private final KeycloakSession session;

    public CryptoIdentityService(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Retrieve the active signing key for the given realm.
     */
    public KeyWrapper getActiveKey(RealmModel realm) {
        KeyWrapper activeKey = session.keys().getActiveKey(realm, KeyUse.SIG, "RS256");
        if (activeKey == null) {
            throw new IllegalStateException("No active signing key found for realm: " + realm.getName());
        }

        return activeKey;
    }

    /**
     * Generate a JWT bearer token for authenticating with the status list server.
     */
    public String getJwtToken(StatusListConfig realmConfig) {
        KeyWrapper keyWrapper = getActiveKey(realmConfig.getRealm());

        // Payload
        Map<String, Object> payload = new HashMap<>();
        payload.put("iss", realmConfig.getTokenIssuerId());
        payload.put("iat", Time.currentTime());
        payload.put("exp", Time.currentTime() + DEFAULT_AUTH_TOKEN_LIFETIME);

        // Build and sign JWT
        return new JWSBuilder()
                .jsonContent(payload)
                .sign(new AsymmetricSignatureSignerContext(keyWrapper));
    }
}
