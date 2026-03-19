package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Service for retrieving active keys and generating JWT tokens.
 */
public class CryptoIdentityService {

    private static final Logger logger = Logger.getLogger(CryptoIdentityService.class);

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

    /**
     * Gets the realm's active signing key and converts it to JWK. Supports RSA and EC. accessible by
     * CredentialRevocationResourceProviderFactory.
     */
    public static KeyData getRealmKeyData(KeycloakSession session, RealmModel realm)
            throws StatusListException {
        try {
            KeyManager keyManager = session.keys();

            String algorithm = Optional.ofNullable(realm.getDefaultSignatureAlgorithm()).orElse(Algorithm.ES256);

            KeyWrapper activeKey = keyManager.getActiveKey(realm, KeyUse.SIG, algorithm);

            if (activeKey == null || activeKey.getPublicKey() == null) {
                activeKey = keyManager.getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);
                algorithm = Algorithm.RS256;
            }

            if (activeKey == null) {
                throw new StatusListException("No active signing key found for realm: " + realm.getName());
            }

            if (activeKey.getPublicKey() == null) {
                throw new StatusListException("Active key has no public key for realm: " + realm.getName());
            }

            PublicKey pubKey = (PublicKey) activeKey.getPublicKey();
            String finalAlg = activeKey.getAlgorithm() != null ? activeKey.getAlgorithm() : algorithm;

            JWKBuilder builder = JWKBuilder.create()
                    .kid(activeKey.getKid())
                    .algorithm(finalAlg);

            JWK jwk;
            if (pubKey instanceof RSAPublicKey) {
                jwk = builder.rsa(pubKey);
            } else if (pubKey instanceof ECPublicKey) {
                jwk = builder.ec(pubKey);
            } else {
                throw new StatusListException(
                        "Unsupported key type for realm "
                                + realm.getName()
                                + ": "
                                + pubKey.getClass().getName());
            }

            logger.debugf("Retrieved JWK and algorithm for realm %s: %s", realm.getName(), finalAlg);
            return new KeyData(jwk, finalAlg);

        } catch (StatusListException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Error retrieving realm public key and algorithm", e);
            throw new StatusListException("Failed to retrieve realm public key: " + e.getMessage(), e);
        }
    }

    public record KeyData(JWK jwk, String algorithm) {
    }
}
