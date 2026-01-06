package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import org.jboss.logging.Logger;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.KeyManager;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Optional;

public class RevocationRecordService {

    private static final Logger logger = Logger.getLogger(RevocationRecordService.class);

    private final KeycloakSession session;

    public RevocationRecordService(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Gets the realm's active signing key and converts it to JWK.
     * Supports RSA and EC.
     * accessible by CredentialRevocationResourceProviderFactory.
     */
    public static KeyData getRealmKeyData(KeycloakSession session, RealmModel realm) throws StatusListException {
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
                throw new StatusListException("Unsupported key type for realm " + realm.getName() + ": " + pubKey.getClass().getName());
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

    public TokenStatusRecord createRevocationRecord(CredentialRevocationRequest request, String requestId)
            throws StatusListException {

        logger.infof("Creating revocation record. RequestId: %s, CredentialId: %s",
                requestId, request.getCredentialId());

        try {
            RealmModel realm = session.getContext().getRealm();
            validateRevocationReason(request.getRevocationReason());

            KeyData keyData = getRealmKeyData(session, realm);

            TokenStatusRecord record = new TokenStatusRecord();
            record.setCredentialId(request.getCredentialId());
            record.setIssuer(realm.getName());
            record.setIssuerId(realm.getName());

            record.setPublicKey(keyData.jwk());
            record.setStatus(TokenStatus.REVOKED);
            record.setCredentialType("oauth2");
            record.setRevokedAt(Instant.now());
            record.setStatusReason(request.getRevocationReason() != null && !request.getRevocationReason().trim().isEmpty() ?
                    request.getRevocationReason() : "Credential revoked");

            return record;

        } catch (Exception e) {
            logger.errorf("Failed to create revocation record. RequestId: %s, Error: %s",
                    requestId, e.getMessage());
            throw new StatusListException("Failed to create revocation record: " + e.getMessage(), e);
        }
    }

    public void validateRevocationReason(String reason) throws StatusListException {
        if (reason != null && reason.length() > 255) {
            throw new StatusListException("Revocation reason exceeds maximum length of 255 characters");
        }
    }

    public record KeyData(JWK jwk, String algorithm) {
    }
}