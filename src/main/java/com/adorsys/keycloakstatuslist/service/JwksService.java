package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import org.jboss.logging.Logger;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.common.VerificationException;

import java.security.PublicKey;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Service for retrieving Keycloak's internal verifying keys.
 * Leverages Keycloak's session and key management instead of external JWKS endpoints.
 */
public class JwksService {

    private static final Logger logger = Logger.getLogger(JwksService.class);

    private final KeycloakSession session;

    public JwksService(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Retrieves all public keys from Keycloak's internal key management.
     * This is more efficient than making HTTP requests to JWKS endpoints.
     */
    public List<PublicKey> getAllIssuerPublicKeys(SdJwtVP sdJwtVP, String issuer, String requestId) throws StatusListException {
        try {
            RealmModel realm = session.getContext().getRealm();
            var keyManager = session.keys();

            Stream<KeyWrapper> keyStream = keyManager.getKeysStream(realm)
                    .filter(key -> KeyUse.SIG.equals(key.getUse()));

            // If we have a specific key ID from the JWT header, filter by it
            String signingKeyId = getSigningKeyId(sdJwtVP);
            if (signingKeyId != null) {
                keyStream = keyStream.filter(key -> signingKeyId.equals(key.getKid()));
                logger.debugf("Filtering keys by kid: %s. RequestId: %s", signingKeyId, requestId);
            }

            List<PublicKey> publicKeys = keyStream
                    .map(key -> {
                        try {
                            java.security.Key keyValue = key.getPublicKey();
                            if (keyValue instanceof PublicKey) {
                                PublicKey publicKey = (PublicKey) keyValue;
                                logger.debugf("Retrieved public key: %s, algorithm: %s, kid: %s. RequestId: %s",
                                        publicKey.getAlgorithm(), key.getAlgorithm(), key.getKid(), requestId);
                                return publicKey;
                            } else {
                                logger.warnf("Key %s is not a PublicKey (type: %s). RequestId: %s",
                                        key.getKid(), keyValue != null ? keyValue.getClass().getSimpleName() : "null", requestId);
                                return null;
                            }
                        } catch (Exception e) {
                            logger.warnf("Failed to retrieve public key from key %s. RequestId: %s, Error: %s",
                                    key.getKid(), requestId, e.getMessage());
                            return null;
                        }
                    })
                    .filter(publicKey -> publicKey != null)
                    .collect(Collectors.toList());

            logger.infof("Successfully retrieved %d public keys from Keycloak session. RequestId: %s",
                    publicKeys.size(), requestId);
            return publicKeys;

        } catch (Exception e) {
            logger.errorf("Failed to retrieve public keys from Keycloak session. RequestId: %s, Error: %s",
                    requestId, e.getMessage());
            throw new StatusListException("Failed to retrieve public keys from Keycloak session: " + e.getMessage(), e);
        }
    }

    /**
     * Creates signature verifier contexts directly from Keycloak's key management.
     * This is the preferred approach as it avoids converting keys unnecessarily.
     */
    public List<SignatureVerifierContext> getSignatureVerifierContexts(SdJwtVP sdJwtVP, String issuer, String requestId) throws StatusListException {
        try {
            RealmModel realm = session.getContext().getRealm();
            var keyManager = session.keys();

            Stream<KeyWrapper> keyStream = keyManager.getKeysStream(realm)
                    .filter(key -> KeyUse.SIG.equals(key.getUse()));

            // If we have a specific key ID from the JWT header, filter by it
            String signingKeyId = getSigningKeyId(sdJwtVP);
            if (signingKeyId != null) {
                keyStream = keyStream.filter(key -> signingKeyId.equals(key.getKid()));
                logger.debugf("Filtering keys by kid: %s. RequestId: %s", signingKeyId, requestId);
            }

            List<SignatureVerifierContext> verifiers = keyStream
                    .map(key -> {
                        try {
                            SignatureProvider signatureProvider = session
                                    .getProvider(SignatureProvider.class, key.getAlgorithmOrDefault());
                            SignatureVerifierContext verifier = signatureProvider.verifier(key);
                            logger.debugf("Created verifier for key: %s, algorithm: %s. RequestId: %s",
                                    key.getKid(), key.getAlgorithm(), requestId);
                            return verifier;
                        } catch (VerificationException e) {
                            logger.warnf("Failed to create verifier for key %s. RequestId: %s, Error: %s",
                                    key.getKid(), requestId, e.getMessage());
                            return null;
                        }
                    })
                    .filter(verifier -> verifier != null)
                    .collect(Collectors.toList());

            logger.infof("Successfully created %d signature verifier contexts. RequestId: %s",
                    verifiers.size(), requestId);
            return verifiers;

        } catch (Exception e) {
            logger.errorf("Failed to create signature verifier contexts. RequestId: %s, Error: %s",
                    requestId, e.getMessage());
            throw new StatusListException("Failed to create signature verifier contexts: " + e.getMessage(), e);
        }
    }

    /**
     * Extracts the signing key ID from the JWT header if available.
     */
    private String getSigningKeyId(SdJwtVP sdJwtVP) {
        try {
            IssuerSignedJWT issuerSignedJWT = sdJwtVP.getIssuerSignedJWT();
            if (issuerSignedJWT != null && issuerSignedJWT.getHeader() != null) {
                return issuerSignedJWT.getHeader().getKeyId();
            }
        } catch (Exception e) {
            logger.debug("Could not extract signing key ID from JWT header", e);
        }
        return null;
    }
} 
