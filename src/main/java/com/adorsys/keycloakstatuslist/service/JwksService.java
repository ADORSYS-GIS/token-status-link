package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.exception.StatusListException;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.jboss.logging.Logger;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.vp.SdJwtVP;

/**
 * Service for retrieving Keycloak's internal verifying keys. Leverages Keycloak's session and key
 * management instead of external JWKS endpoints.
 */
public class JwksService {

    private static final Logger logger = Logger.getLogger(JwksService.class);

    private final KeycloakSession session;

    public JwksService(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Creates signature verifier contexts directly from Keycloak's key management. This is the
     * preferred approach as it avoids converting keys unnecessarily.
     */
    public List<SignatureVerifierContext> getSignatureVerifierContexts(
            SdJwtVP sdJwtVP, String requestId) throws StatusListException {
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
                            return signatureProvider.verifier(key);
                        } catch (VerificationException e) {
                            logger.warnf("Failed to create verifier for key %s. RequestId: %s, Error: %s",
                                    key.getKid(), requestId, e.getMessage());
                            return null;
                        }
                    })
                    .filter(Objects::nonNull)
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
            if (issuerSignedJWT != null && issuerSignedJWT.getJwsHeader() != null) {
                return issuerSignedJWT.getJwsHeader().getKeyId();
            }
        } catch (Exception e) {
            logger.debug("Could not extract signing key ID from JWT header", e);
        }
        return null;
    }
}
