package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.service.validation.SdJwtVPValidationService;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sdjwt.IssuerSignedJwtVerificationOpts;
import org.keycloak.sdjwt.vp.KeyBindingJwtVerificationOpts;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.services.Urls;

/**
 * Default implementation of SdJwtVPValidationService. Handles token parsing, signature verification,
 * and credential extraction using Keycloak's internal key management.
 */
public class DefaultSdJwtVPValidationService implements SdJwtVPValidationService {

    private static final Logger logger = Logger.getLogger(SdJwtVPValidationService.class);

    private final KeycloakSession session;
    private final JwksService jwksService;

    public DefaultSdJwtVPValidationService(KeycloakSession session, JwksService jwksService) {
        this.session = session;
        this.jwksService = jwksService;
    }

    public DefaultSdJwtVPValidationService(KeycloakSession session) {
        this(session, new JwksService(session));
    }

    @Override
    public SdJwtVP parseAndValidateSdJwtVP(String sdJwtVpString, String requestId) throws StatusListException {

        logger.debugf("Parsing SD-JWT VP token using Keycloak's built-in SdJwtVP class. RequestId: %s", requestId);

        try {
            if (sdJwtVpString == null || sdJwtVpString.trim().isEmpty()) {
                throw new StatusListException("SD-JWT VP token is empty or null");
            }

            SdJwtVP sdJwtVP = SdJwtVP.of(sdJwtVpString);

            logger.infof("SD-JWT VP parsed successfully. RequestId: %s", requestId);

            return sdJwtVP;

        } catch (IllegalArgumentException e) {

            logger.errorf("Invalid SD-JWT VP token format. RequestId: %s, Error: %s", requestId, e.getMessage());
            throw new StatusListException("Invalid SD-JWT VP token format: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.errorf("Failed to parse SD-JWT VP token. RequestId: %s, Error: %s", requestId, e.getMessage());
            throw new StatusListException("Failed to parse SD-JWT VP token: " + e.getMessage(), e);
        }
    }

    /**
     * Verifies the SD-JWT VP token's issuer signature using Keycloak's internal key management. This
     * ensures the token was properly issued by the claimed issuer.
     */
    public void verifySdJwtVP(SdJwtVP sdJwtVP, String requestId, String expectedNonce) throws StatusListException {
        try {

            String issuer = extractIssuerFromToken(sdJwtVP);
            if (issuer == null || issuer.trim().isEmpty()) {
                logger.errorf("No issuer found in SD-JWT VP token. RequestId: %s", requestId);
                throw new StatusListException("Token missing required issuer information for verification");
            }

            // Use the new approach with internal key management
            List<SignatureVerifierContext> verifyingKeys = jwksService.getSignatureVerifierContexts(sdJwtVP, requestId);

            if (verifyingKeys.isEmpty()) {
                logger.errorf("No valid issuer signature verifier contexts created. RequestId: %s", requestId);
                throw new StatusListException("No public keys available for issuer: " + issuer);
            }

            sdJwtVP.verify(
                    verifyingKeys,
                    getIssuerSignedJwtVerificationOpts(),
                    getKeyBindingJwtVerificationOpts(requestId, getRevocationEndpointUrl(), expectedNonce));

            logger.infof(
                    "SD-JWT VP signature verification completed successfully with nonce validation. RequestId: %s, Nonce: %s",
                    requestId, expectedNonce);

        } catch (VerificationException e) {
            logger.errorf(
                    "SD-JWT VP signature verification failed - REJECTING REQUEST. RequestId: %s, Error: %s",
                    requestId, e.getMessage());
            throw new StatusListException("Invalid SD-JWT VP signature: " + e.getMessage(), e, 401);

        } catch (Exception e) {
            logger.errorf(
                    "SD-JWT VP verification failed - REJECTING REQUEST. RequestId: %s, Error: %s",
                    requestId, e.getMessage());
            throw new StatusListException("SD-JWT VP verification failed: " + e.getMessage(), e, 401);
        }
    }

    /**
     * Extracts the issuer from the SD-JWT VP token.
     */
    public String extractIssuerFromToken(SdJwtVP sdJwtVP) {
        try {
            return extractPayloadField(sdJwtVP, "iss");
        } catch (Exception e) {
            logger.warn("Failed to extract issuer from SD-JWT VP token", e);
            return null;
        }
    }

    /**
     * Extracts the holder's signing key from the token's cnf.jwk field. This is the key that the
     * credential holder used to sign the VP token.
     */
    public String extractNonceFromKeyBindingJWT(SdJwtVP sdJwtVP) {
        try {
            var kbOpt = sdJwtVP.getKeyBindingJWT();
            if (kbOpt.isEmpty()) {
                logger.debug("No Key Binding JWT present in SD-JWT VP");
                return null;
            }

            var payload = kbOpt.get().getPayload();
            if (payload != null) {
                JsonNode nonceNode = payload.get("nonce");
                if (nonceNode != null && nonceNode.isTextual()) {
                    return nonceNode.asText();
                }
            }

            logger.debug("Nonce not found in Key Binding JWT payload");
            return null;

        } catch (Exception e) {
            logger.warn("Failed to extract nonce from Key Binding JWT", e);
            return null;
        }
    }

    /**
     * Creates issuer signed JWT verification options with appropriate security settings. These
     * options control how the issuer signature is validated.
     */
    private IssuerSignedJwtVerificationOpts getIssuerSignedJwtVerificationOpts() {
        return IssuerSignedJwtVerificationOpts.builder()
                .withIatCheck(Integer.MAX_VALUE, true)
                .withNbfCheck(true)
                .withExpCheck(true)
                .build();
    }

    /**
     *
     * Creates key binding JWT verification options that enforce presenter verification. This is
     * critical for ensuring the presenter is actually the credential holder.
     */
    private KeyBindingJwtVerificationOpts getKeyBindingJwtVerificationOpts(
            String requestId, String expectedAudience, String expectedNonce) throws StatusListException {
        try {
            // Build verification options with SERVER-GENERATED nonce
            // The Keycloak library will verify that the client's Key Binding JWT contains this exact nonce
            return KeyBindingJwtVerificationOpts.builder()
                    .withKeyBindingRequired(true)
                    .withIatCheck(300) // 5 minutes max age
                    .withNonceCheck(expectedNonce)
                    .withAudCheck(expectedAudience)
                    .withExpCheck(true)
                    .withNbfCheck(true)
                    .build();
        } catch (IllegalArgumentException e) {
            logger.errorf(
                    "Failed to build Key Binding verification options due to invalid arguments. RequestId: %s, Error: %s",
                    requestId, e.getMessage());
            throw new StatusListException("Malformed VP: " + e.getMessage(), e, 400);
        } catch (Exception e) {
            logger.errorf(
                    "Unexpected error building Key Binding verification options. RequestId: %s, Error: %s",
                    requestId, e.getMessage());
            throw new StatusListException("Failed to build Key Binding verification options: " + e.getMessage(), e);
        }
    }

    /**
     * Helper method to extract a field from the JWT payload.
     */
    private String extractPayloadField(SdJwtVP sdJwtVP, String fieldName) {
        try {
            var jwt = sdJwtVP.getIssuerSignedJWT();
            var payload = jwt.getPayload();
            if (payload != null) {
                JsonNode fieldNode = payload.get(fieldName);
                return fieldNode != null ? fieldNode.asText() : null;
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private String getRevocationEndpointUrl() {
        RealmModel realm = session.getContext().getRealm();
        return Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName())
                + "/protocol/openid-connect/revoke";
    }
}
