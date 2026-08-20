package io.github.adorsysgis.keycloakstatuslist.service;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloakstatuslist.exception.StatusListException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

/**
 * Service responsible for extracting public keys from JWKS key nodes. Handles RSA and EC key
 * extraction with proper parameter validation.
 */
public class JwksKeyExtractor {

    /**
     * Extracts the public key from a JWKS key node.
     */
    public PublicKey extractPublicKeyFromJwksKey(JsonNode keyNode) throws StatusListException {
        String kty = requireTextParameter(keyNode, "kty", "JWKS key type (kty)");

        return switch (kty) {
            case "RSA" -> extractRsaPublicKey(keyNode);
            case "EC" -> extractEcPublicKey(keyNode);
            default -> throw new StatusListException("Unsupported JWKS key type: " + kty);
        };
    }

    /**
     * Extracts an RSA public key from a JWKS key node.
     */
    private PublicKey extractRsaPublicKey(JsonNode keyNode) throws StatusListException {
        String n = requireTextParameter(keyNode, "n", "RSA JWKS key parameter n");
        String e = requireTextParameter(keyNode, "e", "RSA JWKS key parameter e");

        BigInteger modulus = decodeUnsignedInteger(n, "n");
        BigInteger exponent = decodeUnsignedInteger(e, "e");

        try {
            RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(rsaPublicKeySpec);
        } catch (GeneralSecurityException ex) {
            throw new StatusListException("Invalid RSA JWKS key parameters: " + ex.getMessage(), ex);
        }
    }

    /**
     * Extracts an EC public key from a JWKS key node.
     */
    private PublicKey extractEcPublicKey(JsonNode keyNode) throws StatusListException {
        String crv = requireTextParameter(keyNode, "crv", "EC JWKS key parameter crv");
        String x = requireTextParameter(keyNode, "x", "EC JWKS key parameter x");
        String y = requireTextParameter(keyNode, "y", "EC JWKS key parameter y");

        BigInteger xCoord = decodeUnsignedInteger(x, "x");
        BigInteger yCoord = decodeUnsignedInteger(y, "y");

        ECPoint ecPoint = new ECPoint(xCoord, yCoord);

        ECParameterSpec ecParams = getEcParameterSpec(crv);

        try {
            ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPoint, ecParams);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            return keyFactory.generatePublic(ecPublicKeySpec);
        } catch (GeneralSecurityException ex) {
            throw new StatusListException("Invalid EC JWKS key parameters: " + ex.getMessage(), ex);
        }
    }

    private String requireTextParameter(JsonNode keyNode, String fieldName, String description)
            throws StatusListException {
        if (keyNode == null
                || !keyNode.hasNonNull(fieldName)
                || !keyNode.get(fieldName).isTextual()) {
            throw new StatusListException("Missing required " + description);
        }

        String value = keyNode.get(fieldName).asText();
        if (value.isBlank()) {
            throw new StatusListException("Missing required " + description);
        }
        return value;
    }

    private BigInteger decodeUnsignedInteger(String value, String fieldName) throws StatusListException {
        try {
            return new BigInteger(1, Base64.getUrlDecoder().decode(value));
        } catch (IllegalArgumentException ex) {
            throw new StatusListException("Invalid Base64URL value for JWKS parameter " + fieldName, ex);
        }
    }

    /**
     * Gets EC parameter specification for the given curve.
     */
    private ECParameterSpec getEcParameterSpec(String crv) throws StatusListException {
        String curveName =
                switch (crv) {
                    case "P-256" -> "secp256r1";
                    case "P-384" -> "secp384r1";
                    case "P-521" -> "secp521r1";
                    default -> throw new StatusListException("Unsupported EC curve: " + crv);
                };

        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec(curveName));
            return params.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException ex) {
            throw new StatusListException("Failed to resolve EC parameter spec for curve " + crv, ex);
        }
    }
}
