package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.fasterxml.jackson.databind.JsonNode;
import org.jboss.logging.Logger;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.ECPoint;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.AlgorithmParameters;
import java.math.BigInteger;
import java.util.Base64;

/**
 * Service responsible for extracting public keys from JWKS key nodes.
 * Handles RSA and EC key extraction with proper parameter validation.
 */
public class JwksKeyExtractor {

    private static final Logger logger = Logger.getLogger(JwksKeyExtractor.class);

    /**
     * Extracts the public key from a JWKS key node.
     */
    public PublicKey extractPublicKeyFromJwksKey(JsonNode keyNode) throws StatusListException {
        try {
            String kty = keyNode.get("kty").asText();

            if (kty.equals("RSA")) {
                return extractRsaPublicKey(keyNode);
            } else if (kty.equals("EC")) {
                return extractEcPublicKey(keyNode);
            } else {
                throw new StatusListException("Unsupported JWKS key type: " + kty);
            }

        } catch (Exception e) {
            logger.errorf("Failed to extract public key from JWKS key node. Error: %s", e.getMessage());
            throw new StatusListException("Failed to extract public key from JWKS key node: " + e.getMessage(), e);
        }
    }

    /**
     * Extracts an RSA public key from a JWKS key node.
     */
    private PublicKey extractRsaPublicKey(JsonNode keyNode) throws Exception {
        String n = keyNode.get("n").asText();
        String e = keyNode.get("e").asText();

        if (n == null || e == null) {
            throw new StatusListException("Missing required RSA JWKS key parameters (n, e)");
        }

        BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(n));
        BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(e));

        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(rsaPublicKeySpec);
    }

    /**
     * Extracts an EC public key from a JWKS key node.
     */
    private PublicKey extractEcPublicKey(JsonNode keyNode) throws Exception {
        String crv = keyNode.get("crv").asText();
        String x = keyNode.get("x").asText();
        String y = keyNode.get("y").asText();

        if (crv == null || x == null || y == null) {
            throw new StatusListException("Missing required EC JWKS key parameters (crv, x, y)");
        }

        BigInteger xCoord = new BigInteger(1, Base64.getUrlDecoder().decode(x));
        BigInteger yCoord = new BigInteger(1, Base64.getUrlDecoder().decode(y));

        ECPoint ecPoint = new ECPoint(xCoord, yCoord);

        ECParameterSpec ecParams = getEcParameterSpec(crv);
        if (ecParams == null) {
            throw new StatusListException("Unsupported EC curve: " + crv);
        }

        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPoint, ecParams);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(ecPublicKeySpec);
    }

    /**
     * Gets EC parameter specification for the given curve.
     */
    private ECParameterSpec getEcParameterSpec(String crv) {
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            if (crv.equals("P-256")) {
                params.init(new ECGenParameterSpec("secp256r1"));
            } else if (crv.equals("P-384")) {
                params.init(new ECGenParameterSpec("secp384r1"));
            } else if (crv.equals("P-521")) {
                params.init(new ECGenParameterSpec("secp521r1"));
            } else {
                return null;
            }
            return params.getParameterSpec(ECParameterSpec.class);
        } catch (Exception e) {
            logger.warnf("Failed to get EC parameter spec for curve: %s", crv);
            return null;
        }
    }
} 
