package com.adorsys.keycloakstatuslist.integration;

import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.ECDSASignatureSignerContext;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.protocol.oid4vc.issuance.keybinding.JwtProofValidator;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.JsonWebToken;

final class WalletProofFactory {

    private WalletProofFactory() {}

    static String jwt(String clientId, String audience, String nonce) throws Exception {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        var keyPair = generator.generateKeyPair();

        JWK publicJwk = JWKBuilder.create().algorithm(Algorithm.ES256).ec(keyPair.getPublic(), KeyUse.SIG);
        JsonWebToken payload =
                new JsonWebToken().issuer(clientId).audience(audience).issuedNow();
        payload.setOtherClaims(IDToken.NONCE, nonce);

        return new JWSBuilder()
                .type(JwtProofValidator.PROOF_JWT_TYP)
                .jwk(publicJwk)
                .jsonContent(payload)
                .sign(new ECDSASignatureSignerContext(key(keyPair.getPublic(), keyPair.getPrivate())));
    }

    private static KeyWrapper key(java.security.PublicKey publicKey, java.security.PrivateKey privateKey) {
        KeyWrapper key = new KeyWrapper();
        key.setType(KeyType.EC);
        key.setAlgorithm(Algorithm.ES256);
        key.setUse(KeyUse.SIG);
        key.setCurve("P-256");
        key.setPublicKey(publicKey);
        key.setPrivateKey(privateKey);
        return key;
    }
}
