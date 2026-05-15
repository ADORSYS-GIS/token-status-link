package com.adorsys.keycloakstatuslist.helpers;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.util.Map;
import java.util.Objects;
import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.util.JWKSUtils;

public class ECTestUtils {

    // Maps JWK crv names to Java ECGenParameterSpec names
    private static final Map<String, String> CRV_TO_EC_SPEC = Map.of(
            "P-256", "secp256r1",
            "P-384", "secp384r1",
            "P-521", "secp521r1");

    public static KeyWrapper getEcKeyWrapper(JWK jwk) throws Exception {
        if (!KeyType.EC.equals(jwk.getKeyType())) {
            throw new IllegalArgumentException("Only EC keys are supported");
        }

        KeyWrapper keyWrapper = JWKSUtils.getKeyWrapper(jwk);
        Objects.requireNonNull(keyWrapper);
        keyWrapper.setPrivateKey(getEcPrivateKey(jwk));

        return keyWrapper;
    }

    private static PrivateKey getEcPrivateKey(JWK jwk) throws Exception {
        String dEncoded = (String) jwk.getOtherClaims().get("d");
        if (dEncoded == null) {
            throw new IllegalArgumentException("Missing 'd' claim in EC JWK — cannot reconstruct private key");
        }
        byte[] dBytes = Base64Url.decode(dEncoded);
        BigInteger d = new BigInteger(1, dBytes);

        // Read curve from JWK 'crv' field
        String crv = (String) jwk.getOtherClaims().get("crv");
        if (crv == null) {
            throw new IllegalArgumentException("Missing 'crv' claim in EC JWK");
        }
        String ecSpecName = CRV_TO_EC_SPEC.get(crv);
        if (ecSpecName == null) {
            throw new IllegalArgumentException("Unsupported EC curve: " + crv);
        }

        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec(ecSpecName));
        ECParameterSpec ecParameters = params.getParameterSpec(ECParameterSpec.class);

        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(d, ecParameters);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePrivate(privateKeySpec);
    }
}
