package com.adorsys.keycloakstatuslist.helpers;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.util.Objects;
import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.util.JWKSUtils;

public class ECTestUtils {

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
        byte[] dBytes = Base64Url.decode((String) jwk.getOtherClaims().get("d"));
        BigInteger d = new BigInteger(1, dBytes);

        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec ecParameters = params.getParameterSpec(ECParameterSpec.class);

        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(d, ecParameters);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePrivate(privateKeySpec);
    }
}
