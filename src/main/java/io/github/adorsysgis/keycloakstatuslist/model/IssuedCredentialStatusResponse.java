package io.github.adorsysgis.keycloakstatuslist.model;

import java.util.List;

public record IssuedCredentialStatusResponse(
        List<IssuedCredentialStatus> credentials, List<IssuedCredentialLimit> limits) {

    public static final String OVERFLOW_POLICY_REJECT = "REJECT";
    public static final String OVERFLOW_POLICY_REVOKE_OLDEST = "REVOKE_OLDEST";

    public IssuedCredentialStatusResponse {
        credentials = credentials == null ? List.of() : List.copyOf(credentials);
        limits = limits == null ? List.of() : List.copyOf(limits);
    }

    public IssuedCredentialStatusResponse(List<IssuedCredentialStatus> credentials) {
        this(credentials, List.of());
    }

    public record IssuedCredentialStatus(
            String credentialId,
            String verifiableCredentialId,
            Long issuedAt,
            Long expiresAt,
            String clientId,
            String revision,
            String status) {}

    public record IssuedCredentialLimit(
            String credentialConfigurationId, int max, long activeCount, long remaining, String overflowPolicy) {}
}
