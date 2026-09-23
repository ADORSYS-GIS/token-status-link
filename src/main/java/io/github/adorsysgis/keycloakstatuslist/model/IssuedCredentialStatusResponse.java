package io.github.adorsysgis.keycloakstatuslist.model;

import java.util.List;

public record IssuedCredentialStatusResponse(
        List<IssuedCredentialStatus> credentials, List<IssuedCredentialLimit> limits) {

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
            String credentialType,
            Long issuedAt,
            Long expiresAt,
            String clientId,
            String clientName,
            String revision,
            String status,
            String userId,
            String username) {}

    public record IssuedCredentialLimit(
            String credentialConfigurationId, int max, long activeCount, long remaining, String overflowPolicy) {}
}
