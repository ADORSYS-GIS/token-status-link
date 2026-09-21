package io.github.adorsysgis.keycloakstatuslist.model;

import java.util.List;

public record IssuedCredentialStatusResponse(List<IssuedCredentialStatus> credentials) {

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
}
