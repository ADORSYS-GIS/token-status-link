package com.adorsys.keycloakstatuslist.model;

import java.util.List;

public record IssuedCredentialStatusResponse(List<IssuedCredentialStatus> credentials) {

    public record IssuedCredentialStatus(
            String credentialId,
            String verifiableCredentialId,
            Long issuedAt,
            Long expiresAt,
            String clientId,
            String revision,
            String status) {}
}
