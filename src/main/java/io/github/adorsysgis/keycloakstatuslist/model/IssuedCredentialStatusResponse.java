package io.github.adorsysgis.keycloakstatuslist.model;

import java.util.List;

public record IssuedCredentialStatusResponse(
        List<IssuedCredentialStatus> credentials,
        List<IssuedCredentialLimit> limits,
        DanglingIssuedCredentials dangling) {

    public static final String DANGLING_NOTICE =
            "Omitted issued-credential entries may be a valid but non-revokable credential, or a leftover from a failed issuance. Ask an administrator to remove the Keycloak issued-credential entry if a quota slot must be freed.";

    public IssuedCredentialStatusResponse {
        credentials = credentials == null ? List.of() : List.copyOf(credentials);
        limits = limits == null ? List.of() : List.copyOf(limits);
        dangling = dangling == null ? DanglingIssuedCredentials.none() : dangling;
    }

    public IssuedCredentialStatusResponse(List<IssuedCredentialStatus> credentials) {
        this(credentials, List.of(), DanglingIssuedCredentials.none());
    }

    public IssuedCredentialStatusResponse(
            List<IssuedCredentialStatus> credentials, List<IssuedCredentialLimit> limits) {
        this(credentials, limits, DanglingIssuedCredentials.none());
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

    /**
     * Issued-credential rows with no successful status-list mapping. They are omitted from
     * {@code credentials} so the list only shows completed mappings.
     */
    public record DanglingIssuedCredentials(int count, String notice) {

        public static DanglingIssuedCredentials none() {
            return new DanglingIssuedCredentials(0, null);
        }

        public static DanglingIssuedCredentials of(int count) {
            if (count <= 0) {
                return none();
            }
            return new DanglingIssuedCredentials(count, DANGLING_NOTICE);
        }
    }
}
