package com.adorsys.keycloakstatuslist.model;

import java.util.List;

/**
 * Filter criteria for querying credential status entries.
 *
 * @param userId       user ID to filter by (resolved from username at the resource layer)
 * @param tokenStatus  token status to filter by (VALID or INVALID)
 * @param claims       substring patterns to match against the metadata JSON column (ANDed)
 */
public record CredentialStatusFilter(
        String userId,
        TokenStatus tokenStatus,
        List<String> claims) {

    /** A filter that matches everything. */
    public static final CredentialStatusFilter EMPTY = new CredentialStatusFilter(null, null, List.of());

    /**
     * Returns true if no filter criteria are set.
     */
    public boolean isEmpty() {
        return userId == null && tokenStatus == null && (claims == null || claims.isEmpty());
    }
}
