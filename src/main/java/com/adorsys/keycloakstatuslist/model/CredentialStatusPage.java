package com.adorsys.keycloakstatuslist.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Paginated response containing credential status entries.
 */
public record CredentialStatusPage(
        @JsonProperty("items") List<CredentialStatusResponse> items,
        @JsonProperty("total") long total,
        @JsonProperty("offset") int offset,
        @JsonProperty("limit") int limit) {}
