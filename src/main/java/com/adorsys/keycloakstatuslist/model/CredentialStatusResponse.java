package com.adorsys.keycloakstatuslist.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonRawValue;

/**
 * Response model representing a single credential's status list mapping entry,
 * returned by the admin credentials endpoint.
 */
public record CredentialStatusResponse(
        @JsonProperty("id") String id,
        @JsonProperty("token_id") String tokenId,
        @JsonProperty("user_id") String userId,
        @JsonProperty("username") String username,
        @JsonProperty("status") String status,
        @JsonProperty("status_list_id") String statusListId,
        @JsonProperty("index") long index,
        @JsonProperty("created_timestamp") long createdTimestamp,
        @JsonRawValue @JsonProperty("metadata") String metadata) {}
