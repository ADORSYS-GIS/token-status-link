package com.adorsys.keycloakstatuslist.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import java.util.Map;

/**
 * Represents a status claim for inclusion in an OAuth 2.0 or OpenID Connect token, as defined in the
 * <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-11.html#name-referenced-token">IETF OAuth Status List specification (Section 6.1)</a>.
 * The status claim contains a `status_list` object with an index (`idx`) and URI (`uri`) to reference the token's position in a status list,
 * enabling verification of the token's validity status. This class is annotated with Jackson annotations for automatic JSON serialization,
 * similar to Rust's serde library, to produce the required claim structure: `{ "status_list": { "idx": <index>, "uri": <uri> } }`.
 */
@JsonSerialize // Ensures Jackson serializes the class to JSON
public class Status {
    /**
     * The status list claim containing the index and URI, mapped to the `status_list` key in the JSON output.
     */
    @JsonProperty("status_list") // Maps this field to the "status_list" key in JSON
    private final StatusListClaim statusList;

    /**
     * Constructs a Status object with the provided status list reference.
     *
     * @param statusList The StatusListClaim containing the `idx` and `uri` for the token's status list entry.
     */
    public Status(StatusListClaim statusList) {
        this.statusList = statusList;
    }

    /**
     * Returns the status list claim for serialization by Jackson.
     * This getter is used by Jackson to access the `status_list` field during serialization.
     *
     * @return The StatusListClaim object containing `idx` and `uri`.
     */
    public StatusListClaim getStatusList() {
        return statusList;
    }

    /**
     * Converts the status claim to a map representation for inclusion in a token's claims.
     * This method is retained for compatibility with existing code (e.g., StatusListProtocolMapper),
     * delegating to Jackson for serialization to ensure consistency with the IETF specification.
     *
     * @return A map representing the status claim with the structure: `{ "status_list": { "idx": <index>, "uri": <uri> } }`.
     * @throws RuntimeException if serialization fails.
     */
    public Map<String, Object> toMap() {
        return Map.of(
                "status_list", statusList != null ? statusList.toMap() : null
        );
    }
}
