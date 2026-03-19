package com.adorsys.keycloakstatuslist.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;
import org.keycloak.util.JsonSerialization;

/**
 * Represents a status claim for inclusion in an OAuth 2.0 or OpenID Connect token, as defined in
 * the <a
 * href="https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-11.html#name-referenced-token">IETF
 * OAuth Status List specification (Section 6.1)</a>. The status claim contains a `status_list`
 * object with an index (`idx`) and URI (`uri`) to reference the token's position in a status list,
 * enabling verification of the token's validity status. This class is annotated with Jackson
 * annotations for automatic JSON serialization, similar to Rust's serde library, to produce the
 * required claim structure: `{ "status_list": { "idx": <index>, "uri": <uri> } }`.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Status {

    /**
     * The status list claim containing the index and URI, mapped to the `status_list` key in the JSON
     * output.
     */
    @JsonProperty("status_list")
    private StatusListClaim statusList;

    /**
     * Default constructor for JSON deserialization. Required by Jackson to create an instance of this
     * class when deserializing from JSON.
     */
    public Status() {
        // Default constructor for JSON deserialization
    }

    /**
     * Constructs a Status object with the provided status list reference.
     *
     * @param statusList The StatusListClaim containing the `idx` and `uri` for the token's status
     *                   list entry.
     */
    public Status(StatusListClaim statusList) {
        this.statusList = statusList;
    }

    public StatusListClaim getStatusList() {
        return statusList;
    }

    public Status setStatusList(StatusListClaim statusList) {
        this.statusList = statusList;
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        Status status = (Status) o;
        return Objects.equals(getStatusList(), status.getStatusList());
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(getStatusList());
    }

    @Override
    public String toString() {
        return JsonSerialization.valueAsString(this);
    }
}
