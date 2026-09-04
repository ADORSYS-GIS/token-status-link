# Keycloak Token Status Plugin

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

This plugin lets Keycloak send the status of long-lived tokens or verifiable credentials to an external status list
server. It helps you quickly revoke credentials before they expire.

The primary use case is for verifiable credentials or other long-lived tokens that may need to be invalidated before
their expiration (for example, if a credential is compromised or must be revoked for compliance reasons).

The status list server should implement the
[OAuth 2.0 Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list) pattern.

## Table of Contents

- [Features](#features)
- [Configuration Properties](#configuration-properties)
  - [Proxy support](#proxy-support)
- [Compatibility](#compatibility)
- [Installation](#installation)
  - [Releases on Maven Central](#releases-on-maven-central)
  - [Enabling the Status List protocol mapper](#enabling-the-status-list-protocol-mapper)
- [Performance Considerations](#performance-considerations)
- [HTTP Endpoints](#http-endpoints)
  - [Revoke an issued credential](#revoke-an-issued-credential)
  - [List issued credentials and their status](#list-issued-credentials-and-their-status)
- [Status List Server API](#status-list-server-api)
- [Development and Testing](#development-and-testing)
- [License](#license)

## Features

- Publish token status to an external status list server
- Support for OAuth Status List token statuses (VALID, INVALID, SUSPENDED)
- Revocation of issued verifiable credentials through Keycloak's `/revoke` endpoint
- Secure communication with TLS 1.2/1.3; outbound status list API calls are authenticated with a
  realm-signed JWT bearer token
- Detailed logging with unique request IDs for better traceability

## Configuration Properties

The plugin can be configured at the realm level with the following properties:

| Property                                        | Description                                                                                                               | Default Value                         |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| `status-list-enabled`                           | Enables or disables the status list service                                                                               | `true`                                |
| `status-list-server-url`                        | URL of the status list server                                                                                             | `https://statuslist.eudi-adorsys.com` |
| `status-list-token-issuer-prefix`               | Prefix for building the Token Issuer ID                                                                                   | `Generated UUID`                      |
| `status-list-issuance-timeout`                  | Timeout in milliseconds for **issuance** operations (runtime). Non-positive values disable circuit breaker                | `10000`                               |
| `status-list-registration-timeout`              | Timeout in milliseconds for **background registration** operations                                                        | `30000`                               |
| `status-list-registration-retries`              | Number of retries for background registration operations                                                                  | `1`                                   |
| `status-list-registration-cooldown`             | Cooldown period in **milliseconds** between registration attempts for the same realm                                      | `60000`                               |
| `status-list-circuit-breaker-failure-threshold` | Number of failures/timeouts before opening the circuit breaker                                                            | `5`                                   |
| `status-list-mandatory`                         | If true, publication failures block issuance; if false, failures are logged and issuance continues without a status claim | `false`                               |
| `status-list-max-entries`                       | Maximum number of entries to publish under the same status list                                                           | `10000`                               |
| `status-list-tls-trust-all`                     | Instructs the status-list http-client to trust all TLS certificates. **DO NOT USE IN PRODUCTION**                         | `false`                               |
| `status-list-tls-ca-cert-path`                  | Path to a PEM-encoded CA certificate to be trusted by the status-list http-client, in addition to the JVM defaults        | `null`                                |

### Proxy support

Usage of HTTP/S proxies for the status-list http-client is supported via the standard environment variables
(see [Keycloak Outgoing Proxy Config](https://www.keycloak.org/server/outgoinghttp#_proxy_mappings_for_outgoing_http_requests) for format reference):

- `HTTPS_PROXY` / `HTTP_PROXY` (also lowercase) define the proxy to be used. `HTTPS_PROXY` takes precedence.
- `NO_PROXY` (also lowercase) defines a comma-separated list of hosts to be reached without the proxy. Matching is case-insensitive; a bare `*` matches all hosts.

## Compatibility

This plugin has been tested and verified to work with:

| Component | Version |
| --------- | ------- |
| Keycloak  | 26.7.2  |

## Installation

### Prerequisites

- Java 17 or later

1. Build the plugin using Maven:
   ```bash
   ./mvnw clean package
   ```
2. Copy the resulting JAR file from `target/keycloak-token-status-plugin-*.jar` to Keycloak's `providers` directory.
3. Restart Keycloak to load the plugin.
4. Configure the plugin using the realm attributes described in
   [Configuration Properties](#configuration-properties).

### Releases on Maven Central

The plugin is published
to [Maven Central](https://central.sonatype.com/artifact/io.github.adorsys-gis/keycloak-token-status-plugin).
Releases are automated via GitHub Actions and triggered by pushing a version tag (`vX.Y.Z`). The workflow requires the following repository secrets:

| Secret                   | Description                                               |
| :----------------------- | :-------------------------------------------------------- |
| `CENTRAL_TOKEN_USERNAME` | The Maven Central token username.                         |
| `CENTRAL_TOKEN_PASSWORD` | The Maven Central token password.                         |
| `GPG_PRIVATE_KEY`        | The ASCII-armored private key used for signing artifacts. |
| `GPG_PASSPHRASE`         | The passphrase required to unlock the GPG private key.    |

### Enabling the Status List protocol mapper

For the Status List protocol mapper to come into effect, you need to explicitly attach it to the client scope
corresponding to a specific credential's configuration. Below is a sample such configuration:

```json
{
  "name": "status-list-claim-mapper",
  "protocol": "oid4vc",
  "protocolMapper": "oid4vc-status-list-claim-mapper",
  "config": {}
}
```

## Performance Considerations

- **Non-Blocking Registration**: Realm registration is performed **asynchronously** in background threads (`status-list-init`). This ensures that Keycloak startup and OIDC request processing are never blocked by status list server latency.
- **Retry & Cooldown**: The plugin includes a built-in **retry mechanism** with exponential backoff (1s, 2s, 4s) for registration attempts. To prevent resource exhaustion during server failures, a **1-minute cooldown** is enforced per-realm between registration attempts.
- **On-Demand (Lazy) Trigger**: Registration is triggered on-demand when a realm's OIDC endpoints are first accessed, but the trigger itself is non-blocking to the caller's thread.
- **Configurable Timeouts**: Timeouts are configurable via `status-list-issuance-timeout` (default: 10s for runtime) and `status-list-registration-timeout` (default: 30s for background).

## HTTP Endpoints

The plugin exposes two inbound endpoints, both realm-scoped under
`{keycloak-base}/realms/{realm}/protocol/openid-connect`. Both authenticate with a standard Keycloak
bearer access token. Listing is always scoped to the authenticated user. Revocation accepts either the
credential holder or a user with the realm role `credential-offer-create`.

### Revoke an issued credential

Revocation is initiated by the client application. The plugin overrides Keycloak's standard
`/revoke` endpoint and activates only when `mode=issued_credential_revocation` is present in the form payload;
any other value (or none) falls through to Keycloak's default token revocation behavior, even when the plugin
is disabled.

```http
POST /realms/{realm}/protocol/openid-connect/revoke
Authorization: Bearer <user-access-token>
Content-Type: application/x-www-form-urlencoded

mode=issued_credential_revocation&credential_id=<issued-credential-id>&reason=<optional reason>
```

| Parameter       | Required | Description                                                              |
| --------------- | -------- | ------------------------------------------------------------------------ |
| `mode`          | yes      | Must be `issued_credential_revocation` to select the plugin's behavior   |
| `credential_id` | yes      | ID of the Keycloak-issued credential to revoke                           |
| `reason`        | no       | Free-form reason, echoed back in the response                            |

The credential is looked up among those issued to the authenticated user. Users with the realm role
`credential-offer-create` may also revoke a credential issued to another user in the same realm. Callers without
that role still receive `404` for another user's `credential_id`, the same as for an unknown id. On success, the
credential's status list entry is set to `INVALID` and the issued credential record is kept in Keycloak, so clients
can continue to display it with a revoked status.

**Success** — `200 OK`, `application/json`:

```json
{
  "success": true,
  "revoked_at": "2026-08-03T10:30:00Z",
  "revocation_reason": "compromised",
  "message": "Credential revoked successfully"
}
```

**Errors** use the same shape with `"success": false`, `revoked_at` and `revocation_reason` set to `null`, and
`message` describing the failure:

| Status | Cause                                                                       |
| ------ | --------------------------------------------------------------------------- |
| `400`  | Invalid input, such as a missing or blank `credential_id`                   |
| `401`  | Missing, invalid, or expired bearer token                                   |
| `404`  | Credential not found for this caller, or it has no status list mapping      |
| `500`  | Service disabled or not configured, or an unexpected error during revocation |

### List issued credentials and their status

Returns the credentials issued to the authenticated user, together with the status recorded in the plugin's
status list mapping table. The status is read locally and is not fetched from the status list server per request.

```http
GET /realms/{realm}/protocol/openid-connect/issued-credential-status
Authorization: Bearer <user-access-token>
Accept: application/json
```

The response wraps the entries in a `credentials` array:

```json
{
  "credentials": [
    {
      "credentialId": "8f14e45f-ea8d-4c6b-9f2a-1b7c3d5e9a02",
      "verifiableCredentialId": "urn:uuid:2c8a1f7b-64d3-4a19-9f0e-7d5b3c1a8e46",
      "issuedAt": 1754216400000,
      "expiresAt": 1785752400000,
      "clientId": "wallet-app",
      "revision": "1",
      "status": "VALID"
    }
  ]
}
```

| Field                    | Type   | Description                                                          |
| ------------------------ | ------ | -------------------------------------------------------------------- |
| `credentialId`           | string | Keycloak-issued credential ID                                        |
| `verifiableCredentialId` | string | Verifiable credential identifier                                     |
| `issuedAt`               | number | Issuance timestamp as recorded by Keycloak, in Unix epoch milliseconds |
| `expiresAt`              | number | Expiration timestamp as recorded by Keycloak, in Unix epoch milliseconds; `null` if not set |
| `clientId`               | string | Client that requested the credential                                 |
| `revision`               | string | Credential revision                                                  |
| `status`                 | string | `VALID`, `INVALID`, `SUSPENDED`, or `UNKNOWN` when no mapping exists |

## Status List Server API

These are the outbound calls the plugin makes to the configured status list server. Each request includes an
`Authorization: Bearer <jwt>` header signed with the realm's active signing key.

| Operation                             | Endpoint                                                                       |
| ------------------------------------- | ------------------------------------------------------------------------------ |
| Register issuer credential/public key | `POST /api/v1/credentials`                                                     |
| Retrieve status list JWT              | `GET /api/v1/status-lists/{list_id}` with `Accept: application/statuslist+jwt` |
| Publish status entries                | `PUT /api/v1/status-lists/{list_id}/statuses`                                  |
| Update status entries                 | `PATCH /api/v1/status-lists/{list_id}/statuses`                                |
| Health check                          | `GET /health`                                                                  |

## Development and Testing

```bash
./mvnw test            # run tests
./mvnw spotless:check  # verify formatting
./mvnw spotless:apply  # fix formatting
```

To test against a local status list server, point `status-list-server-url` at it and enable debug logging to
see the request and response details.

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-only).
See [LICENSE](./LICENSE) for details.
