# Technical Reference

This document is the detailed technical reference for the Keycloak Token Status Plugin.
For a general overview and quick start, see the [README](../README.md).

The plugin works with any status list server that implements both the
[OAuth 2.0 Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list) format and the management API
used by this plugin, such as the [status list server](https://github.com/adorsys/status-list-server) project.

## Table of Contents

- [Configuration Properties](#configuration-properties)
- [Enabling the Status List protocol mapper](#enabling-the-status-list-protocol-mapper)
- [HTTP Endpoints](#http-endpoints)
  - [Revoke an issued credential](#revoke-an-issued-credential)
  - [List issued credentials and their statuses](#list-issued-credentials-and-their-statuses)
- [Performance Considerations](#performance-considerations)
- [Proxy support](#proxy-support)

## Configuration Properties

The plugin can be configured at the realm level with the following properties:

| Property                                        | Description                                                                                                                                                                                                                        | Default Value    |
| ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- |
| `status-list-enabled`                           | Enables or disables the status list service for the realm (must be explicitly opted in)                                                                                                                                            | `false`          |
| `status-list-server-url`                        | URL of the status list server (required when the feature is enabled; issuance fails if it is missing or invalid and `status-list-mandatory` is `true`). You may try our public instance at `https://statuslist.eudi-adorsys.com`   | _None_           |
| `status-list-token-issuer-prefix`               | Prefix for building the Token Issuer ID                                                                                                                                                                                            | `Generated UUID` |
| `status-list-issuance-timeout`                  | Timeout in milliseconds for **issuance** operations (runtime). Non-positive values disable circuit breaker                                                                                                                         | `10000`          |
| `status-list-registration-timeout`              | Timeout in milliseconds for **background registration** operations                                                                                                                                                                 | `30000`          |
| `status-list-registration-retries`              | Maximum number of HTTP request retries for background registration operations                                                                                                                                                      | `1`              |
| `status-list-registration-cooldown`             | Cooldown period in **milliseconds** between registration attempts for the same realm                                                                                                                                               | `60000`          |
| `status-list-circuit-breaker-failure-threshold` | Number of failures/timeouts before opening the circuit breaker                                                                                                                                                                     | `5`              |
| `status-list-mandatory`                         | If true, publication failures block issuance; if false, failures are logged and issuance continues without a status claim                                                                                                          | `false`          |
| `status-list-max-entries`                       | Maximum number of entries to publish under the same status list                                                                                                                                                                    | `10000`          |
| `status-list-max-credentials-per-user`          | Optional realm fallback for the maximum number of non-revoked credentials per holder and credential type. Mapper config takes precedence. Absent or `0` means unlimited. Non-numeric or negative values are rejected (fail closed) | `0`              |
| `status-list-overflow-policy`                   | Optional realm fallback for overflow behavior when the max is reached: `REJECT` or `REVOKE_OLDEST`. Mapper config takes precedence. Defaults to `REJECT`                                                                           | `REJECT`         |
| `status-list-tls-trust-all`                     | Instructs the status-list http-client to trust all TLS certificates. **DO NOT USE IN PRODUCTION**                                                                                                                                  | `false`          |
| `status-list-tls-ca-cert-path`                  | Path to a PEM-encoded CA certificate to be trusted by the status-list http-client, in addition to the JVM defaults                                                                                                                 | `null`           |

## Enabling the Status List protocol mapper

To enable the Status List protocol mapper, attach it to the client scope for the relevant credential configuration. Below is a sample configuration:

```json
{
  "name": "status-list-claim-mapper",
  "protocol": "oid4vc",
  "protocolMapper": "oid4vc-status-list-claim-mapper",
  "config": {
    "status-list-max-credentials-per-user": "3",
    "status-list-overflow-policy": "REJECT"
  }
}
```

`status-list-max-credentials-per-user` is optional. If you omit it or leave it blank, the plugin inherits the realm fallback. You can set it to `0` to leave this credential type unlimited.

A positive value limits how many credentials of that type a holder may keep at the same time. A credential issued by Keycloak counts toward the limit unless it has been revoked. In detail, it counts when any of these is true:

- It has a status-list mapping with status `SUCCESS`, and the plugin has not marked it `INVALID`.
- It has a mapping with status `FAILURE`. The plugin could not publish its status, but Keycloak may still have delivered the credential when the status list is not mandatory.
- It has no mapping at all. This happens when an issuance attempt failed after Keycloak had already recorded the credential.

A `SUSPENDED` credential still counts; revoking it frees its slot. The `limits.activeCount` field in the listing endpoint uses the same count. While reserving a slot, the plugin also counts other issuance requests that are still in progress, so parallel requests cannot exceed the limit. Those in-progress requests are not part of `activeCount`.

When the holder has reached the limit, the plugin applies `status-list-overflow-policy`. The plugin reads the policy from the mapper first, then from the optional realm attribute, and falls back to `REJECT`:

- `REJECT` — The plugin refuses the new issuance with `409` and `credential_limit_reached`.
- `REVOKE_OLDEST` — The plugin revokes the holder's oldest credentials of that type until the new credential fits, then continues with the issuance. If an administrator lowered the limit (for example from 5 to 3 while the holder had 5), the plugin revokes 3 credentials: 2 to get back under the new limit and 1 to make room for the new credential.

With `REVOKE_OLDEST`, the plugin only revokes a credential through the status-list server. It marks the credential `INVALID` locally only after the server has accepted the revocation. A `FAILURE` credential or a credential without a mapping cannot be revoked that way. If such a credential is among the oldest ones that must go, the plugin refuses the issuance with `400` and `credential_limit_unresolved` rather than exceed the limit.

A revocation that has succeeded is never undone. If the plugin revokes several credentials and one of them fails, the earlier ones stay revoked and the issuance fails. If the revocation succeeds but publishing the new credential fails afterwards, the old credential also stays revoked.

Two parallel requests from the same holder may revoke the same oldest credential. Only one of them can take the freed slot. The other one fails with `409` and `credential_limit_reached`, and the holder can simply retry.

Known limitation: a failed issuance attempt leaves behind a `FAILURE` or unmapped credential that still counts toward the limit and cannot be revoked. Under `REVOKE_OLDEST`, that holder cannot receive a new credential of that type until the leftover is removed.

## HTTP Endpoints

The plugin exposes two inbound endpoints, both realm-scoped under `{keycloak-base}/realms/{realm}/status-list` and
authenticating with a standard Keycloak bearer access token. Users can list and revoke their own credentials. Users
with the realm role `credential-offer-create` (admin users) can additionally list or revoke the credentials of other
users in the same realm.

### Revoke an issued credential

Revocation is initiated by the client application at the plugin's dedicated
`/revoke` endpoint. It activates only when `mode=issued_credential_revocation` is present in the form payload;
any other value is rejected.

```text
POST /realms/{realm}/status-list/revoke
Authorization: Bearer <user-access-token>
Content-Type: application/x-www-form-urlencoded

mode=issued_credential_revocation&credential_id=<issued-credential-id>&reason=<optional reason>
```

| Parameter       | Required | Description                                                            |
| --------------- | -------- | ---------------------------------------------------------------------- |
| `mode`          | yes      | Must be `issued_credential_revocation` to select the plugin's behavior |
| `credential_id` | yes      | ID of the Keycloak-issued credential to revoke                         |
| `reason`        | no       | Free-form reason, echoed back in the response                          |

The credential is looked up among those issued to the authenticated user. Users with the realm role
`credential-offer-create` may also revoke a credential issued to another user in the same realm. On success, the
credential's status list entry is set to `INVALID` and the issued credential record updated accordingly in Keycloak.

**Success** (`200 OK`, `application/json`):

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

| Status | Cause                                                                                                            |
| ------ | ---------------------------------------------------------------------------------------------------------------- |
| `400`  | Invalid input, such as a missing or blank `credential_id`, or a `mode` other than `issued_credential_revocation` |
| `401`  | Missing, invalid, or expired bearer token                                                                        |
| `404`  | Credential not found for this caller, or it has no status list mapping                                           |
| `500`  | Service disabled or not configured, or an unexpected error during revocation                                     |

### List issued credentials and their statuses

This endpoint returns issued credentials together with the status recorded in the plugin's status list mapping
table, plus display metadata (`credentialType`, `clientName`). The status is read locally and is
not fetched from the status list server per request.

Callers receive their own credentials. Admin users may pass
`target_user` to list a single holder. Without that query, admins still receive only their own
credentials. Non-admin users receive `403` if `target_user` is set.

```text
GET /realms/{realm}/status-list/issued-credential-status
Authorization: Bearer <user-access-token>
Accept: application/json
```

```text
GET /realms/{realm}/status-list/issued-credential-status?target_user=<holder-username>
Authorization: Bearer <user-access-token>
Accept: application/json
```

The response wraps the entries in a `credentials` array and includes quota metadata in `limits`
for credential types that have a configured maximum:

```json
{
  "credentials": [
    {
      "credentialId": "8f14e45f-ea8d-4c6b-9f2a-1b7c3d5e9a02",
      "verifiableCredentialId": "urn:uuid:2c8a1f7b-64d3-4a19-9f0e-7d5b3c1a8e46",
      "credentialType": "IdentityCredential",
      "issuedAt": 1754216400000,
      "expiresAt": 1785752400000,
      "clientId": "c9f1a2b3-4d5e-6789-abcd-ef0123456789",
      "clientName": "wallet-app",
      "revision": "1",
      "status": "VALID",
      "userId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "username": "alice"
    }
  ],
  "limits": [
    {
      "credentialConfigurationId": "IdentityCredential",
      "max": 3,
      "activeCount": 3,
      "remaining": 0,
      "overflowPolicy": "REJECT"
    }
  ]
}
```

| Field                    | Type   | Description                                                                                                                |
| ------------------------ | ------ | -------------------------------------------------------------------------------------------------------------------------- |
| `credentialId`           | string | Internal ID of the issued credential record in Keycloak, created per issuance; used for status list mapping and revocation |
| `verifiableCredentialId` | string | ID of the holder's verifiable credential (the OID4VCI credential identifier), stable per holder and credential type        |
| `credentialType`         | string | Credential configuration/type (client-scope name)                                                                          |
| `issuedAt`               | number | Issuance timestamp as recorded by Keycloak, in Unix epoch milliseconds                                                     |
| `expiresAt`              | number | Expiration timestamp as recorded by Keycloak, in Unix epoch milliseconds; `null` if not set                                |
| `clientId`               | string | Internal id of the client that requested the credential                                                                    |
| `clientName`             | string | Display name of that client, falling back to its public client id                                                          |
| `revision`               | string | Credential revision                                                                                                        |
| `status`                 | string | `VALID`, `INVALID`, `SUSPENDED`, or `UNKNOWN` when no mapping exists                                                       |
| `userId`                 | string | Keycloak user id of the credential holder                                                                                  |
| `username`               | string | Username of the credential holder                                                                                          |

Each `limits` entry describes the holder's quota for one credential type:

| Field                       | Type   | Description                                                                                                               |
| --------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------- |
| `credentialConfigurationId` | string | Credential type the cap applies to                                                                                        |
| `max`                       | number | Configured maximum of non-revoked credentials of this type                                                                |
| `activeCount`               | number | `SUCCESS`/`FAILURE` mappings that still have an issued credential (not `INVALID`). In-flight `INIT` rows are not included |
| `remaining`                 | number | Slots left before the overflow policy applies                                                                             |
| `overflowPolicy`            | string | Configured overflow behavior: `REJECT` or `REVOKE_OLDEST`                                                                 |

## Performance Considerations

<!-- TODO: Rework this section - see https://github.com/ADORSYS-GIS/token-status-link/issues/136. Much of it has fallen out of sync. -->

- **Non-Blocking Registration**: Realm registration is performed **asynchronously** in background threads (
  `status-list-registration`). This ensures that Keycloak startup and request processing are never blocked by status list
  server latency.
- **Retry & Cooldown**: Unregistered realms are retried by a scheduled reconciliation task at a fixed interval
  (every 30 seconds), up to a maximum of 5 attempts per realm. A per-realm cooldown (default: 1 minute) is enforced
  between registration attempts. Outbound HTTP requests additionally use exponential backoff (1s, 2s, 4s).
- **On-Demand (Lazy) Trigger**: Registration is triggered on-demand when a realm's status list endpoints are first
  accessed, but the trigger itself is non-blocking to the caller's thread.
- **Configurable Timeouts**: Timeouts are configurable via `status-list-issuance-timeout` (default: 10s for runtime) and
  `status-list-registration-timeout` (default: 30s for background).

## Proxy support

Usage of HTTP(S) proxies for the status list HTTP client is supported via the standard environment variables
(see [Keycloak Outgoing Proxy Config](https://www.keycloak.org/server/outgoinghttp#_proxy_mappings_for_outgoing_http_requests)
for format reference):

- `HTTPS_PROXY` / `HTTP_PROXY` (also lowercase) define the proxy to be used. `HTTPS_PROXY` takes precedence.
- `NO_PROXY` (also lowercase) defines a comma-separated list of hosts to be reached without the proxy. Matching is
  case-insensitive; a bare `*` matches all hosts.
