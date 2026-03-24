# Keycloak Token Status Plugin

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

This plugin lets Keycloak send the status of long-lived tokens or verifiable credentials to an external status list
server. It helps you quickly revoke credentials before they expire.

The primary use case is for verifiable credentials or other long-lived tokens that may need to be invalidated before
their expiration (for example, if a credential is compromised or must be revoked for compliance reasons).

The status list server should implement the OAuth 2.0 Status List pattern.

## Features

- Publish token status to an external status list server
- Support for different token statuses (VALID, REVOKED)
- Fixed connection parameters with safe defaults
- Secure communication with TLS 1.2/1.3
- Support for authentication with the status list server
- Detailed logging with unique request IDs for better traceability

## Configuration Properties

The plugin can be configured at the realm level with the following properties:

| Property                                  | Description                                                                                                               | Default Value                          |
|-------------------------------------------|---------------------------------------------------------------------------------------------------------------------------|----------------------------------------|
| `status-list-enabled`                     | Enables or disables the status list service                                                                               | `true`                                 |
| `status-list-server-url`                  | URL of the status list server                                                                                             | `https://statuslist.eudi-adorsys.com/` |
| `status-list-token-issuer-prefix`         | Prefix for building the Token Issuer ID                                                                                   | `Generated UUID`                       |
| `status-list-issuance-timeout`            | Timeout in milliseconds for issuance operations (used for both connection and read). Non-positive values disable circuit breaker | `10000`                                |
| `status-list-circuit-breaker-failure-threshold` | Number of failures/timeouts before opening the circuit breaker                                                          | `5`                                    |
| `status-list-mandatory`                   | If true, publication failures block issuance; if false, failures are logged and issuance continues without a status claim | `false`                                |
| `status-list-max-entries`                 | Maximum number of entries to publish under the same status list                                                           | `10000`                                |

## Installation

1. Build the plugin using Maven:
    ```bash
    ./mvnw clean package
    ```
2. Copy the resulting JAR file `target/keycloak-token-status-plugin-1.0.0-SNAPSHOT.jar` to Keycloak's `providers`
   directory.

3. Restart Keycloak to load the plugin.

4. Configure the plugin using the realm attributes described in
   the [Configuration Properties Section](README.md#configuration-properties)

### Releases on Maven Central

The plugin is officially published
to [Maven Central](https://central.sonatype.com/artifact/io.github.adorsys-gis/keycloak-token-status-plugin).

Releases are fully automated via GitHub Actions. A new deployment is triggered whenever a version tag (`vX.Y.Z`)
is created on the repository. The workflow requires the following secrets to be configured:

| Secret                   | Description                                               |
|:-------------------------|:----------------------------------------------------------|
| `CENTRAL_TOKEN_USERNAME` | The Maven Central token username.                         |
| `CENTRAL_TOKEN_PASSWORD` | The Maven Central token password.                         |
| `GPG_PRIVATE_KEY`        | The ASCII-armored private key used for signing artifacts. |
| `GPG_PASSPHRASE`         | The passphrase required to unlock the GPG private key.    |

### Configuring Keycloak's credential issuance to use the Status List protocol mapper

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

- The plugin performs HTTP requests using the bundled HTTP clients; calls are synchronous (blocking) in the current
  implementation and execute on the caller's thread.
- **No retry mechanism** is used by default (retry count = 0) to ensure fast failure and avoid prolonged thread
  blocking. Some internal clients include retry strategies but the default configuration disables retries.
- Timeouts are configurable via `status-list-issuance-timeout` (default: 10s for both connection and read operations).
  A non-positive timeout value effectively disables the circuit breaker.

## Security Features

- Secure communication using TLS 1.2/1.3
- Bearer token authentication support for the status list server

## Revocation Protocol

Revocation requires a pre-issued server challenge to ensure proper Verifiable Presentation (VP) verification.
Before submitting a revocation request, clients must first obtain a challenge from the `/revoke/challenge` endpoint.
This challenge includes a cryptographically strong nonce, the audience (revocation endpoint URL), and an
expiration timestamp.

The revocation plugin strictly validates the incoming VP against these server-issued values:

- The `nonce` in the VP must exactly match the issued nonce. It must neither be expired nor replayed (it is a one-time
  use value).
- The `aud` (audience) in the VP must exactly match the configured revocation endpoint URL.

After obtaining the challenge, the next step is to submit the prepared SD-JWT VP token of the credential to the
`/revoke` endpoint. The request payload must include both the token (as authorization bearer token) and a body payload
indicating the `credential_revocation` mode and a revocation reason. For example:

```json
{
  "mode": "credential_revocation",
  "reason": "some reason"
}
```

The `mode` parameter is required to ensure that the plugin’s credential revocation logic is used instead of Keycloak’s
default revocation behavior.

## Development and Testing

### Running Tests and Formatting

To check code formatting (Spotless), use:

```bash
./mvnw spotless:check
```

To automatically remove unused imports, use:

```bash
./mvnw spotless:apply
```

To run tests:

```bash
./mvnw test
```

### Integration Testing with a Status List Server

For manual testing with a local status list server:

1. Configure the `status-list-server-url` to point to your test server
2. Enable debug logging to see detailed request/response information

## TODO

- Improve test coverage (StatusListService, RevocationEndpoint, NonceCacheService)
- Ensure nonce cache logic is compatible with clustered environments
- Document the plugin's HTTP endpoints and expected request/response formats in more detail
- Improve realm registration robustness. Consider implementing a background retry task or lazy registration to make up
  for potential transient failures during startup, maybe due to network issues or the status list server being
  temporarily unavailable.

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-only).
See [LICENSE](./LICENSE) for details.
