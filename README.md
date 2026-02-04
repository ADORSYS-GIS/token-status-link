# Keycloak Token Status Plugin

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
- Proper handling of realm public keys and signing algorithms

## Configuration Properties

The plugin can be configured at the realm level with the following properties:

| Property                          | Description                                 | Default Value                          |
|-----------------------------------|---------------------------------------------|----------------------------------------|
| `status-list-enabled`             | Enables or disables the status list service | `true`                                 |
| `status-list-server-url`          | URL of the status list server               | `https://statuslist.eudi-adorsys.com/` |
| `status-list-token-issuer-prefix` | Prefix for building the Token Issuer ID     | `Generated UUID`                       |

## Token Status Record Format

The plugin sends token status information to the status list server in the following JSON format, compliant with the
OAuth 2.0 Status List specification:

```json
{
  "sub": "unique-token-identifier",
  "iss": "realm-name",
  "issuer": "realm-name",
  "public_key": "realm-public-key",
  "alg": "RS256",
  "status": 0,
  "iat": 1717006530,
  "exp": 1717010130,
  "revoked_at": 1717008330,
  "type": "oauth2",
  "status_reason": "Client: client-id, User: user-id, Reason: Token revoked"
}
```

### Fields Explanation

- `sub`: The token identifier (credential ID)
- `iss`: The issuer identifier (realm name)
- `issuer`: The issuer name (realm name)
- `public_key`: The realm's public key used for token verification
- `alg`: The signing algorithm used (e.g., RS256)
- `status`: Token status (0 = VALID, 1 = REVOKED)
- `iat`: Issued at timestamp (seconds since epoch)
- `exp`: Expiration timestamp (seconds since epoch)
- `revoked_at`: Revocation timestamp for revoked tokens (seconds since epoch)
- `type`: Credential type, always "oauth2" for this plugin
- `status_reason`: Human-readable explanation of token status, including client and user IDs

## Installation

1. Build the plugin using Maven:
    ```bash
    ./mvnw clean package
    ```
2. Copy the resulting JAR file `target/keycloak-token-status-plugin-1.0.0-SNAPSHOT.jar` to Keycloak's `providers` directory.

3. Restart Keycloak to load the plugin.

4. Configure the plugin using the realm attributes described in the [Configuration Properties Section](README.md#configuration-properties)

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
- Connection and read timeouts are **fixed at safe defaults** (30s connect, 60s read) to prevent hanging connections.

## Security Features

- Secure communication using TLS 1.2/1.3
- Bearer token authentication support for the status list server
- Proper handling of Keycloak's realm public keys and algorithms
- No sensitive information is logged beyond what's necessary for debugging

## Revocation Protocol

Revocation now requires a pre-issued server challenge to ensure proper LDP-compliant Verifiable Presentation (VP) verification. Before submitting a revocation request, clients must first obtain a challenge from the `/challenge` endpoint. This challenge includes a cryptographically strong nonce, the audience (revocation endpoint URL), and an expiration timestamp.

The revocation plugin strictly validates the incoming VP against these server-issued values:

- The `nonce` in the VP must exactly match the issued nonce.
- The `aud` (audience) in the VP must exactly match the configured revocation endpoint URL.
- The `nonce` must not be expired.
- The `nonce` must not be replayed (it is a one-time use value).

Failure to meet these validation requirements will result in specific error responses:

- `400 Bad Request`: For malformed VPs or invalid challenge parameters.
- `401 Unauthorized`: For invalid holder proofs (e.g., incorrect nonce, audience mismatch, expired or replayed nonce).

**Retry policy:** The plugin does **not** retry revocation requests. A nonce is single-use and is consumed on the first
attempt. On failure, clients must request a **new challenge** and repeat the flow.

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

### TODO

- Unify HTTP interaction with the status list server in the dedicated `StatusListService` class.
- Improve persistence layer as the plugin interacts with the database.
- Drop unnecessary configuration properties.
- Implement HTTP retry strategy within the framework of the HTTP client library, not manually. For readability.
- Clean up dependencies.
