# Keycloak Token Status Plugin

This plugin integrates with Keycloak to publish token status information to a status list server. The plugin listens for long-lived token revocation events (e.g., REVOKE_GRANT) and sends the token status to a configurable external server that implements the OAuth 2.0 Status List pattern.

## Features

- Track long-lived token revocation events
- Publish token status to an external status list server
- Support for different token statuses (VALID, REVOKED)
- Configurable connection parameters with sensible defaults
- Robust retry mechanism for failed publishing attempts with exponential backoff
- Secure communication with TLS 1.2/1.3
- Support for authentication with the status list server
- Detailed logging with unique request IDs for better traceability
- Proper handling of realm public keys and signing algorithms

## Configuration Properties

The plugin can be configured at the realm level with the following properties:

| Property | Description | Default Value |
|----------|-------------|---------------|
| `status-list-enabled` | Enables or disables the status list service | `true` |
| `status-list-server-url` | URL of the status list server | `https://statuslist.eudi-adorsys.com/` |
| `status-list-auth-token` | Authentication token for the status list server | (empty) |
| `status-list-connect-timeout` | Connection timeout in milliseconds | `5000` |
| `status-list-read-timeout` | Read timeout in milliseconds | `5000` |
| `status-list-retry-count` | Number of retry attempts for failed requests | `3` |

## Supported Events

The plugin processes the following Keycloak events:

- REVOKE_GRANT

## Token Status Record Format

The plugin sends token status information to the status list server in the following JSON format, compliant with the OAuth 2.0 Status List specification:

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
mvn clean package
```

2. Copy the resulting JAR file from `target/keycloak-token-status-plugin-1.0.0-SNAPSHOT.jar` to Keycloak's `providers` directory.

3. Restart Keycloak to load the plugin.

4. Enable the event listener in your Keycloak realm:
   - Navigate to the Realm Settings
   - Go to Events tab
   - Add "token-status-event-listener" to the Event Listeners

5. Configure the plugin using the realm attributes described in the Configuration Properties section above.

## Performance Considerations

- The plugin performs non-blocking HTTP requests to minimize impact on Keycloak performance
- Failed requests are retried with exponential backoff (1s, 2s, 3s, etc.)
- Connection and read timeouts are configurable to prevent hanging connections

## Security Features

- Secure communication using TLS 1.2/1.3
- Bearer token authentication support for the status list server
- Proper handling of Keycloak's realm public keys and algorithms
- No sensitive information is logged beyond what's necessary for debugging

## Development and Testing

### Running Tests

```bash
mvn test
```

### Integration Testing with a Status List Server

For manual testing with a local status list server:

1. Configure the `status-list-server-url` to point to your test server
2. Set the appropriate `status-list-auth-token` if required
3. Enable debug logging to see detailed request/response information
