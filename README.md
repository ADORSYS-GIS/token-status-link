# Keycloak Token Status Plugin

This plugin integrates with Keycloak to publish token status information to a statuslist server. The plugin listens for token-related events (login, logout, token refresh, etc.) and sends the token status to a configurable external server.

## Features

- Track token lifecycle events (issuance, refresh, revocation)
- Publish token status to an external status list server
- update token status 
- Configurable connection parameters
- Retry mechanism for failed publishing attempts
- Support for authentication with the status list server

## Configuration Properties

| Property | Description | Default Value |
|----------|-------------|---------------|
| `status-list-enabled` | Enables or disables the status list service | `false` |
| `status-list-server-url` | URL of the status list server | `https://statuslist.eudi-adorsys.com/` |
| `status-list-auth-token` | Authentication token for the status list server | (empty) |
| `status-list-connect-timeout` | Connection timeout in milliseconds | `5000` |
| `status-list-read-timeout` | Read timeout in milliseconds | `5000` |
| `status-list-retry-count` | Number of retry attempts | `3` |

## Payload Format

The plugin sends token status information to the status list server in the following JSON format:

```json
{
  "tokenId": "unique-token-identifier",
  "userId": "keycloak-user-id",
  "status": "ACTIVE|REVOKED|EXPIRED",
  "issuedAt": "2025-06-01T10:15:30Z",
  "expiresAt": "2025-06-01T11:15:30Z",
  "revokedAt": "2025-06-01T10:45:30Z",
  "issuer": "realm-name",
  "clientId": "client-id"
}
```

### Building the Plugin

```bash
mvn clean package
```

### Running Tests

```bash
mvn test
```
