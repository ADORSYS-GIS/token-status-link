2. Navigate to your realm
3. Go to **Realm Settings** → **Events**
4. In the **Event Listeners** field, add `token-status-event-listener`
5. Click **Save**

### Configure the Status List Service

You can configure the plugin using realm attributes. Here's how to set them:

1. Use the Keycloak Admin CLI to set realm attributes:

```bash
# Enable the status list service
/path/to/keycloak/bin/kcadm.sh update realms/your-realm -s 'attributes.status-list-enabled=true'

# Set status list server URL
/path/to/keycloak/bin/kcadm.sh update realms/your-realm -s 'attributes.status-list-server-url=https://your-statuslist-server.com/api/v1/status'

# Set authentication token
/path/to/keycloak/bin/kcadm.sh update realms/your-realm -s 'attributes.status-list-auth-token=your-secret-token'

# Set connection timeout (in milliseconds)
/path/to/keycloak/bin/kcadm.sh update realms/your-realm -s 'attributes.status-list-connect-timeout=5000'

# Set read timeout (in milliseconds)
/path/to/keycloak/bin/kcadm.sh update realms/your-realm -s 'attributes.status-list-read-timeout=5000'

# Set retry count
/path/to/keycloak/bin/kcadm.sh update realms/your-realm -s 'attributes.status-list-retry-count=3'
```

## Configuration Properties

| Property | Description | Default Value |
|----------|-------------|---------------|
| `status-list-enabled` | Enables or disables the status list service | `false` |
| `status-list-server-url` | URL of the status list server | `http://localhost:8090/api/v1/token-status` |
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
  "issuedAt": "2023-06-01T10:15:30Z",
  "expiresAt": "2023-06-01T11:15:30Z",
  "revokedAt": "2023-06-01T10:45:30Z",
  "issuer": "realm-name",
  "clientId": "client-id"
}
```

## Status List Server Requirements

Your status list server should implement an API endpoint that accepts POST requests with the JSON payload described above. The endpoint should:

1. Validate the request (check Authentication header if configured)
2. Process and store the token status information
3. Return an HTTP 200-299 status code on success

## Development

### Building the Plugin

```bash
mvn clean package
```

### Running Tests

```bash
mvn test
```

## Troubleshooting

Check the Keycloak server logs for messages from the plugin. All plugin logs use the following format:

```
[com.yourcompany.keycloak.statuslist.*] Message
```

Common issues:

1. **Plugin not loading**: Ensure the JAR file is in the correct Keycloak providers directory
2. **Event listener not triggered**: Verify that you've added the event listener to the realm settings
3. **Connection failures**: Check that the status list server URL is correct and accessible from the Keycloak server

## License

[Apache License 2.0](LICENSE)