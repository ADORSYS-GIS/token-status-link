# Keycloak Token Status Plugin

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

A [Keycloak](https://www.keycloak.org) plugin that reports the status of long-lived tokens and verifiable
credentials to an external [OAuth 2.0 Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list)
server.

This lets you revoke a credential before it expires, for example when it is compromised or must be
invalidated for compliance reasons.

## Features

- Reports token and credential status to an external status list server
- Supports `VALID`, `INVALID` and `SUSPENDED` statuses
- Revokes issued verifiable credentials through a dedicated endpoint

## Getting started

### Requirements

- Keycloak 26.x
- Java 17

### Installation

1. Build the plugin:

   ```bash
   ./mvnw clean package
   ```

2. Copy the resulting JAR from `target/keycloak-token-status-plugin-*.jar` into Keycloak's
   `providers` directory.

3. Restart Keycloak.

The plugin is also published on [Maven Central](https://central.sonatype.com/artifact/io.github.adorsys-gis/keycloak-token-status-plugin).

### Configuration

Enable the plugin for a realm and point it at your status list server using these realm attributes:

| Attribute                | Description                                   |
| ------------------------ | --------------------------------------------- |
| `status-list-enabled`    | Enables the status list service for the realm |
| `status-list-server-url` | URL of the status list server                 |

Attach the `oid4vc-status-list-claim-mapper` protocol mapper to the client scope of the credential
configuration you want to publish.

### Revoking a credential

A client application can revoke an issued credential through the plugin's `/revoke` endpoint, which
sets the credential's status to `INVALID` so it can no longer be used.

## Demo

This plugin can be combined with the [OpenID4VP plugin](https://github.com/ADORSYS-GIS/keycloak-oid4vp-plugin),
the [status list server](https://github.com/adorsys/status-list-server) and the
[Mock FE](https://github.com/ADORSYS-GIS/keycloak-oid4vc-mock-fe) app to build an end-to-end credential
revocation demo. A step-by-step setup guide is available in
[docs/credential-revocation-demo/setup.md](./docs/credential-revocation-demo/setup.md).

## Development

```bash
./mvnw test            # run tests
./mvnw spotless:check  # verify formatting
./mvnw spotless:apply  # fix formatting
```

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-only).
See [LICENSE](./LICENSE) for details.
