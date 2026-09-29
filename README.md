# Keycloak Token Status Plugin

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

A [Keycloak](https://www.keycloak.org) plugin that reports the status of verifiable credentials to an external
status list server, so you can revoke a credential before it expires, for example when it is compromised or must
be invalidated for compliance reasons.

## Features

- Reports credential status to an external status list server
- Revokes issued verifiable credentials through a dedicated endpoint

## Compatibility

This plugin has been tested and verified to work with:

| Component | Version |
| --------- | ------- |
| Keycloak  | 26.7.2  |

It works with any status list server that implements both the
[OAuth 2.0 Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list) format and the management API
used by this plugin, such as the [status list server](https://github.com/adorsys/status-list-server) project. A public
instance is available at `https://statuslist.eudi-adorsys.com`.

## Getting started

### Installation

Prerequisite: Java 17 or later.

1. Build the plugin:

   ```bash
   ./mvnw clean package -DskipTests
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

Enabling these attributes alone is not sufficient. The status claim is only emitted after the
`oid4vc-status-list-claim-mapper` protocol mapper is attached to the client scope of the credential
configuration you want to publish. See [Enabling the Status List protocol mapper](./docs/technical-reference.md#enabling-the-status-list-protocol-mapper) for details.

The full list of configuration properties is documented in the
[technical reference](./docs/technical-reference.md#configuration-properties).

### Revoking a credential

A client application can revoke an issued credential through the plugin's `/revoke` endpoint, which sets the credential's status to `INVALID` so it can no longer be used. The request requires a bearer access token, `mode=issued_credential_revocation`, and the `credential_id` of the credential to revoke.

See the [technical reference](./docs/technical-reference.md#revoke-an-issued-credential) for the full request and response details.

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
