# Revoking credentials by leveraging a Status List Server

Credential revocation is a critical feature for maintaining trust and security in decentralized identity systems. The
Token Status List specification defines a robust mechanism for revoking issued credentials, ensuring that once a
credential is revoked, it cannot be used for future presentations. This guide documents the setup and configuration of
the components we developed to demonstrate credential revocation in practice.

## Contents

- [User journey](#user-journey)
- [Overview of components](#overview-of-components)
- [Configuration of components](#configuration-of-components)
    - [Demo app](#demo-app)
    - [Wallet](#wallet)
    - [Keycloak](#keycloak)
        - [Token Status plugin](#token-status-plugin)
        - [OpenID4VP plugin](#openid4vp-plugin)
    - [Status List Server](#status-list-server)
- [Closing thoughts](#closing-thoughts)

## User journey

A demo application delegates user authentication to Keycloak. The app allows users to obtain a verifiable credential (
VC) and supports authentication either via username/password or by presenting a previously issued credential.

The user journey is as follows:

- The user logs in to the demo app (via Keycloak) using a username and password.
- The user retrieves an Identity VC to their wallet and logs out.
- The user logs back in to the app (via Keycloak) by presenting the VC, then logs out again.
- The user requests revocation of the VC from their wallet.
- The user is no longer able to log in to the app using the now-revoked VC.

Below is a video recording demonstrating this user journey, end to end:

[Download the demo video](assets/keycloak-oid4vp-auth+revocation-260302.webm)

## Overview of components

The following diagram illustrates the high-level architecture and interactions between the main components involved in a
credential revocation demo for the above user journey:

![Components for Credential Revocation](assets/overview.png)

The environment comprises the following main components:

- **Demo app**: An application that leverages Keycloak for user authentication.
- **Wallet**: Allows users to receive, store, and present verifiable credentials.
- **Keycloak**: Configured for credential issuance and extended with custom plugins to support both credential
  revocation and OpenID4VP authentication.
    - Token Status plugin: Connects to the Status List Server to enable revocation functionality.
    - OpenID4VP plugin: Facilitates user authentication through verifiable credential presentation.
- **Status List Server**: Maintains and serves status lists for checking the validity of credentials.

## Configuration of components

The demo app and the wallet do not require any uncommon configuration. We'll cover them briefly but our main focus will
be on Keycloak and the Status List Server.

### Demo app

A suitable demo app is one that uses Keycloak for authentication and that can initiate the OpenID4VCI flow to display a
credential offer QR code. Our [Mock FE](https://github.com/ADORSYS-GIS/keycloak-oid4vc-mock-fe) application satisfies
these requirements. Latest tested
commit: https://github.com/ADORSYS-GIS/keycloak-oid4vc-mock-fe/tree/34d10f231beebff91f0d9681e6a2c3d358b9a295.

Check the README and create a `.env` file with the appropriate configuration to connect the app to your Keycloak
instance. Here is a sample configuration for reference:

```env
VITE_KEYCLOAK_URL=http://localhost:8080
VITE_KEYCLOAK_REALM=oid4vc-vci
VITE_KEYCLOAK_CLIENT_ID=oid4vc-demo-public
VITE_OID4VC_DEFAULT_CREDENTIAL_CONFIGURATION_ID=IdentityCredential
```

![Screenshot of our MOCK FE demo app](assets/demo-app-mock-fe.png)

### Wallet

We developed a [wallet](https://github.com/adorsys/eudiw-app) supporting revocation for testing purposes. An online
instance is available at https://adorsys.github.io/eudiw-app. However, that can't work with a Keycloak instance running
locally due to a proxy handling all HTTP calls. With a local Keycloak, you need to start the wallet locally as well.
Latest tested commit: https://github.com/adorsys/eudiw-app/tree/a446d3edbfc9db066a13d6a41937d6fe446640fc.

Make sure no proxy is configured in the `.env` file as you start the wallet.

```env
NX_PROXY_SERVER=''
```

If you happen to run into CORS issues, consider starting your browser with CORS disabled for demo purposes.

```sh
google-chrome --disable-web-security
```

### Keycloak

Keycloak natively supports OpenID4VCI for credential issuance. All standard documentations on how to configure
OpenID4VCI in Keycloak apply. The OAuth SIG maintains an OpenID4VCI deployment project that you may find
useful: https://github.com/keycloak/keycloak-oauth-sig/tree/db7f6125a8b8ba1f3305f9f83db3853f9c689d35/oid4vci-deployment.
The link directly points to the latest tested commit.

Because of known issues with self-signed certificates, we recommend starting Keycloak without HTTPS locally. Of course,
this is not a requirement for production environments. Here is a sample configuration to use in your
`config.override.yml` file:

```yaml
keycloak:
  version: "26.5.3"
database:
  opts: "--db postgres --db-url jdbc:postgresql://localhost:5432/keycloak_demo --db-username admin --db-password admin"
keycloak_endpoints:
  admin_addr: "http://localhost:8080"
keystore:
  path: "${PROJECT_TARGET_DIR}/kc_keystore.pkcs12"
start_command: "start-dev --log-level=INFO,com.adorsys.keycloakstatuslist:DEBUG,de.adorsys.gis:DEBUG"
```

Keycloak must be started with two plugins: a Token Status and an OpenID4VP plugin. The plugins require some
configuration, which is documented below. As usual, download the `jar` files for the plugins from the indicated sources
and place them in the `providers` directory of your Keycloak installation.

For reference, these versions of Keycloak and the plugins have been successfully tested and confirmed to be compatible:

| Component           | Version | Source                                                                    |
|---------------------|---------|---------------------------------------------------------------------------|
| Keycloak            | 26.5.3  | https://www.keycloak.org/archive/downloads-26.5.3.html                    |
| Token Status plugin | 0.1.0   | https://github.com/ADORSYS-GIS/token-status-link/releases/tag/v0.1.0      |
| OpenID4VP plugin    | 1.0.1   | https://github.com/ADORSYS-GIS/keycloak-oid4vp-plugin/releases/tag/v1.0.1 |

Minimal commands to start, then config Keycloak with the OpenID4VCI deployment project:

```sh
./keycloak-ssi.sh setup
# In another terminal...
./keycloak-ssi.sh config
```

We explicitly recommend using a persistent database because a restart is required after the configuration command.

#### Token Status plugin

The plugin integrates with a Status List Server. The URL of the server is configurable as a realm attribute. It must be
accessible via HTTPS.

```json
{
  "status-list-server-url": "https://statuslist.example.com"
}
```

Additionally, revocable credential types must explicitly configure the mapping of a status claim. Add the `status` claim
to the list of visible claims and configure the Status List protocol mapper as shown below:

```json
{
  "attributes": {
    "vc.credential_build_config.sd_jwt.visible_claims": "id,iat,nbf,exp,jti,status"
  },
  "protocolMappers": [
    {
      "name": "status-list-claim-mapper",
      "protocol": "oid4vc",
      "protocolMapper": "oid4vc-status-list-claim-mapper",
      "config": {}
    }
  ]
}
```

The above configuration is sufficient to enable using the plugin. For additional options and advanced settings, refer to
the [plugin documentation](https://github.com/ADORSYS-GIS/token-status-link).

#### OpenID4VP plugin

To enable login via verifiable credential presentation, you must activate a login theme that supports OpenID4VP. The
plugin provides a minimal theme named `keycloak.v2+oid4vp`.

![Select OpenID4VP login theme](assets/select-oid4vp-login-theme.png)

In addition, the SD-JWT authenticator in the new `oid4vp auth` flow must be configured to accept specific credential
types and to reject revoked credentials.

![Configure SD-JWT authenticator](assets/configure-sdjwt-authenticator.png)

For additional details, refer to
the [plugin documentation](https://github.com/ADORSYS-GIS/keycloak-oid4vp-plugin?tab=readme-ov-file#documentation-site-antora).

### Status List Server

The Token Status plugin pairs with the REST interface implemented by this open source Status List
Server: https://github.com/adorsys/status-list-server. Documentation on how to configure and spin up an instance of the
server is available on the GitHub repository. It must be accessible via HTTPS.

For demonstration purposes, you can use the public instance at: https://statuslist.eudi-adorsys.com.

## Closing thoughts

This guide has outlined the essential steps to set up and demonstrate credential revocation using Keycloak and a Status
List Server. By following these instructions, you can explore the full lifecycle of verifiable credentials in a
practical environment, from issuance to revocation. For further customization and advanced scenarios, consult the
documentation of each component and experiment with different configurations to best fit your needs.
