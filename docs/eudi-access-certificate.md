# Configure EUDI Access Certificate Signing for OID4VCI Metadata

## Scope

This guide shows how to configure Keycloak to sign OID4VCI Credential Issuer Metadata with an EUDI access certificate and how to inspect the resulting signed metadata JWT. It covers the access certificate used for metadata signing. Publishing a provider registration certificate in `issuer_info` is outside the scope of this guide.

## Prerequisites

- A Keycloak realm with the OID4VCI issuer configured.
- The EUDI access certificate and the matching private key. The private key must correspond to the public key in the certificate.
- Any issuing intermediate certificates and, if needed for Keycloak's certificate-path validation, the self-signed root certificate.
- A supported signing algorithm matching the key. The example below uses an EC P-256 certificate and `ES256`.

Do not put private keys, keystores, or passwords in source control.

## Create a PKCS#12 keystore

Prepare these files:

- `access-certificate.pem`: the EUDI access certificate (leaf certificate).
- `access-certificate.key`: its matching private key.
- `issuer-chain.pem`: intermediate certificate(s), followed by the self-signed root certificate when required.

Create a PKCS#12 file. OpenSSL prompts for an export password; protect it and use the corresponding values when configuring Keycloak.

```bash
openssl pkcs12 -export \
  -name oid4vci-issuer \
  -inkey access-certificate.key \
  -in access-certificate.pem \
  -certfile issuer-chain.pem \
  -out oid4vci-issuer.p12
```

The key alias (`oid4vci-issuer` in this example) must identify the private-key entry and its associated certificate chain.

## Configure the Keycloak Java keystore provider

Place the keystore in a realm-specific directory. By default, Keycloak looks under `${kc.home.dir}/data/<realm-name>/`; the parent directory can be changed with `spi-keys--java-keystore--keystores-path`. Ensure the file is mounted and readable by the Keycloak process. A relative keystore path is resolved from the realm-specific directory.

In the Admin Console, select **Realm Settings** > **Keys** > **Providers**, add a **java-keystore** provider, and set:

| Setting           | Example                                                                     |
| ----------------- | --------------------------------------------------------------------------- |
| Keystore          | `oid4vci-issuer.p12`                                                        |
| Keystore Password | The PKCS#12 export password                                                 |
| Keystore Type     | `PKCS12`                                                                    |
| Key Alias         | `oid4vci-issuer`                                                            |
| Key Password      | The private-key password (may be the same as the keystore password)         |
| Algorithm         | `ES256`                                                                     |
| Key Use           | `sig`                                                                       |
| Priority          | Choose a priority that makes this the active key for the selected algorithm |

Enable the provider and make it active. The configured key algorithm must match the key type.

Then, in **Realm Settings** > **Tokens** > **OID4VCI Attributes**, set `oid4vci.signed_metadata.alg` to the same algorithm (for example, `ES256`).

## Request signed issuer metadata

Request the issuer metadata endpoint with `Accept: application/jwt`:

```bash
curl --fail --silent --show-error \
  -H 'Accept: application/jwt' \
  'https://<keycloak-host>/.well-known/openid-credential-issuer/realms/<realm-name>' \
  --output issuer-metadata.jwt
```

Replace the host and realm placeholders with the deployed Keycloak values. The response should be a signed JWT; its protected header contains the signing algorithm and the `x5c` certificate chain.

## Inspect the `x5c` header

The response is a signed JWT. Decode it with a JWT debugger, and inspect its protected header. Do not provide private keys, keystores, or passwords to a debugger.

Check the `alg` value and the `x5c` certificate chain. The first certificate must be the EUDI access certificate; any required intermediate certificates follow it. In Keycloak 26.8.0, a trailing self-signed root is not included in `x5c`.

Decoding a JWT only exposes its contents. Verify the signature separately before relying on the metadata.

## Certificate-chain requirements

Keycloak validates the certificate path configured in its Java keystore provider. Include the access certificate, its matching private key, and every intermediate or trust-anchor certificate required to validate that path.

If a required trust anchor is absent, Keycloak rejects the provider configuration with:

```text
Certificate error on server. Path does not chain with any of the trust anchors
```

With Keycloak 26.8.0, a trailing self-signed root can remain in the keystore for certificate-path validation but is omitted from the signed metadata JWT's `x5c` header. Do not remove a root that Keycloak requires for validation merely to change the published header.

## References

- [Keycloak Server Administration Guide: loading keys from a Java keystore](https://www.keycloak.org/docs/26.8.0/server_admin/)
