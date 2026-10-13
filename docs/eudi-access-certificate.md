# Configure EUDI Access and Registration Certificates for OID4VCI Metadata

## Scope

This guide shows how to configure Keycloak to sign OID4VCI Credential Issuer Metadata with a private key associated with an EUDI access certificate and to publish the matching registration certificate in the `issuer_info` claim of that metadata. It covers:

- The access certificate used for metadata signing.
- The registration certificate advertised through `issuer_info`.

Both certificates are assumed to be already obtained. The procedure for obtaining them from the German EUDI Wallet Sandbox Registrar is documented in [Obtaining access and registration certificates from the German EUDI Wallet Sandbox](https://github.com/ADORSYS-GIS/keycloak-oid4vp-plugin/blob/main/docs/modules/ROOT/pages/obtaining-sandbox-access-and-registration-certificates.adoc). That guide focuses mainly on the verifier side; the issuer steps are briefly covered at the end.

## Prerequisites

- A Keycloak realm with OID4VCI configured.
- The EUDI access certificate and the matching private key. The private key must correspond to the public key in the certificate.
- The registration certificate: a signed `registration_cert` JWT issued for the organization.
- Any issuing intermediate certificates and the self-signed root certificate.
- A supported signing algorithm matching the key. The example below uses an EC P-256 certificate and `ES256`.

Do not put private keys, keystores, or passwords in source control.

## Create a PKCS#12 keystore

Prepare these files:

- `access-certificate.pem`: the EUDI access certificate (leaf certificate).
- `access-certificate.key`: its matching private key.
- `issuer-chain.pem`: intermediate certificate(s), followed by the self-signed root certificate.

Create a PKCS#12 file. OpenSSL prompts for an export password; protect it and use the corresponding values when configuring Keycloak.

```bash
openssl pkcs12 -export \
  -name oid4vci-issuer \
  -inkey access-certificate.key \
  -in access-certificate.pem \
  -certfile issuer-chain.pem \
  -out oid4vci-issuer.p12
```

The key alias (`oid4vci-issuer` in this example) identifies the private-key entry and its associated certificate chain.

Include every issuing intermediate and the self-signed root certificate in `issuer-chain.pem`. Keycloak needs the complete chain to validate the configured certificate path; otherwise, it rejects the provider with `Certificate error on server. Path does not chain with any of the trust anchors`.

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

## Publish the registration certificate in `issuer_info`

The Credential Issuer Metadata advertises the registration certificate through the top-level `issuer_info` claim. The claim value is a JSON array of elements, each pairing a `format` string with a `data` payload; the registration certificate JWT is published with the format `registration_cert`.

Store the JSON array in the `oid4vci.issuer_info` realm attribute:

```json
[
  {
    "format": "registration_cert",
    "data": "<registration-cert-jwt>"
  }
]
```

In the Admin Console, go to **Realm Settings** > **Tokens** > **OID4VCI Attributes** and paste the JSON array into the **Issuer info** field. Alternatively, update the realm attribute through the Admin REST API:

```bash
REGISTRATION_CERT_JWT='<registration-cert-jwt>'

curl --fail --silent --show-error \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://<keycloak-host>/admin/realms/<realm-name>" \
  --output realm.json

jq --arg info "[{\"format\":\"registration_cert\",\"data\":\"$REGISTRATION_CERT_JWT\"}]" \
  '.attributes["oid4vci.issuer_info"] = $info' \
  realm.json \
  | curl --fail --silent --show-error \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -H "Content-Type: application/json" \
      -X PUT \
      "https://<keycloak-host>/admin/realms/<realm-name>" \
      --data @-
```

The realm attribute holds the serialized JSON array as a single string.

An invalid value is logged and the claim is omitted from the metadata; it does not break the metadata endpoint.

## Request the issuer metadata

The issuer metadata endpoint serves two representations, selected through the `Accept` header: `application/json` returns the unsigned JSON document, and `application/jwt` returns the signed metadata JWT.

```bash
curl --fail --silent --show-error \
  -H 'Accept: application/json' \
  'https://<keycloak-host>/.well-known/openid-credential-issuer/realms/<realm-name>' \
  --output issuer-metadata.json

curl --fail --silent --show-error \
  -H 'Accept: application/jwt' \
  'https://<keycloak-host>/.well-known/openid-credential-issuer/realms/<realm-name>' \
  --output issuer-metadata.jwt
```

Replace the host and realm placeholders with the deployed Keycloak values. When testing against a local deployment with a self-signed certificate, add `-k` to skip TLS verification. The JWT response should be a signed JWT; its protected header contains the signing algorithm and the `x5c` certificate chain.

Both representations carry the same `issuer_info` claim. To inspect it without saving files first, request the metadata and extract the claim in one pipeline:

```bash
curl --fail --silent --show-error \
  -H 'Accept: application/json' \
  'https://<keycloak-host>/.well-known/openid-credential-issuer/realms/<realm-name>' \
  | jq '.issuer_info'

curl --fail --silent --show-error \
  -H 'Accept: application/jwt' \
  'https://<keycloak-host>/.well-known/openid-credential-issuer/realms/<realm-name>' \
  | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq '.issuer_info'
```

The JWT payload is base64url-encoded: `tr '_-' '/+'` maps it to the standard base64 alphabet, and `2>/dev/null` suppresses the missing-padding warning of `base64 -d`.

## Inspect the `x5c` header

The signed JWT representation is the one to verify against the EUDI access certificate. Decode it with a JWT debugger, and inspect its protected header. Do not provide private keys, keystores, or passwords to a debugger.

Check the `alg` value and the `x5c` certificate chain. The first certificate must be the EUDI access certificate; any required intermediate certificates follow it. In Keycloak 26.8.0, a trailing self-signed root is not included in `x5c`.

Decoding a JWT only exposes its contents. Verify the signature separately before relying on the metadata.

## References

- [ETSI TS 119 472-3](https://www.etsi.org/deliver/etsi_ts/119400_119499/11947203/): `issuer_info` and registration certificates for trusted issuers
- [Obtaining access and registration certificates from the German EUDI Wallet Sandbox](https://github.com/ADORSYS-GIS/keycloak-oid4vp-plugin/blob/main/docs/modules/ROOT/pages/obtaining-sandbox-access-and-registration-certificates.adoc)
- [Keycloak Server Administration Guide: loading keys from a Java keystore](https://www.keycloak.org/docs/26.8.0/server_admin/)
