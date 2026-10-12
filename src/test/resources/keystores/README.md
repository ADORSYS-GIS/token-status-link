# Test signing keystore for OID4VCI (Keycloak 26.8+)

A ready-to-use EC P-256 signing keystore for integration tests. The private key
certificate is signed by a dedicated test CA (not self-signed), which Keycloak
26.8 requires for the SD-JWT `x5c` header (HAIP-6.1.1).

## Files

| File           | Description                                                      |
| -------------- | ---------------------------------------------------------------- |
| `keystore.p12` | PKCS#12 keystore: `oid4vci-issuer` key + chain `[leaf, test CA]` |

## Credentials

- **Keystore password:** `password`
- **Key alias:** `oid4vci-issuer`
- **Key password:** `password`
- **Keystore type:** `PKCS12`
- **Algorithm:** `ES256` (EC curve `prime256v1` / P-256)

> Test-only credentials. Never use them in production.
