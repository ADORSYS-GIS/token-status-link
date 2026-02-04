# Token Status List Specification Summary

> This document summarizes the Token Status List specification in an easy-to-understand way.

📄 **Source Specification**: [IETF OAuth Status List Draft](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-11.html)

---

## 1. Introduction & Overview

### What is a Token Status List?

A **Token Status List** is a mechanism to track and communicate the status (e.g., valid, revoked, suspended) of many tokens efficiently. Instead of checking each token individually with the issuer, the status of thousands or millions of tokens can be encoded in a single, compact data structure.

### The Problem It Solves

When tokens (like JWTs, access tokens, or verifiable credentials) are issued, their validity can change over time — they might be revoked or suspended. Relying parties need a way to check this status without:
- Contacting the issuer for every single token validation (poor scalability)
- Revealing which specific token they're checking (privacy concern)

### Key Artifacts & Relationships

```
┌────────────────┐  describes status  ┌──────────────────┐
│  Status List   │──────────────────► │ Referenced Token │
│ (JSON or CBOR) │◄───────────────────│ (JOSE, COSE, ..) │
└─────┬──────────┘    references      └──────────────────┘
      │
      │ embedded in
      ▼
┌───────────────────┐
│ Status List Token │
│   (JWT or CWT)    │
└───────────────────┘
```

| Artifact | Description |
|----------|-------------|
| **Referenced Token** | The actual token whose status is being tracked (JWT, SD-JWT VC, CWT, mdoc, etc.) |
| **Status List** | A bit array (JSON or CBOR) where each position represents a token's status |
| **Status List Token** | The Status List wrapped in a cryptographically signed container (JWT or CWT) |

### How It Works (Simplified)

1. **At Issuance**: Each token is assigned an **index** (position in the bit array)
2. **Status Encoding**: The bit(s) at that index represent the token's current status
3. **Status Retrieval**: Anyone can fetch the Status List Token and look up the status by index

### Roles in the System

```
                    issue              present
                  Referenced          Referenced
                    Token               Token
┌────────┐        ┌────────┐         ┌───────────────┐
│ Issuer │───────►│ Holder │────────►│ Relying Party │
└───┬────┘        └────────┘         └───────┬───────┘
    │                                        │
    │ update status                          │
    ▼                                        │
┌──────────────┐                             │
│ Status Issuer│                             │
└───┬──────────┘                             │
    │ provide Status List                    │
    ▼                                        │
┌─────────────────┐    fetch Status List     │
│ Status Provider │◄─────────────────────────┘
└─────────────────┘
```

| Role | Responsibility |
|------|----------------|
| **Issuer** | Issues Referenced Tokens to Holders |
| **Status Issuer** | Creates/updates Status List Tokens (can be the Issuer or authorized delegate) |
| **Status Provider** | Hosts Status List Tokens at a public, resolvable endpoint |
| **Holder** | Receives and presents Referenced Tokens |
| **Relying Party (Verifier)** | Validates tokens and checks their status |

> 💡 **Note**: The Issuer, Status Issuer, and Status Provider roles can all be the same entity.

### Example Use Cases

1. **Access Token Management**: Instead of token introspection (contacting issuer per token), relying parties fetch one Status List for many tokens
2. **Verifiable Credentials**: Track status of credentials in the Issuer-Holder-Verifier model (SD-JWT VC)

### Why This Approach? (Rationale)

| Previous Approach | Problem |
|-------------------|---------|
| Certificate Revocation Lists (CRLs) | Limited scalability |
| OCSP (Online Certificate Status Protocol) | Privacy risk — leaks which certificate is being checked |
| OCSP Stapling | Data may be outdated |
| Accumulator-based + Zero-Knowledge Proofs | Scalability issues |
| Short-lived tokens + re-issuance | Burden on issuer infrastructure |

**Token Status List balances**: scalability, security, and privacy by:
- Minimizing status to just bits (often 1 bit per token)
- Compressing the data
- Grouping many tokens together for "herd privacy"

### Design Goals

| Goal | Description |
|------|-------------|
| **Simplicity** | Easy to understand and implement |
| **Performance** | Fast and secure implementation in any language |
| **Scalability** | Support millions of tokens (government/enterprise scale) |
| **Caching & Offline** | Enable caching policies and offline validation |
| **Format Support** | Works with JSON and CBOR tokens |
| **Extensibility** | Extension points for custom status types and mechanisms |

---

## 2. Terminology (Glossary)

| Term | Definition |
|------|------------|
| **Issuer** | Entity that issues the Referenced Token |
| **Status Issuer** | Entity that issues the Status List Token (can be same as Issuer) |
| **Status Provider** | Entity that hosts Status List Token at a public endpoint (can be same as Status Issuer) |
| **Holder** | Entity that receives tokens from Issuer and presents them to Relying Parties |
| **Relying Party (Verifier)** | Entity that validates Referenced Tokens by fetching and checking Status List Tokens |
| **Status List** | JSON/CBOR object containing a compressed byte array representing statuses of many tokens |
| **Status List Token** | JWT or CWT containing a cryptographically secured Status List |
| **Referenced Token** | A secured data structure (e.g., SD-JWT VC, ISO mdoc) with a "status" claim pointing to its Status List entry |
| **base64url** | URL-safe base64 encoding without padding (per RFC 7515) |

---

## 3. Status List Format

### 3.1 Core Concept: The Compressed Byte Array

The Status List is fundamentally a **compressed byte array** where each token's status is represented by bits at a specific index.

#### Bit Size Options

| Bits per Token | Statuses per Byte | Possible Status Values |
|----------------|-------------------|------------------------|
| **1 bit** | 8 tokens/byte | 2 values (0-1) |
| **2 bits** | 4 tokens/byte | 4 values (0-3) |
| **4 bits** | 2 tokens/byte | 16 values (0-15) |
| **8 bits** | 1 token/byte | 256 values (0-255) |

> 💡 The bit size is limited to 1, 2, 4, or 8 to keep bit manipulation within a single byte — simpler and less error-prone.

#### Algorithm to Create a Status List

```
1. CHOOSE bit size (1, 2, 4, or 8)
2. CREATE byte array: size = (number_of_tokens × bits) / 8
3. SET status values at each index (index starts at 0)
4. COMPRESS using DEFLATE with ZLIB format (highest compression recommended)
```

#### How Bits Map to Indices

- Bits are counted from **least significant bit (0)** to **most significant bit (7)**
- Index 0 starts at the LSB of byte 0

### 3.2 Example: 1-Bit Status List (16 tokens)

For 16 tokens with 1-bit statuses (just valid/revoked):

```
Statuses: [1,0,0,1,1,1,0,1,1,1,0,0,0,1,0,1]
           ↑                             ↑
        index 0                      index 15

Byte Layout:
┌─────────────────────────┐  ┌─────────────────────────┐
│  Byte 0 (indices 0-7)   │  │  Byte 1 (indices 8-15)  │
├─────────────────────────┤  ├─────────────────────────┤
│ bit: 7 6 5 4 3 2 1 0    │  │ bit: 7 6 5 4 3 2 1 0    │
│      1 0 1 1 1 0 0 1    │  │      1 0 1 0 0 0 1 1    │
│      ↑         ↑   ↑    │  │      ↑             ↑    │
│    idx7      idx1 idx0  │  │    idx15         idx8   │
├─────────────────────────┤  ├─────────────────────────┤
│      = 0xB9             │  │      = 0xA3             │
└─────────────────────────┘  └─────────────────────────┘
```

### 3.3 Example: 2-Bit Status List (12 tokens)

For 12 tokens with 2-bit statuses (valid/revoked/suspended + one more):

```
Statuses: [1,2,0,3,0,1,0,1,1,2,3,3]
           ↑                     ↑
        index 0              index 11

Each pair of bits = one status:
┌────────────────────────────┐
│  Byte 0 (indices 0-3)      │
├────────────────────────────┤
│ bits: 7-6  5-4  3-2  1-0   │
│        3    0    2    1    │  → indices 3,2,1,0
│      = 0xC9                │
└────────────────────────────┘
```

### 3.4 JSON Representation

The Status List in JSON format uses a `status_list` object:

```json
{
  "status_list": {
    "bits": 1,
    "lst": "eNrbuRgAAhcBXQ",
    "aggregation_uri": "https://example.com/statuslists"
  }
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `bits` | ✅ Yes | Number of bits per token (1, 2, 4, or 8) |
| `lst` | ✅ Yes | Base64url-encoded DEFLATE-compressed byte array |
| `aggregation_uri` | ❌ No | URI to retrieve Status List Aggregation |

#### Encoded Examples

**1-bit example** (16 tokens):
```json
{
  "bits": 1,
  "lst": "eNrbuRgAAhcBXQ"
}
```

**2-bit example** (12 tokens):
```json
{
  "bits": 2,
  "lst": "eNo76fITAAPfAgc"
}
```

### 3.5 CBOR Representation

For CBOR-encoded Status Lists, the structure is a **map (Major Type 5)**:

| Field | CBOR Type | Required | Description |
|-------|-----------|----------|-------------|
| `bits` | Unsigned int (Major Type 0) | ✅ Yes | Number of bits per token (1, 2, 4, or 8) |
| `lst` | Byte string (Major Type 2) | ✅ Yes | Compressed byte array (raw, not base64url) |
| `aggregation_uri` | Text string (Major Type 3) | ❌ No | URI for Status List Aggregation |

#### CDDL Definition

```cddl
StatusList = {
    bits: 1 / 2 / 4 / 8,        ; The number of bits per Referenced Token
    lst: bstr,                   ; Byte string containing the Status List
    ? aggregation_uri: tstr,     ; Optional link to Status List Aggregation
}
```

#### CBOR Example (Hex)

```
Input: byte_array = [0xb9, 0xa3]
Encoded: a2646269747301636c73744a78dadbb918000217015d
```

**Annotated breakdown:**
```
a2                              # map(2)
  64                            #   string(4)
    62697473                    #     "bits"
  01                            #   uint(1)
  63                            #   string(3)
    6c7374                      #     "lst"
  4a                            #   bytes(10)
    78dadbb918000217015d        #     compressed data
```

---

## 4. Status List Token

The Status List Token is a **cryptographically signed container** that wraps the Status List. This enables:
- ✅ Third-party hosting
- ✅ Integrity protection
- ✅ Offline use cases

### 4.1 Status List Token in JWT Format

The Status List Token MUST be a valid JWT per RFC 7519.

#### JWT Header

| Claim | Required | Value |
|-------|----------|-------|
| `typ` | ✅ Yes | **`statuslist+jwt`** (exactly this value) |
| `alg` | ✅ Yes | Signing algorithm (e.g., ES256) |
| `kid` | Recommended | Key identifier |

#### JWT Claims (Payload)

| Claim | Required | Description |
|-------|----------|-------------|
| `sub` | ✅ Yes | URI of this Status List Token. **Must match** the `uri` in Referenced Tokens' `status_list` claim |
| `iat` | ✅ Yes | Issued-at timestamp |
| `exp` | ❌ No | Expiration time |
| `ttl` | ❌ No | Time-to-live in seconds for caching (positive integer) |
| `status_list` | ✅ Yes | The Status List object (with `bits` and `lst`) |

#### Example JWT

**Header:**
```json
{
  "alg": "ES256",
  "kid": "12",
  "typ": "statuslist+jwt"
}
```

**Payload:**
```json
{
  "sub": "https://example.com/statuslists/1",
  "iat": 1686920170,
  "exp": 2291720170,
  "ttl": 43200,
  "status_list": {
    "bits": 1,
    "lst": "eNrbuRgAAhcBXQ"
  }
}
```

#### Validation Rules

| Rule | Description |
|------|-------------|
| ✅ Signature | MUST be cryptographically signed; reject invalid signatures |
| ✅ JWT validity | Must be valid per RFC 7519 |
| ✅ `sub` matching | The `sub` claim must match the URI referenced by the token being checked |

### 4.2 Status List Token in CWT Format

The Status List Token can also be encoded as a **CBOR Web Token (CWT)** per RFC 8392.

#### CWT Protected Header

| Claim | Code | Required | Value |
|-------|------|----------|-------|
| `type` | **16** | ✅ Yes | `application/statuslist+cwt` or registered CoAP Content-Format ID |

#### CWT Claims Set

| Claim | Code | Required | Description |
|-------|------|----------|-------------|
| `subject` | **2** | ✅ Yes | URI of this Status List Token (must match Referenced Token's `uri`) |
| `issued at` | **6** | ✅ Yes | Issuance timestamp |
| `expiration time` | **4** | ❌ No | When the token expires |
| `time to live` | **65534** | ❌ No | Cache duration in seconds (unsigned int) |
| `status list` | **65533** | ✅ Yes | The Status List (per Section 4.3 CBOR format) |

#### CWT Claim Codes Summary

```
Standard Claims:        Custom Claims:
  2  = subject            65533 = status_list
  4  = expiration         65534 = ttl
  6  = issued_at
  16 = type (header)
```

#### Validation Rules

| Rule | Description |
|------|-------------|
| ✅ Signature | MUST be cryptographically signed; reject invalid signatures |
| ✅ CWT validity | Must be valid per RFC 8392 |
| ✅ `subject` matching | Must match the URI referenced by the token being checked |

### 4.3 JWT vs CWT Comparison

| Aspect | JWT Format | CWT Format |
|--------|------------|------------|
| **Type** | `typ: "statuslist+jwt"` | `16: "application/statuslist+cwt"` |
| **Subject** | `sub` (string) | `2` (subject) |
| **Issued At** | `iat` (number) | `6` (issued at) |
| **Expiration** | `exp` (number) | `4` (expiration time) |
| **TTL** | `ttl` (number) | `65534` (unsigned int) |
| **Status List** | `status_list` (JSON object) | `65533` (CBOR map) |
| **Encoding** | Base64url JSON | CBOR binary |

---

## 5. Referenced Token

A **Referenced Token** is any token (JWT, SD-JWT VC, CWT, ISO mdoc) that includes a `status` claim pointing to its entry in a Status List.

### 5.1 The Status Claim

The `status` claim is a container that can reference **one or more status mechanisms**. This specification defines the `status_list` mechanism, but other mechanisms can coexist.

> 💡 This is similar to the `cnf` (confirmation) claim in RFC 7800 where different confirmation methods can be included.

### 5.2 Referenced Token in JOSE/JWT Format

#### Structure

```json
{
  "status": {
    "status_list": {
      "idx": 0,
      "uri": "https://example.com/statuslists/1"
    }
  }
}
```

#### Fields in `status_list`

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `idx` | ✅ Yes | Integer | Index position in the Status List (0 or greater) |
| `uri` | ✅ Yes | String (URI) | URI of the Status List Token to fetch |

#### Full JWT Example

**Header:**
```json
{
  "alg": "ES256",
  "kid": "11"
}
```

**Payload:**
```json
{
  "iss": "https://example.com/issuer",
  "iat": 1683000000,
  "exp": 1883000000,
  "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
  "status": {
    "status_list": {
      "idx": 0,
      "uri": "https://example.com/statuslists/1"
    }
  }
}
```

#### SD-JWT VC Support

SD-JWT-based Verifiable Credentials use the same `status` encoding. The `status` claim is placed in the SD-JWT payload alongside selective disclosure claims.

### 5.3 Referenced Token in COSE/CWT Format

#### CBOR Claim Codes

| Claim | Code | Type | Description |
|-------|------|------|-------------|
| `status` | **65535** | CBOR map | Container for status mechanisms |
| `idx` | — | Unsigned int (Major Type 0) | Index in Status List |
| `uri` | — | Text string (Major Type 3) | URI of Status List Token |

#### Structure (CBOR)

```
65535 (status): {
  "status_list": {
    idx: 0,
    uri: "https://example.com/statuslists/1"
  }
}
```

### 5.4 ISO mdoc Support

ISO mdoc (Mobile Driver's License) can use the Status List mechanism by adding a `status` parameter in the **Mobile Security Object (MSO)**.

- Uses the same CBOR encoding as CWT
- Recommended label: `status`

#### Example (from MSO):
```cbor-diag
{
  "status": {
    "status_list": {
      "idx": 412,
      "uri": "https://example.com/statuslists/1"
    }
  },
  "docType": "org.iso.18013.5.1.mDL",
  "version": "1.0",
  "validityInfo": { ... }
}
```

### 5.5 How It All Connects

```
┌─────────────────────────────────────┐
│         Referenced Token            │
│  (JWT, SD-JWT VC, CWT, ISO mdoc)    │
├─────────────────────────────────────┤
│  status: {                          │
│    status_list: {                   │
│      idx: 5,  ◄─────────────────────┼──── "Look at index 5"
│      uri: "https://.../statuslist/1"│
│    }           │                    │
│  }             │                    │
└────────────────┼────────────────────┘
                 │
                 │ fetch
                 ▼
┌─────────────────────────────────────┐
│       Status List Token             │
│  sub: "https://.../statuslist/1"    │◄── URI must match!
├─────────────────────────────────────┤
│  status_list: {                     │
│    bits: 1,                         │
│    lst: "eNrbuRg..."                │
│  }                                  │
│         │                           │
│         ▼                           │
│  Decompress & check bit at index 5  │
└─────────────────────────────────────┘
```

### 5.6 JWT vs CWT Comparison for Referenced Tokens

| Aspect | JWT (JOSE) | CWT (COSE) |
|--------|------------|------------|
| **Status claim** | `"status"` (string key) | `65535` (numeric key) |
| **Index** | `"idx"` (JSON integer) | `idx` (unsigned int, Major Type 0) |
| **URI** | `"uri"` (JSON string) | `uri` (text string, Major Type 3) |
| **Use cases** | JWT, SD-JWT VC | CWT, ISO mdoc |

---

## 6. Status Types

Status Types define the possible states a Referenced Token can have. Each token has **exactly one status** at any given time.

### 6.1 Defined Status Type Values

| Hex | Decimal | Name | Description |
|-----|---------|------|-------------|
| `0x00` | 0 | **VALID** | Token is valid, correct, legal |
| `0x01` | 1 | **INVALID** | Token is revoked, annulled, cancelled |
| `0x02` | 2 | **SUSPENDED** | Token is temporarily invalid (usually temporary state) |

### 6.2 Reserved Values

| Range | Usage |
|-------|-------|
| `0x03` | Application-specific (permanently reserved) |
| `0x0B` - `0x0F` | Application-specific (permanently reserved) |
| All others | Reserved for future registration |

### 6.3 Bit Size Requirements

| Status Types Needed | Minimum `bits` Value |
|--------------------|---------------------|
| VALID, INVALID only | 1 bit (2 values) |
| VALID, INVALID, SUSPENDED | 2 bits (4 values) |
| Up to 16 statuses | 4 bits |
| Up to 256 statuses | 8 bits |

### 6.4 Important Processing Rule

> ⚠️ **Token validation rules take precedence over status!**
>
> If a token is expired (`exp` claim), it's rejected even if the Status List says `VALID (0x00)`.

---

## 7. Verification and Processing

This section describes how to fetch, validate, and process Status List Tokens. These rules apply to both **Holders** and **Relying Parties**.

### 7.1 Status List Request

#### HTTP Request

```http
GET /statuslists/1 HTTP/1.1
Host: example.com
Accept: application/statuslist+jwt
```

#### Request Requirements

| Requirement | Details |
|-------------|---------|
| **Method** | HTTP GET |
| **URI** | From the `uri` field in Referenced Token's `status_list` claim |
| **Accept Header** | `application/statuslist+jwt` (JWT) or `application/statuslist+cwt` (CWT) |
| **CORS** | SHOULD be supported for browser-based clients |

#### Response Handling

| HTTP Status | Action |
|-------------|--------|
| **2xx** | Success - process the Status List Token |
| **3xx** | Follow redirect (detect infinite loops) |
| **4xx/5xx** | Error - cannot determine status |

### 7.2 Status List Response

#### HTTP Response Example

```http
HTTP/1.1 200 OK
Content-Type: application/statuslist+jwt
Content-Encoding: gzip

eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyIiwidHlwIjoic3RhdHVzbGlzdCtqd3QifQ...
```

#### Response Requirements

| Requirement | Details |
|-------------|---------|
| **Content-Type** | `application/statuslist+jwt` or `application/statuslist+cwt` |
| **Compression** | SHOULD use gzip Content-Encoding |
| **Caching** | `exp` and `ttl` claims in token take priority over HTTP cache headers |

### 7.3 Complete Validation Algorithm

```
┌─────────────────────────────────────────────────────────────┐
│                    VALIDATION FLOWCHART                      │
└─────────────────────────────────────────────────────────────┘

Step 1: VALIDATE REFERENCED TOKEN FIRST
        ├── Check signature
        ├── Check expiration (exp)
        ├── Check required attributes
        └── If FAIL → REJECT TOKEN (don't check status)

Step 2: CHECK STATUS CLAIM EXISTS
        ├── Verify "status" claim exists
        ├── Verify "status_list" object within it
        ├── Extract "idx" and "uri"
        └── If FAIL → REJECT TOKEN

Step 3: FETCH STATUS LIST TOKEN
        └── HTTP GET to "uri"

Step 4: VALIDATE STATUS LIST TOKEN
        ├── Validate JWT/CWT signature
        ├── Check required claims exist (sub, iat, status_list)
        ├── Verify: sub == uri from Referenced Token
        ├── Check iat (issued at) for freshness policy
        ├── Check exp (if present) - reject if expired
        ├── Check ttl for cache freshness
        └── If FAIL → REJECT TOKEN

Step 5: DECOMPRESS STATUS LIST
        └── Decompress "lst" using ZLIB/DEFLATE

Step 6: RETRIEVE STATUS VALUE
        ├── Look up bit(s) at index "idx"
        └── If index out of bounds → REJECT TOKEN

Step 7: EVALUATE STATUS
        ├── 0x00 (VALID) → Token is valid
        ├── 0x01 (INVALID) → Token is revoked
        ├── 0x02 (SUSPENDED) → Token is suspended
        └── Other → Application-specific handling
```

### 7.4 Validation Checklist

| # | Check | Action on Failure |
|---|-------|-------------------|
| 1 | Referenced Token signature valid | REJECT |
| 2 | Referenced Token not expired | REJECT |
| 3 | `status` claim exists | REJECT |
| 4 | `status_list` with `idx` and `uri` exists | REJECT |
| 5 | Status List Token fetched successfully | REJECT |
| 6 | Status List Token signature valid | REJECT |
| 7 | `sub` matches `uri` | REJECT |
| 8 | Status List Token not expired (`exp`) | REJECT |
| 9 | Cache fresh (`iat` + `ttl` > now) | Fetch fresh copy |
| 10 | Decompression successful | REJECT |
| 11 | Index within bounds | REJECT |
| 12 | Status value acceptable | Depends on value |

### 7.6 Historical Resolution (Optional Feature)

By default, Status List Tokens only convey **current** status. However, an optional mechanism allows querying status at a **specific point in time**.

#### Request with Timestamp

```http
GET /statuslists/1?time=1686925000 HTTP/1.1
Host: example.com
Accept: application/statuslist+jwt
```

| Parameter | Description |
|-----------|-------------|
| `time` | Unix timestamp for the desired point in time |

#### Response Handling

| HTTP Status | Meaning |
|-------------|---------|
| **200** | Success - verify `iat` and `exp` cover requested time |
| **501** | Not Implemented - server doesn't support historical queries |
| **406** | Not Acceptable - requested time not available |

> ⚠️ **Privacy Warning**: Historical resolution has significant privacy implications (see Section 8).

---

## 8. Status List Aggregation (Optional)

Status List Aggregation allows Relying Parties to fetch **all Status List Token URIs** for a given Issuer, enabling:
- Pre-fetching and caching
- Offline validation for a period of time

### 8.1 How to Discover Aggregation

```
┌─────────────────────────────┐
│  Two Discovery Methods:     │
├─────────────────────────────┤
│ 1. Issuer Metadata          │ ← .well-known, OAuth metadata, trust lists
│ 2. aggregation_uri claim    │ ← In the Status List itself
└─────────────────────────────┘
```

### 8.2 Aggregation Response (JSON)

```json
{
  "status_lists": [
    "https://example.com/statuslists/1",
    "https://example.com/statuslists/2",
    "https://example.com/statuslists/3"
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `status_lists` | Array of strings | URIs to all Status List Tokens |

**Media Type**: `application/json`

### 8.3 Processing Note

> If one Status List in the aggregation is invalid, **continue processing the others** rather than aborting entirely.

---

## 9. Security Considerations

### 9.1 Cryptographic Protection

- Status Lists only exist in **signed containers** (JWT/CWT)
- Integrity and origin can be verified without relying on transport security
- Follow security guidance from RFC 7519 (JWT), RFC 8725 (JWT best practices), RFC 8392 (CWT)

### 9.2 Correct Bit/Byte Indexing

> ⚠️ **Implementation Warning**: Incorrect parsing is a common source of bugs!

| Aspect | Rule |
|--------|------|
| **Bit order** | LSB (0) to MSB (7) — "right to left" |
| **Byte order** | Natural incrementing order — "left to right" |
| **Endianness** | Does NOT apply (each status fits in one byte) |

**Recommendation**: Use the specification's test vectors to verify implementation correctness.

### 9.3 Key Resolution and Trust Management

The spec doesn't mandate specific methods, but provides guidance:

#### Same Issuer = Same Status Issuer

```
Option A: Use the SAME key for both Referenced Token and Status List Token
          - x5c, x5t, x5t#S256, kid referencing same key

Option B: Use the SAME web-based resolution
          - x5u, jwks, jwks_uri, kid via same resolver
```

#### Different Issuer and Status Issuer

```
Use PKI with Certificate Authority:
┌───────────────────────┐
│ Certificate Authority │
└─────────┬─────────────┘
          │ issues certificates to both
    ┌─────┴─────┐
    ▼           ▼
┌────────┐  ┌───────────────┐
│ Issuer │  │ Status Issuer │ ← Uses Extended Key Usage (EKU)
└────────┘  └───────────────┘
```

### 9.4 X.509 Extended Key Usage

For X.509 certificates, an EKU OID is defined:
```
id-kp-oauthStatusListSigning OBJECT IDENTIFIER ::= { id-kp TBD }
```

This explicitly delegates Status List Token signing authority.

---

## 10. Privacy Considerations

### 10.1 Privacy Threat Model

| Threat | Actor | Risk |
|--------|-------|------|
| **Issuer Tracking** | Issuer/Status Issuer | Could track when/where tokens are validated |
| **Relying Party Profiling** | Relying Party | Could monitor status changes over time |
| **Outsider Analysis** | External actors | Could infer business data from public lists |
| **Collusion** | Multiple Relying Parties | Could link transactions across parties |

### 10.2 Herd Privacy (Main Protection)

```
┌─────────────────────────────────────────────────────────────┐
│                    HERD PRIVACY                              │
├─────────────────────────────────────────────────────────────┤
│  Many tokens share ONE Status List                          │
│  → Issuer doesn't know WHICH token is being checked         │
│  → Privacy through anonymity in the crowd                   │
│                                                             │
│  Larger Status List = Better Privacy (but more data)        │
└─────────────────────────────────────────────────────────────┘
```

### 10.3 Privacy Threats and Mitigations

#### Threat: Issuer Tracking Validation Requests

| Mitigation | Description |
|------------|-------------|
| **Herd privacy** | Many tokens in same list |
| **Private relay** | Hide requester's IP (RFC 9458) |
| **Third-party hosting** | Status Provider ≠ Issuer |

#### Threat: Malicious Issuer (Unique Lists)

A malicious issuer could create **one Status List per token**, defeating herd privacy.

**Detection**: Relying Parties can detect this by comparing Status List sizes across many tokens.

#### Threat: Relying Party Monitoring

Relying Party stores `uri` + `idx` and repeatedly checks status.

| Mitigation | Description |
|------------|-------------|
| **Regular re-issuance** | New tokens = new indices |
| **Disable historical resolution** | No past lookups |

#### Threat: Outsider Analysis

External actors analyze public Status Lists to infer:
- Total tokens issued
- Revocation rates
- Business patterns

| Mitigation | Description |
|------------|-------------|
| **Random indices** | Non-sequential assignment |
| **Decoy entries** | Fake entries to obscure real count |
| **Multiple lists** | Spread across several Status Lists |
| **Disable aggregation** | Don't publish list of all Status Lists |
| **Disable historical** | No time-based queries |

### 10.4 Unlinkability Concerns

The `(uri, idx)` tuple is **unique and traceable**.

#### Colluding Relying Parties

Two Relying Parties can compare `status` claims to detect same Holder.

**Mitigation**: Issue **batches of one-time-use tokens** with different indices.

#### Colluding Status Issuer + Relying Party

Can link transactions by comparing status claims.

**Mitigation**: Use Status Lists only with token formats that have similar unlinkability properties.

### 10.5 Third-Party Hosting Benefits

```
┌────────────────────────────────────────────────────────────┐
│  Separate Status Issuer from Status Provider:              │
│                                                            │
│  ┌──────────────┐         ┌─────────────────┐              │
│  │Status Issuer │ signs   │ Status Provider │ hosts        │
│  │  (Issuer)    │────────►│    (CDN)        │◄──── RP      │
│  └──────────────┘         └─────────────────┘              │
│                                                            │
│  Benefits:                                                 │
│  ✅ Issuer can't see who's requesting                      │
│  ✅ Better scalability (CDN)                               │
│  ✅ Integrity still protected (signature)                  │
└────────────────────────────────────────────────────────────┘
```

### 10.6 Status Types and Privacy

> ⚠️ **Warning**: Additional status types beyond VALID/INVALID can leak information!

**Example**: A `SUSPENDED` status on a driver's license could reveal:
- License suspension even when used for ID purposes
- Enable unwanted statistical analysis

**Recommendation**: Consider if revocation + re-issuance is better than adding status types.

---

## 11. Implementation Considerations

### 11.1 Token Lifecycle

```
┌─────────────────────────────────────────────────────────────────┐
│                    TOKEN LIFECYCLE                               │
├─────────────────────────────────────────────────────────────────┤
│  Referenced Token Lifetime  ──────►  Status List Token Lifetime │
│                                                                 │
│  When ALL Referenced Tokens expire, the Status List Token       │
│  can be retired.                                                │
└─────────────────────────────────────────────────────────────────┘
```

#### Re-issuance Strategy

| Strategy | Requirement | Use Case |
|----------|-------------|----------|
| **Regular re-issuance** | Each re-issued token gets a **fresh index** | Mitigate linkability |
| **Batch issuance** | Each token in batch gets **dedicated index** | One-time-use tokens |
| **Cross-list batches** | Tokens MAY span multiple Status Lists | Large batches |

> ⚠️ Revoking batch-issued tokens may reveal correlation later.

### 11.2 Default Values and Double Allocation

#### Initialization Best Practice

```
┌────────────────────────────────────────────────────────────┐
│  Initialize Status List with DEFAULT VALUE (usually 0x00)  │
│                                                            │
│  Benefits:                                                 │
│  ✅ Better compression                                     │
│  ✅ Hides actual number of tokens (unused = valid = 0x00)  │
│  ✅ No update needed at issuance time                      │
└────────────────────────────────────────────────────────────┘
```

#### Double Allocation Prevention

| Rule | Description |
|------|-------------|
| **RECOMMENDED** | Prevent double allocation (same `uri` + `idx` for different tokens) |
| **MUST** | Prevent any **unintended** double allocation |

> `(uri, idx)` is a unique identifier — reuse enables tracking!

### 11.3 Status List Size Considerations

#### Factors Affecting Size

| Factor | Impact |
|--------|--------|
| **Number of tokens** | More tokens = larger list |
| **Revocation rate** | ~0% or ~100% = smallest (compression); ~50% random = largest |
| **Token lifetime** | Shorter = earlier retirement of Status Lists |

#### Size Recommendations

| Recommendation | Details |
|----------------|---------|
| **Divisible by 8** | Size in bits should be divisible by 8 (no remainder) |
| **Multiple lists** | Split across lists for constrained environments (mobile, IoT) |
| **Organize by expiry** | Group by Referenced Token expiry date for easier retirement |

### 11.4 External Status Issuer

When Issuer ≠ Status Issuer, both parties must align on:

| Alignment Point | Reference |
|-----------------|-----------|
| Key and trust management | Section 9.3 |
| Status List parameters | — |
| Number of bits for Status Type | Section 3 |
| Update cycle (`ttl`) | Section 4 |

### 11.5 External Status Provider (Scalability)

```
┌──────────────┐  signs   ┌─────────────────┐  serves  ┌──────────┐
│Status Issuer │─────────►│ Status Provider │◄─────────│    RP    │
│              │          │     (CDN)       │          │          │
└──────────────┘          └─────────────────┘          └──────────┘

Benefits:
✅ Greater scalability (CDN resources)
✅ Authenticity still guaranteed (signature)
✅ Privacy benefits (Issuer can't see requests)
```

### 11.6 Update Interval and Caching Strategy

#### Claims for Communicating Update Policy

| Claim | Type | Description |
|-------|------|-------------|
| `exp` | Absolute timestamp | When Status List MUST NOT be used anymore |
| `ttl` | Duration (seconds) | When to check for updates (relative to fetch time) |
| `iat` | Absolute timestamp | When Status List was issued |

**Recommendation**: Use BOTH `exp` and `ttl`.

#### Caching Options for Relying Parties

```
Timeline:
                                                              
 iat     fetch     fetch+ttl   fetch+2*ttl  fetch+3*ttl    exp
  │        │           │            │            │          │
  ▼        ▼           ▼            ▼            ▼          ▼
──┼────────┼───────────┼────────────┼────────────┼──────────┼──►
           │           │            │            │
           │    ttl    │     ttl    │     ttl    │
           │◄─────────►│◄──────────►│◄──────────►│
           
Option A (RECOMMENDED): Check at (fetch_time + ttl)
         → Distributes load on Status Provider

Option B: Check at (iat + ttl)  
         → Most up-to-date for critical use cases

Option C: If no ttl, check before exp
```

### 11.7 Relying Party Data Hygiene

**Delete correlatable information when no longer needed:**

| Data | When to Delete |
|------|----------------|
| `status` claim in Referenced Token | After presentation validation |
| Status List Token | After expiration or update |

**Keep only**: Relevant payload from Referenced Token.

### 11.8 Format Mixing

| Aspect | Guidance |
|--------|----------|
| **Allowed** | CBOR Referenced Token + JWT Status List (technically possible) |
| **Expected** | Ecosystems choose specific formats |
| **Profiles** | Define which combinations are supported |

---

## 12. IANA Registrations Summary

### 12.1 Registered Claims

#### JWT Claims (`IANA.JWT`)

| Claim | Description |
|-------|-------------|
| `status` | Reference to status mechanism |
| `status_list` | Status list with token statuses |
| `ttl` | Time to live |

#### CWT Claims (`IANA.CWT`)

| Claim | Key | Type |
|-------|-----|------|
| `status` | 65535 | map |
| `status_list` | 65533 | map |
| `ttl` | 65534 | unsigned integer |

### 12.2 Status Types Registry

| Name | Value | Description |
|------|-------|-------------|
| **VALID** | `0x00` | Token is valid |
| **INVALID** | `0x01` | Token is revoked |
| **SUSPENDED** | `0x02` | Token is temporarily invalid |
| **APPLICATION_SPECIFIC** | `0x03`, `0x0B-0x0F` | Custom use |

### 12.3 Media Types

| Media Type | Format |
|------------|--------|
| `application/statuslist+jwt` | JWT-based Status List |
| `application/statuslist+cwt` | CWT-based Status List |

### 12.4 OAuth Metadata

| Parameter | Description |
|-----------|-------------|
| `status_list_aggregation_endpoint` | URL for Status List Aggregation |

### 12.5 X.509 Extended Key Usage

```
OID: 1.3.6.1.5.5.7.3.TBD (id-kp-oauthStatusListSigning)
Purpose: Explicitly delegate Status List Token signing authority
```

---

## Quick Reference Card

### The Complete Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                         COMPLETE FLOW                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. ISSUANCE                                                        │
│     Issuer → Referenced Token (with status.status_list.idx/uri)     │
│                     → Holder                                        │
│                                                                     │
│  2. STATUS MANAGEMENT                                               │
│     Issuer → Status Issuer → Status List Token                      │
│                                  → Status Provider (hosts publicly) │
│                                                                     │
│  3. PRESENTATION                                                    │
│     Holder → Referenced Token → Relying Party                       │
│                                                                     │
│  4. VALIDATION                                                      │
│     Relying Party:                                                  │
│       a) Validate Referenced Token (signature, exp, etc.)           │
│       b) Extract idx + uri from status_list claim                   │
│       c) GET Status List Token from uri                             │
│       d) Validate Status List Token (signature, sub==uri, exp)      │
│       e) Decompress lst (ZLIB/DEFLATE)                              │
│       f) Read bits at index idx                                     │
│       g) Interpret status (0x00=VALID, 0x01=INVALID, 0x02=SUSPENDED)│
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Data Structures

```
Referenced Token (JWT):
{
  "status": {
    "status_list": {
      "idx": 12345,
      "uri": "https://issuer.example/statuslists/1"
    }
  }
}

Status List Token (JWT):
Header: { "typ": "statuslist+jwt", "alg": "ES256" }
Payload: {
  "sub": "https://issuer.example/statuslists/1",  // must match uri!
  "iat": 1686920170,
  "exp": 2291720170,
  "ttl": 43200,
  "status_list": {
    "bits": 1,
    "lst": "eNrbuRgAAhcBXQ"  // base64url(DEFLATE(byte_array))
  }
}
```

### Bit Extraction Formula

```
Given: bits = number of bits per status (1, 2, 4, or 8)
       idx  = index of the token
       lst  = decompressed byte array

byte_index = floor(idx * bits / 8)
bit_offset = (idx * bits) % 8
mask       = (2^bits - 1) << bit_offset

status = (lst[byte_index] & mask) >> bit_offset
```

---

*Last updated: Complete specification (Sections 1-14)*
