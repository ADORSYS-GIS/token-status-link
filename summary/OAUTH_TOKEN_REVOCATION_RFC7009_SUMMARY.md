# OAuth 2.0 Token Revocation (RFC 7009) Summary

> How OAuth 2.0 clients notify authorization servers that tokens are no longer needed.

📄 **Source Specification**: [RFC 7009 - OAuth 2.0 Token Revocation](https://www.rfc-editor.org/rfc/rfc7009)

---

## 1. Introduction & Overview

### What is Token Revocation?

**Token Revocation** is a mechanism that allows OAuth 2.0 clients to notify the authorization server that a previously obtained **access token** or **refresh token** is no longer needed. This enables:

- Clean up of security credentials
- Invalidation of tokens and related authorization grants
- Better end-user experience and security hygiene

### The Problem It Solves

| Scenario | Without Revocation | With Revocation |
|----------|-------------------|-----------------|
| User logs out | Tokens remain valid until expiry | Tokens immediately invalidated |
| User uninstalls app | Abandoned tokens could be abused | Tokens cleaned up |
| User changes identity | Old tokens still work | Old tokens invalidated |
| Security incident | Must wait for token expiry | Immediate invalidation |

### Key Concept

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       TOKEN REVOCATION FLOW                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌────────────┐                              ┌─────────────────────────┐    │
│  │            │  POST /revoke                │                         │    │
│  │   Client   │  token=<token_value>         │   Authorization Server  │    │
│  │            │─────────────────────────────►│                         │    │
│  │            │                              │   1. Validate client    │    │
│  │            │                              │   2. Verify token       │    │
│  │            │◄─────────────────────────────│   3. Invalidate token   │    │
│  │            │  HTTP 200 OK                 │   4. Revoke related     │    │
│  └────────────┘                              │      tokens (optional)  │    │
│                                              └─────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Revocation Endpoint

### Requirements

| Requirement | Description |
|-------------|-------------|
| **Protocol** | MUST be HTTPS |
| **Method** | HTTP POST |
| **Content-Type** | `application/x-www-form-urlencoded` |
| **TLS** | MUST use TLS (compliant with RFC 6749 Section 1.6) |
| **Discovery** | Endpoint location obtained from trusted source (documentation, metadata) |

### Endpoint URL

Typically exposed at:
```
https://authorization-server.example.com/oauth/revoke
```

Or in Keycloak:
```
https://keycloak.example.com/realms/{realm}/protocol/openid-connect/revoke
```

---

## 3. Revocation Request

### Request Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `token` | ✅ **REQUIRED** | The token to be revoked |
| `token_type_hint` | ❌ Optional | Hint about the token type to optimize lookup |

### Token Type Hints

| Hint Value | Description |
|------------|-------------|
| `access_token` | The token is an access token |
| `refresh_token` | The token is a refresh token |

> 💡 If the server cannot find the token using the hint, it MUST search across all supported token types.

### Client Authentication

The client MUST include its authentication credentials as per RFC 6749 Section 2.3:

| Method | Description |
|--------|-------------|
| **HTTP Basic Auth** | `Authorization: Basic <base64(client_id:client_secret)>` |
| **POST Body** | `client_id` and `client_secret` in request body |
| **Client Assertion** | JWT-based authentication (RFC 7523) |

### Example Request

```http
POST /revoke HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

token=45ghiukldjahdnhzdauz&token_type_hint=refresh_token
```

### Server Processing Steps

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    SERVER PROCESSING STEPS                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Step 1: VALIDATE CLIENT CREDENTIALS                                        │
│          • Verify client_id and client_secret (confidential clients)        │
│          • Or verify client_id only (public clients)                        │
│                         │                                                   │
│                         ▼ FAIL → 401 Unauthorized                           │
│                                                                             │
│  Step 2: VERIFY TOKEN OWNERSHIP                                             │
│          • Check that the token was issued to the requesting client         │
│                         │                                                   │
│                         ▼ FAIL → 401 Unauthorized                           │
│                                                                             │
│  Step 3: INVALIDATE TOKEN                                                   │
│          • Token becomes immediately unusable                               │
│          • Propagation delay may exist in distributed systems               │
│                         │                                                   │
│                         ▼                                                   │
│                                                                             │
│  Step 4: CASCADE REVOCATION (Policy-dependent)                              │
│          • If refresh token revoked → MAY revoke related access tokens      │
│          • If access token revoked → MAY revoke related refresh token       │
│          • MAY revoke underlying authorization grant                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Revocation Response

### Successful Revocation

```http
HTTP/1.1 200 OK
```

> **Important**: HTTP 200 is returned for:
> - Successfully revoked tokens
> - **Invalid/unknown tokens** (already revoked, expired, or never existed)

### Why 200 for Invalid Tokens?

| Reason | Explanation |
|--------|-------------|
| **Client can't handle the error meaningfully** | What would the client do with "token not found"? |
| **Purpose already achieved** | If token is invalid, it's already not usable |
| **Prevents information disclosure** | Attacker can't probe for valid tokens |

### Error Responses

| HTTP Status | Error Code | Description |
|-------------|------------|-------------|
| `400` | `invalid_request` | Missing required parameter or malformed request |
| `400` | `invalid_client` | Client authentication failed |
| `400` | `unsupported_token_type` | Server doesn't support revoking this token type |
| `503` | (service unavailable) | Temporary failure; client should retry |

### Error Response Format

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "error": "unsupported_token_type",
  "error_description": "Access token revocation is not supported"
}
```

### 503 Service Unavailable

If the server returns HTTP 503:
- Client MUST assume the token still exists
- Client MAY retry after a reasonable delay
- Server MAY include `Retry-After` header

```http
HTTP/1.1 503 Service Unavailable
Retry-After: 120

{"error": "temporarily_unavailable"}
```

---

## 5. Token Revocation Policies

### Cascade Revocation

The server decides whether revoking one token affects related tokens:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    CASCADE REVOCATION POLICIES                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Policy A: Refresh Token Revoked                                            │
│  ────────────────────────────────                                           │
│                                                                             │
│  ┌─────────────────┐                                                        │
│  │ Refresh Token   │──► REVOKED                                             │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼ SHOULD (if supported)                                           │
│  ┌─────────────────┐                                                        │
│  │ Access Token(s) │──► REVOKED                                             │
│  └─────────────────┘                                                        │
│           │                                                                 │
│           ▼ MAY                                                             │
│  ┌─────────────────┐                                                        │
│  │ Authorization   │──► REVOKED                                             │
│  │ Grant           │                                                        │
│  └─────────────────┘                                                        │
│                                                                             │
│  ────────────────────────────────────────────────────────────────────────   │
│                                                                             │
│  Policy B: Access Token Revoked                                             │
│  ──────────────────────────────                                             │
│                                                                             │
│  ┌─────────────────┐                                                        │
│  │ Access Token    │──► REVOKED                                             │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼ MAY                                                             │
│  ┌─────────────────┐                                                        │
│  │ Refresh Token   │──► REVOKED (policy-dependent)                          │
│  └─────────────────┘                                                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Implementation Requirements

| Token Type | Support Level |
|------------|---------------|
| Refresh Tokens | **MUST** support revocation |
| Access Tokens | **SHOULD** support revocation |

---

## 6. Implementation Considerations

### Access Token Types and Revocation

| Token Type | Revocation Complexity |
|------------|----------------------|
| **Reference Tokens** (opaque handles) | Easy - just delete from database |
| **Self-Contained Tokens** (JWTs) | Hard - requires backend coordination |

### Self-Contained Token Challenge

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                 SELF-CONTAINED TOKEN REVOCATION CHALLENGE                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Problem: JWT access tokens can be validated offline without contacting     │
│           the authorization server. How do you revoke them?                 │
│                                                                             │
│  Solutions:                                                                 │
│                                                                             │
│  1. SHORT-LIVED TOKENS                                                      │
│     • Issue access tokens with short lifetime (e.g., 5-15 minutes)          │
│     • Use refresh tokens to get new access tokens                           │
│     • Revoke refresh token → no new access tokens issued                    │
│     • Trade-off: More token refresh traffic                                 │
│                                                                             │
│  2. TOKEN INTROSPECTION                                                     │
│     • Resource server checks token status via introspection endpoint        │
│     • Adds latency to each request                                          │
│     • Trade-off: Performance vs. immediate revocation                       │
│                                                                             │
│  3. STATUS LISTS (Token Status List Spec)                                   │
│     • Publish revocation status in a compressed list                        │
│     • Resource servers fetch and cache the list                             │
│     • Trade-off: Slight propagation delay                                   │
│                                                                             │
│  4. PUSH-BASED REVOCATION                                                   │
│     • Authorization server notifies resource servers                        │
│     • Requires backend infrastructure                                       │
│     • Trade-off: Complexity                                                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Cross-Origin Support

### CORS Support

For browser-based applications, the revocation endpoint MAY support CORS:

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://client.example.com
Access-Control-Allow-Methods: POST
Access-Control-Allow-Headers: Authorization, Content-Type
```

### JSONP Support (Legacy)

For legacy user-agents, JSONP MAY be supported via GET requests:

```
GET /revoke?token=abcdef&callback=myCallback HTTP/1.1
```

**Success Response:**
```javascript
myCallback();
```

**Error Response:**
```javascript
myCallback({"error":"unsupported_token_type"});
```

> ⚠️ **Security Warning**: JSONP can expose clients to code injection from malicious endpoints.

---

## 8. Security Considerations

### Threats and Mitigations

| Threat | Mitigation |
|--------|------------|
| **Denial of Service** | Rate limiting, same protections as token endpoint |
| **Token Guessing** | Client authentication required; attacker would need valid credentials |
| **Counterfeit Endpoint** | Clients MUST verify endpoint authenticity (certificate validation) |
| **Plaintext Credentials** | MUST use HTTPS/TLS |
| **Invalid Token Type Hints** | Server should handle gracefully; don't trust hints blindly |

### Client Resilience

> ⚠️ **Important**: Clients compliant with RFC 6749 MUST be prepared to handle unexpected token invalidation at any time, regardless of this revocation mechanism.

Tokens may be invalidated by:
- Resource owner revoking authorization
- Authorization server policy
- Security threat mitigation
- This revocation mechanism

---

## 9. IANA Registrations

### OAuth Extensions Error Registry

| Error Value | Usage Location | Reference |
|-------------|----------------|-----------|
| `unsupported_token_type` | Revocation endpoint error response | RFC 7009 |

### OAuth Token Type Hints Registry

| Hint Value | Change Controller | Reference |
|------------|-------------------|-----------|
| `access_token` | IETF | RFC 7009 |
| `refresh_token` | IETF | RFC 7009 |

---

## 10. Relationship to Keycloak Token Status Plugin

The **Keycloak Token Status Plugin** extends the standard RFC 7009 revocation endpoint to support **Verifiable Credential (VC) revocation** with holder-initiated flows.

### How the Plugin Extends RFC 7009

```
┌─────────────────────────────────────────────────────────────────────────────┐
│            RFC 7009 vs. TOKEN STATUS PLUGIN REVOCATION                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                     STANDARD RFC 7009                                │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │  • Client authenticates with client_id/secret                       │    │
│  │  • Client sends token to revoke                                     │    │
│  │  • Server validates client owns the token                           │    │
│  │  • Token is invalidated locally                                     │    │
│  │  • Used for: access_token, refresh_token                            │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                              │                                              │
│                              │ EXTENDS                                      │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                  TOKEN STATUS PLUGIN EXTENSION                       │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │  • Holder authenticates with SD-JWT VP + Key Binding JWT            │    │
│  │  • Challenge/nonce required for replay protection                   │    │
│  │  • Credential ownership verified via cryptographic proof            │    │
│  │  • Status published to external Status List Server                  │    │
│  │  • Used for: Verifiable Credentials (VCs)                           │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Differences

| Aspect | RFC 7009 (Standard) | Token Status Plugin |
|--------|---------------------|---------------------|
| **Who revokes** | Client (application) | Holder (end-user) |
| **Authentication** | Client credentials | SD-JWT VP + Key Binding |
| **Token types** | access_token, refresh_token | Verifiable Credentials |
| **Challenge required** | ❌ No | ✅ Yes (nonce) |
| **External notification** | ❌ No | ✅ Yes (Status List Server) |
| **Cryptographic proof** | ❌ No | ✅ Yes (holder key binding) |

### Plugin Implementation Details

The plugin's `CredentialRevocationEndpoint` **extends** Keycloak's `TokenRevocationEndpoint`:

```java
public class CredentialRevocationEndpoint extends TokenRevocationEndpoint {
    
    @Override
    public Response revoke() {
        // Check for Bearer token (SD-JWT VP)
        String authorizationHeader = getHeaders().getHeaderString(HttpHeaders.AUTHORIZATION);
        
        if (authorizationHeader == null) {
            // No Bearer token → fall back to standard RFC 7009 revocation
            return super.revoke();
        }
        
        if (authorizationHeader.startsWith("Bearer ")) {
            // Bearer token present → use VC revocation with Status List
            // 1. Validate SD-JWT VP
            // 2. Verify nonce (challenge-response)
            // 3. Verify credential ownership
            // 4. Publish to Status List Server
            return performVCRevocation(...);
        }
    }
}
```

### Endpoint Behavior

| Request Type | Plugin Behavior |
|--------------|-----------------|
| `POST /revoke` with Basic Auth | Falls back to standard RFC 7009 (`super.revoke()`) |
| `POST /revoke` with Bearer SD-JWT VP | Uses VC revocation with Status List |
| `POST /revoke` with no auth | Falls back to standard RFC 7009 |

### Same Endpoint, Extended Functionality

```
POST /realms/{realm}/protocol/openid-connect/revoke

┌─────────────────────────────────────────────────────────────────────────────┐
│  Request arrives at /revoke                                                 │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────────────────────────────────┐                            │
│  │ Is there a Bearer token with SD-JWT VP?     │                            │
│  └─────────────────────────────────────────────┘                            │
│           │                                                                 │
│     ┌─────┴─────┐                                                           │
│     │           │                                                           │
│    YES          NO                                                          │
│     │           │                                                           │
│     ▼           ▼                                                           │
│  ┌────────────────────┐    ┌────────────────────────────────────────────┐   │
│  │ VC Revocation Flow │    │ Standard RFC 7009 Flow (Keycloak default) │   │
│  │                    │    │                                            │   │
│  │ 1. Validate nonce  │    │ 1. Validate client credentials            │   │
│  │ 2. Verify VP sig   │    │ 2. Verify token ownership                 │   │
│  │ 3. Verify ownership│    │ 3. Invalidate token                       │   │
│  │ 4. Publish to      │    │                                            │   │
│  │    Status Server   │    │                                            │   │
│  └────────────────────┘    └────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Why This Design?

| Benefit | Explanation |
|---------|-------------|
| **Backward Compatible** | Standard OAuth clients continue to work |
| **Same Endpoint** | Wallets use the standard revocation URL |
| **Graceful Fallback** | Missing Bearer token → standard flow |
| **Protocol Compliant** | Uses RFC 7009's `token` parameter for credential ID |

---

## 11. Summary

### RFC 7009 Key Points

| Aspect | Specification |
|--------|---------------|
| **Purpose** | Allow clients to notify server that tokens are no longer needed |
| **Endpoint** | `POST /revoke` over HTTPS |
| **Parameters** | `token` (required), `token_type_hint` (optional) |
| **Authentication** | Client credentials required |
| **Response** | HTTP 200 for success AND invalid tokens |
| **Error** | `unsupported_token_type` if token type not supported |
| **Cascade** | Server MAY revoke related tokens |

### Plugin Extension Summary

The Keycloak Token Status Plugin extends RFC 7009 by:

1. **Adding holder-initiated revocation** via SD-JWT VP authentication
2. **Requiring challenge/nonce** for replay protection
3. **Integrating with Status List Server** for distributed revocation
4. **Maintaining backward compatibility** with standard OAuth revocation

This allows the same `/revoke` endpoint to handle both:
- Traditional OAuth token revocation (access/refresh tokens)
- Verifiable Credential revocation (with Status List integration)

---

*This document summarizes RFC 7009 (OAuth 2.0 Token Revocation) and explains how the Keycloak Token Status Plugin extends it for Verifiable Credential revocation.*
