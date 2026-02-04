# Status Issuer Integration Guide

> How a Status Issuer (Status List Server) interacts with Token Issuers to manage token statuses.

📄 **Based on**: [IETF OAuth Status List Specification (draft-ietf-oauth-status-list-11)](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-11.html)

---

## 1. Overview

This document describes the interaction between:
- **Token Issuer**: Entity that issues Referenced Tokens (JWTs, SD-JWT VCs, etc.) to Holders
- **Status Issuer**: Entity that manages Status Lists and issues Status List Tokens

These roles can be the same entity or separate entities.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    SYSTEM ARCHITECTURE                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────┐                      ┌─────────────────────────────┐  │
│  │              │  1. Request index    │                             │  │
│  │    Token     │─────────────────────►│      Status Issuer          │  │
│  │    Issuer    │◄─────────────────────│    (Status List Server)     │  │
│  │              │  2. Return idx + uri │                             │  │
│  └──────┬───────┘                      └──────────────┬──────────────┘  │
│         │                                             │                 │
│         │ 3. Issue token                              │ 4. Publish      │
│         │    with status claim                        │    Status List  │
│         ▼                                             ▼                 │
│  ┌──────────────┐                      ┌─────────────────────────────┐  │
│  │    Holder    │                      │     Status Provider         │  │
│  │              │                      │   (Public Endpoint/CDN)     │  │
│  └──────────────┘                      └─────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Integration Scenarios

### Scenario A: Same Entity (Issuer = Status Issuer)

```
┌─────────────────────────────────────────┐
│           Single Entity                  │
│  ┌─────────────────────────────────┐    │
│  │  Token Issuer + Status Issuer   │    │
│  │  ─────────────────────────────  │    │
│  │  • Issues tokens                │    │
│  │  • Manages Status List          │    │
│  │  • Signs Status List Token      │    │
│  │  • Hosts or delegates hosting   │    │
│  └─────────────────────────────────┘    │
└─────────────────────────────────────────┘

Advantages:
✅ Simpler architecture
✅ Same key can be used for both
✅ No coordination needed

Disadvantages:
❌ Single point of failure
❌ May need to scale hosting separately
```

### Scenario B: Separate Entities (Issuer ≠ Status Issuer)

```
┌──────────────────┐          ┌──────────────────┐
│   Token Issuer   │◄────────►│  Status Issuer   │
│                  │   API    │                  │
│  • Issues tokens │          │  • Manages lists │
│  • Embeds status │          │  • Signs tokens  │
│    claim         │          │  • Updates status│
└──────────────────┘          └──────────────────┘

Advantages:
✅ Separation of concerns
✅ Specialized scaling
✅ Regulatory compliance (different jurisdictions)
✅ Multiple issuers can share one Status Issuer

Disadvantages:
❌ Requires coordination/API
❌ Trust establishment needed
❌ More complex key management
```

---

## 3. Integration API Design

### 3.1 Core Operations

| Operation | Description | Direction |
|-----------|-------------|-----------|
| **Allocate Index** | Reserve an index for a new token | Issuer → Status Issuer |
| **Update Status** | Change status of a token | Issuer → Status Issuer |
| **Batch Allocate** | Reserve multiple indices | Issuer → Status Issuer |
| **Get Status** | Query current status | Issuer → Status Issuer |
| **Get Status List Info** | Get list metadata | Issuer → Status Issuer |

### 3.2 API Endpoints (Example REST Design)

```
Base URL: https://status-issuer.example.com/api/v1

┌─────────────────────────────────────────────────────────────────────────┐
│                         API ENDPOINTS                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  POST   /lists                    Create a new Status List              │
│  GET    /lists/{listId}           Get Status List metadata              │
│  DELETE /lists/{listId}           Retire a Status List                  │
│                                                                         │
│  POST   /lists/{listId}/indices   Allocate index(es) for new token(s)   │
│  GET    /lists/{listId}/indices/{idx}   Get status at index             │
│  PATCH  /lists/{listId}/indices/{idx}   Update status at index          │
│                                                                         │
│  POST   /lists/{listId}/batch     Batch allocate or update              │
│                                                                         │
│  GET    /lists/{listId}/token     Get current Status List Token (JWT)   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Detailed API Specifications

### 4.1 Create Status List

**Request:**
```http
POST /api/v1/lists HTTP/1.1
Host: status-issuer.example.com
Authorization: Bearer <issuer_token>
Content-Type: application/json

{
  "bits": 1,
  "size": 100000,
  "defaultStatus": 0,
  "ttl": 43200,
  "metadata": {
    "issuer": "https://issuer.example.com",
    "purpose": "employee_credentials"
  }
}
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `bits` | integer | ✅ | Bits per status (1, 2, 4, or 8) |
| `size` | integer | ✅ | Initial capacity (number of tokens) |
| `defaultStatus` | integer | ❌ | Default status value (default: 0) |
| `ttl` | integer | ❌ | Time-to-live in seconds |
| `metadata` | object | ❌ | Custom metadata |

**Response:**
```http
HTTP/1.1 201 Created
Content-Type: application/json

{
  "listId": "list-abc123",
  "uri": "https://status-issuer.example.com/statuslists/list-abc123",
  "bits": 1,
  "size": 100000,
  "allocated": 0,
  "createdAt": "2026-02-02T10:00:00Z"
}
```

---

### 4.2 Allocate Index (Single Token)

**Request:**
```http
POST /api/v1/lists/{listId}/indices HTTP/1.1
Host: status-issuer.example.com
Authorization: Bearer <issuer_token>
Content-Type: application/json

{
  "tokenId": "cred-xyz789",
  "initialStatus": 0,
  "expiresAt": "2027-02-02T10:00:00Z"
}
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tokenId` | string | ❌ | Issuer's internal token ID (for tracking) |
| `initialStatus` | integer | ❌ | Initial status (default: list default) |
| `expiresAt` | string | ❌ | Token expiration (for lifecycle management) |

**Response:**
```http
HTTP/1.1 201 Created
Content-Type: application/json

{
  "idx": 12345,
  "uri": "https://status-issuer.example.com/statuslists/list-abc123",
  "status": 0,
  "allocatedAt": "2026-02-02T10:05:00Z"
}
```

**The Issuer then uses these values in the token:**
```json
{
  "status": {
    "status_list": {
      "idx": 12345,
      "uri": "https://status-issuer.example.com/statuslists/list-abc123"
    }
  }
}
```

---

### 4.3 Batch Allocate Indices

For issuing multiple tokens at once (e.g., batch credentials):

**Request:**
```http
POST /api/v1/lists/{listId}/batch HTTP/1.1
Host: status-issuer.example.com
Authorization: Bearer <issuer_token>
Content-Type: application/json

{
  "operation": "allocate",
  "count": 100,
  "tokenIds": ["cred-001", "cred-002", ...],
  "initialStatus": 0,
  "expiresAt": "2027-02-02T10:00:00Z"
}
```

**Response:**
```http
HTTP/1.1 201 Created
Content-Type: application/json

{
  "uri": "https://status-issuer.example.com/statuslists/list-abc123",
  "allocations": [
    { "tokenId": "cred-001", "idx": 12345 },
    { "tokenId": "cred-002", "idx": 12346 },
    ...
  ],
  "count": 100,
  "allocatedAt": "2026-02-02T10:05:00Z"
}
```

---

### 4.4 Update Status (Revoke/Suspend)

**Request:**
```http
PATCH /api/v1/lists/{listId}/indices/{idx} HTTP/1.1
Host: status-issuer.example.com
Authorization: Bearer <issuer_token>
Content-Type: application/json

{
  "status": 1,
  "reason": "credential_compromised",
  "revokedAt": "2026-02-02T15:30:00Z"
}
```

**Status Values:**

| Value | Meaning |
|-------|---------|
| `0` | VALID |
| `1` | INVALID (revoked) |
| `2` | SUSPENDED |

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "idx": 12345,
  "previousStatus": 0,
  "currentStatus": 1,
  "updatedAt": "2026-02-02T15:30:00Z",
  "effectiveAt": "2026-02-02T15:35:00Z"
}
```

> **Note:** `effectiveAt` indicates when the Status List Token will be regenerated to include this change.

---

### 4.5 Batch Update Status

**Request:**
```http
POST /api/v1/lists/{listId}/batch HTTP/1.1
Host: status-issuer.example.com
Authorization: Bearer <issuer_token>
Content-Type: application/json

{
  "operation": "update",
  "updates": [
    { "idx": 12345, "status": 1 },
    { "idx": 12346, "status": 2 },
    { "idx": 12350, "status": 1 }
  ],
  "reason": "batch_revocation"
}
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "updated": 3,
  "results": [
    { "idx": 12345, "previousStatus": 0, "currentStatus": 1 },
    { "idx": 12346, "previousStatus": 0, "currentStatus": 2 },
    { "idx": 12350, "previousStatus": 0, "currentStatus": 1 }
  ],
  "effectiveAt": "2026-02-02T15:35:00Z"
}
```

---

### 4.6 Get Status List Token

**Request:**
```http
GET /api/v1/lists/{listId}/token HTTP/1.1
Host: status-issuer.example.com
Accept: application/statuslist+jwt
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/statuslist+jwt

eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyIiwidHlwIjoic3RhdHVzbGlzdCtqd3QifQ...
```

---

## 5. Token Issuance Flow

### 5.1 Complete Sequence

```
┌────────────┐     ┌───────────────┐     ┌─────────────────┐     ┌────────┐
│   Issuer   │     │ Status Issuer │     │ Status Provider │     │ Holder │
└─────┬──────┘     └───────┬───────┘     └────────┬────────┘     └───┬────┘
      │                    │                      │                  │
      │ 1. Allocate Index  │                      │                  │
      │───────────────────►│                      │                  │
      │                    │                      │                  │
      │ 2. Return idx, uri │                      │                  │
      │◄───────────────────│                      │                  │
      │                    │                      │                  │
      │ 3. Create token with status claim         │                  │
      │─────────────────────────────────────────────────────────────►│
      │    { status: { status_list: { idx, uri }}}│                  │
      │                    │                      │                  │
      │                    │ 4. Publish Status    │                  │
      │                    │    List Token        │                  │
      │                    │─────────────────────►│                  │
      │                    │                      │                  │
      │                    │                      │ 5. Host publicly │
      │                    │                      │◄─────────────────│
      │                    │                      │                  │
```

### 5.2 Pseudocode: Token Issuance with Status

```python
# Issuer's token issuance process

def issue_credential(holder_data, credential_type):
    # Step 1: Allocate index from Status Issuer
    allocation = status_issuer_client.allocate_index(
        list_id="list-abc123",
        token_id=generate_uuid(),
        expires_at=calculate_expiry(credential_type)
    )
    
    # Step 2: Build the credential with status claim
    credential = {
        "iss": "https://issuer.example.com",
        "sub": holder_data.subject_id,
        "iat": current_timestamp(),
        "exp": allocation.expires_at,
        
        # The status claim pointing to Status List
        "status": {
            "status_list": {
                "idx": allocation.idx,
                "uri": allocation.uri
            }
        },
        
        # Credential-specific claims
        "credentialSubject": holder_data.claims
    }
    
    # Step 3: Sign and return
    return sign_jwt(credential, issuer_private_key)
```

### 5.3 Pseudocode: Revocation

```python
# Issuer's revocation process

def revoke_credential(credential_id, reason):
    # Look up the index from internal records
    record = database.get_credential_record(credential_id)
    
    # Update status via Status Issuer API
    result = status_issuer_client.update_status(
        list_id=record.list_id,
        idx=record.idx,
        status=1,  # INVALID
        reason=reason
    )
    
    # Log the revocation
    audit_log.record_revocation(
        credential_id=credential_id,
        idx=record.idx,
        revoked_at=result.updated_at,
        effective_at=result.effective_at,
        reason=reason
    )
    
    return result
```

---

## 6. Status Update Propagation

### 6.1 Update Timeline

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    STATUS UPDATE PROPAGATION                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  T+0s        Issuer calls update API                                    │
│     │                                                                   │
│     ▼                                                                   │
│  T+1s        Status Issuer updates internal state                       │
│     │                                                                   │
│     ▼                                                                   │
│  T+Xs        Status Issuer regenerates Status List Token                │
│     │        (X = regeneration interval, e.g., 60 seconds)              │
│     ▼                                                                   │
│  T+Xs+1s     New Status List Token published to Provider                │
│     │                                                                   │
│     ▼                                                                   │
│  T+Xs+TTL    Relying Parties fetch updated list                         │
│              (TTL = time-to-live from previous token)                   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Regeneration Strategies

| Strategy | Description | Trade-off |
|----------|-------------|-----------|
| **Periodic** | Regenerate every N seconds | Predictable, may delay urgent revocations |
| **On-demand** | Regenerate immediately on update | Fast propagation, higher compute cost |
| **Batched** | Collect updates, regenerate in batches | Efficient, slight delay |
| **Hybrid** | Periodic + urgent flag for immediate | Best of both worlds |

### 6.3 Configuration Example

```json
{
  "regeneration": {
    "strategy": "hybrid",
    "periodicInterval": 300,
    "urgentStatuses": [1],
    "maxBatchSize": 1000,
    "batchWindow": 60
  },
  "statusListToken": {
    "ttl": 3600,
    "expiration": 86400
  }
}
```

---

## 7. Authentication & Authorization

### 7.1 Issuer Authentication

| Method | Description |
|--------|-------------|
| **OAuth 2.0 Client Credentials** | Standard, recommended for server-to-server |
| **Mutual TLS (mTLS)** | Strong authentication via certificates |
| **API Keys** | Simple, less secure |
| **JWT Bearer** | Signed assertion from Issuer |

### 7.2 Example: OAuth 2.0 Flow

```
┌──────────────┐                              ┌───────────────────┐
│    Issuer    │                              │   Status Issuer   │
└──────┬───────┘                              └─────────┬─────────┘
       │                                                │
       │ 1. POST /oauth/token                           │
       │    grant_type=client_credentials               │
       │    client_id=issuer-123                        │
       │    client_secret=***                           │
       │───────────────────────────────────────────────►│
       │                                                │
       │ 2. { "access_token": "eyJ...", "expires_in": 3600 }
       │◄───────────────────────────────────────────────│
       │                                                │
       │ 3. POST /api/v1/lists/{listId}/indices         │
       │    Authorization: Bearer eyJ...                │
       │───────────────────────────────────────────────►│
       │                                                │
```

### 7.3 Authorization Model

```json
{
  "issuers": [
    {
      "issuerId": "issuer-123",
      "name": "Example Corp",
      "permissions": {
        "lists": ["list-abc123", "list-def456"],
        "operations": ["allocate", "update", "read"]
      },
      "rateLimit": {
        "allocationsPerHour": 10000,
        "updatesPerHour": 5000
      }
    }
  ]
}
```

---

## 8. Error Handling

### 8.1 Error Response Format

```json
{
  "error": "index_allocation_failed",
  "message": "Status List is at capacity",
  "code": "CAPACITY_EXCEEDED",
  "details": {
    "listId": "list-abc123",
    "currentSize": 100000,
    "allocated": 100000
  },
  "timestamp": "2026-02-02T10:00:00Z",
  "requestId": "req-xyz789"
}
```

### 8.2 Common Errors

| Error Code | HTTP Status | Description |
|------------|-------------|-------------|
| `LIST_NOT_FOUND` | 404 | Status List doesn't exist |
| `INDEX_NOT_FOUND` | 404 | Index not allocated |
| `CAPACITY_EXCEEDED` | 409 | List is full |
| `INVALID_STATUS` | 400 | Status value not allowed for this list |
| `DOUBLE_ALLOCATION` | 409 | Index already allocated |
| `UNAUTHORIZED` | 401 | Invalid or missing credentials |
| `FORBIDDEN` | 403 | Issuer not authorized for this list |
| `RATE_LIMITED` | 429 | Too many requests |

### 8.3 Retry Strategy

```python
def call_status_issuer_with_retry(operation, max_retries=3):
    for attempt in range(max_retries):
        try:
            response = operation()
            return response
        except RateLimitError:
            wait_time = response.headers.get('Retry-After', 60)
            sleep(wait_time)
        except ServerError:
            sleep(exponential_backoff(attempt))
        except ClientError:
            raise  # Don't retry client errors
    
    raise MaxRetriesExceeded()
```

---

## 9. Webhooks (Push Notifications)

### 9.1 Event Types

| Event | Description |
|-------|-------------|
| `status_list.regenerated` | New Status List Token available |
| `status_list.capacity_warning` | List approaching capacity |
| `status_list.expired` | Status List Token expired |
| `index.status_changed` | Status was changed (by another authorized party) |

### 9.2 Webhook Payload

```json
{
  "event": "status_list.regenerated",
  "timestamp": "2026-02-02T15:35:00Z",
  "data": {
    "listId": "list-abc123",
    "uri": "https://status-issuer.example.com/statuslists/list-abc123",
    "tokenHash": "sha256:abc123...",
    "changedIndices": 5,
    "nextRegeneration": "2026-02-02T15:40:00Z"
  }
}
```

### 9.3 Webhook Registration

```http
POST /api/v1/webhooks HTTP/1.1
Host: status-issuer.example.com
Authorization: Bearer <issuer_token>
Content-Type: application/json

{
  "url": "https://issuer.example.com/webhooks/status",
  "events": ["status_list.regenerated", "status_list.capacity_warning"],
  "secret": "webhook-secret-for-signature-verification"
}
```

---

## 10. Monitoring & Observability

### 10.1 Metrics to Track

| Metric | Description |
|--------|-------------|
| `allocations_total` | Total indices allocated |
| `allocations_rate` | Allocations per second |
| `updates_total` | Total status updates |
| `updates_by_status` | Updates grouped by status type |
| `list_utilization` | Percentage of list capacity used |
| `regeneration_latency` | Time to regenerate Status List Token |
| `api_latency` | Response time for API calls |

### 10.2 Health Check Endpoint

```http
GET /api/v1/health HTTP/1.1
Host: status-issuer.example.com
```

```json
{
  "status": "healthy",
  "version": "1.2.0",
  "components": {
    "database": "healthy",
    "signing": "healthy",
    "provider": "healthy"
  },
  "lists": {
    "total": 10,
    "healthy": 10
  }
}
```

---

## 11. Best Practices Summary

### For Token Issuers

| Practice | Reason |
|----------|--------|
| ✅ Store `(tokenId, idx, listId)` mapping | Track which token has which index |
| ✅ Handle allocation failures gracefully | Retry or fail issuance |
| ✅ Use batch allocation for bulk issuance | More efficient |
| ✅ Set appropriate token expiration | Aligns with Status List lifecycle |
| ✅ Implement audit logging | Compliance and debugging |

### For Status Issuers

| Practice | Reason |
|----------|--------|
| ✅ Use random/non-sequential indices | Privacy (prevent inference) |
| ✅ Initialize with default 0x00 | Better compression |
| ✅ Prevent double allocation | Avoid tracking vectors |
| ✅ Support batch operations | Efficiency for issuers |
| ✅ Implement rate limiting | Prevent abuse |
| ✅ Use highest DEFLATE compression | Smaller payloads |

---

## 12. Example Integration Code

### 12.1 Status Issuer Client (Python)

```python
import requests
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class IndexAllocation:
    idx: int
    uri: str
    status: int

@dataclass
class StatusUpdate:
    idx: int
    previous_status: int
    current_status: int
    effective_at: str

class StatusIssuerClient:
    def __init__(self, base_url: str, client_id: str, client_secret: str):
        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self._token = None
    
    def _get_token(self) -> str:
        if self._token is None or self._token_expired():
            response = requests.post(
                f"{self.base_url}/oauth/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret
                }
            )
            self._token = response.json()["access_token"]
        return self._token
    
    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._get_token()}"}
    
    def allocate_index(
        self, 
        list_id: str, 
        token_id: Optional[str] = None,
        initial_status: int = 0
    ) -> IndexAllocation:
        response = requests.post(
            f"{self.base_url}/api/v1/lists/{list_id}/indices",
            headers=self._headers(),
            json={
                "tokenId": token_id,
                "initialStatus": initial_status
            }
        )
        response.raise_for_status()
        data = response.json()
        return IndexAllocation(
            idx=data["idx"],
            uri=data["uri"],
            status=data["status"]
        )
    
    def update_status(
        self, 
        list_id: str, 
        idx: int, 
        status: int,
        reason: Optional[str] = None
    ) -> StatusUpdate:
        response = requests.patch(
            f"{self.base_url}/api/v1/lists/{list_id}/indices/{idx}",
            headers=self._headers(),
            json={
                "status": status,
                "reason": reason
            }
        )
        response.raise_for_status()
        data = response.json()
        return StatusUpdate(
            idx=data["idx"],
            previous_status=data["previousStatus"],
            current_status=data["currentStatus"],
            effective_at=data["effectiveAt"]
        )
    
    def batch_allocate(
        self, 
        list_id: str, 
        count: int,
        token_ids: Optional[List[str]] = None
    ) -> List[IndexAllocation]:
        response = requests.post(
            f"{self.base_url}/api/v1/lists/{list_id}/batch",
            headers=self._headers(),
            json={
                "operation": "allocate",
                "count": count,
                "tokenIds": token_ids
            }
        )
        response.raise_for_status()
        data = response.json()
        return [
            IndexAllocation(idx=a["idx"], uri=data["uri"], status=0)
            for a in data["allocations"]
        ]
```

### 12.2 Usage Example

```python
# Initialize client
client = StatusIssuerClient(
    base_url="https://status-issuer.example.com",
    client_id="issuer-123",
    client_secret="secret"
)

# Issue a credential
def issue_credential(holder_id: str, claims: dict) -> str:
    # 1. Allocate index
    allocation = client.allocate_index(
        list_id="list-abc123",
        token_id=f"cred-{holder_id}-{uuid4()}"
    )
    
    # 2. Build credential
    credential = {
        "iss": "https://issuer.example.com",
        "sub": holder_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + 86400 * 365,
        "status": {
            "status_list": {
                "idx": allocation.idx,
                "uri": allocation.uri
            }
        },
        **claims
    }
    
    # 3. Sign and return
    return jwt.encode(credential, private_key, algorithm="ES256")

# Revoke a credential
def revoke_credential(list_id: str, idx: int, reason: str):
    result = client.update_status(
        list_id=list_id,
        idx=idx,
        status=1,  # INVALID
        reason=reason
    )
    print(f"Revoked index {idx}, effective at {result.effective_at}")
```

---

*This guide covers the integration between Token Issuers and Status Issuers for managing token status using the Token Status List specification.*
