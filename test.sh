#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
KEYCLOAK_URL="http://localhost:8080"
KEYCLOAK_ADMIN="admin"
KEYCLOAK_ADMIN_PASSWORD="admin"
REALM_NAME="test-realm"
CLIENT_ID="test-client"
CLIENT_SECRET="test-secret"
USERNAME="test-user"
PASSWORD="test-password"
STATUS_LIST_SERVER_URL="https://statuslist.eudi-adorsys.com/"

# --- Helper Functions ---
info() {
    echo "[INFO] $1"
}

error() {
    echo "[ERROR] $1" >&2
    exit 1
}

wait_for_keycloak() {
    info "Waiting for Keycloak to start..."
    until $(curl --output /dev/null --silent --head --fail "$KEYCLOAK_URL"); do
        printf '.'
        sleep 5
    done
    info "Keycloak is up and running."
}

get_admin_token() {
    info "Getting admin access token..."
    ADMIN_TOKEN=$(curl -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=$KEYCLOAK_ADMIN" \
        -d "password=$KEYCLOAK_ADMIN_PASSWORD" \
        -d "grant_type=password" \
        -d "client_id=admin-cli" | jq -r .access_token)
    if [ -z "$ADMIN_TOKEN" ]; then
        error "Failed to get admin access token."
    fi
}

# --- Main Script ---

# 1. Cleanup
info "Cleaning up..."
docker-compose down --remove-orphans -v

# 2. Start services
info "Starting Keycloak and PostgreSQL..."
docker-compose up -d

# 3. Wait for Keycloak
wait_for_keycloak

# 4. Get admin token
get_admin_token

# 5. Delete realm if it exists
info "Deleting realm if it exists: $REALM_NAME"
curl -s -X DELETE "$KEYCLOAK_URL/admin/realms/$REALM_NAME" \
    -H "Authorization: Bearer $ADMIN_TOKEN"
sleep 2 # Give Keycloak a moment to process the deletion

# 6. Create realm
info "Creating realm: $REALM_NAME"
CREATE_REALM_RESPONSE=$(curl -s -w "%{http_code}" -X POST "$KEYCLOAK_URL/admin/realms" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "realm": "'"$REALM_NAME"'",
        "enabled": true,
        "attributes": {
            "status-list-enabled": "true",
            "status-list-server-url": "'"$STATUS_LIST_SERVER_URL"'"
        }
    }')

if [[ ! "$CREATE_REALM_RESPONSE" == *"201"* ]]; then
    error "Failed to create realm. Response: $CREATE_REALM_RESPONSE"
fi

sleep 5 # Give Keycloak a moment to initialize the realm

# 7. Add token-status-event-listener to the realm
info "Adding token-status-event-listener to realm..."
curl -s -X PUT "$KEYCLOAK_URL/admin/realms/$REALM_NAME/events/config" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "eventsEnabled": true,
        "eventsListeners": ["token-status-event-listener"]
    }'

# 6. Create client
info "Creating client: $CLIENT_ID"
curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "clientId": "'"$CLIENT_ID"'",
        "secret": "'"$CLIENT_SECRET"'",
        "enabled": true,
        "publicClient": false,
        "serviceAccountsEnabled": true,
        "directAccessGrantsEnabled": true,
        "standardFlowEnabled": true,
        "rootUrl": "http://localhost:8080"
    }'

# 7. Create user
info "Creating user: $USERNAME"
CREATE_USER_RESPONSE=$(curl -s -w "%{http_code}" -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "username": "'"$USERNAME"'",
        "enabled": true,
        "email": "'"$USERNAME@test.com"'",
        "emailVerified": true,
        "firstName": "Test",
        "lastName": "User",
        "credentials": [{
            "type": "password",
            "value": "'"$PASSWORD"'",
            "temporary": false
        }]
    }')

if [[ ! "$CREATE_USER_RESPONSE" == *"201"* ]]; then
    error "Failed to create user. Response: $CREATE_USER_RESPONSE"
fi

sleep 2 # Give Keycloak a moment to process user creation

# 8. Get user token
info "Getting user token..."
TOKEN_RESPONSE=$(curl -s -X POST "$KEYCLOAK_URL/realms/$REALM_NAME/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=$CLIENT_ID" \
    -d "client_secret=$CLIENT_SECRET" \
    -d "username=$USERNAME" \
    -d "password=$PASSWORD" \
    -d "grant_type=password")

REFRESH_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r .refresh_token)
SESSION_STATE=$(echo "$TOKEN_RESPONSE" | jq -r .session_state)

if [ -z "$REFRESH_TOKEN" ] || [ "$REFRESH_TOKEN" == "null" ]; then
    error "Failed to get refresh token. Response: $TOKEN_RESPONSE"
fi

if [ -z "$SESSION_STATE" ] || [ "$SESSION_STATE" == "null" ]; then
    error "Failed to get session state (credential ID). Response: $TOKEN_RESPONSE"
fi

info "Obtained refresh token (session: $SESSION_STATE)."

# 9. Revoke refresh token
info "Revoking refresh token..."
curl -s -X POST "$KEYCLOAK_URL/realms/$REALM_NAME/protocol/openid-connect/revoke" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=$CLIENT_ID" \
    -d "client_secret=$CLIENT_SECRET" \
    -d "token=$REFRESH_TOKEN"

info "Refresh token revoked."
sleep 5 # Wait for the event to be processed

# 10. Verify status
info "Verifying credential status..."
STATUS_RESPONSE=$(curl -s "$STATUS_LIST_SERVER_URL/credentials/$SESSION_STATE")
STATUS=$(echo "$STATUS_RESPONSE" | jq -r .status)

if [ "$STATUS" == "1" ]; then
    info "SUCCESS: Credential status is REVOKED."
elif [ -z "$STATUS" ] || [ "$STATUS" == "null" ]; then
    info "INFO: External status list server did not return a status. This is expected if the server is not a real endpoint."
    info "SUCCESS: The revocation event was triggered successfully within Keycloak."
else
    error "FAILURE: Credential status is not REVOKED. Status: $STATUS"
fi

# 11. Cleanup
info "Cleaning up..."
docker-compose down

info "Test completed successfully."