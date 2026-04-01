#!/bin/bash
set -e

# Register client
REGISTRATION_RESPONSE=$(curl -k -s -X POST "https://localhost:7088/connect/register" \
    -H "Content-Type: application/json" \
    -d '{"client_name": "Debug Test","grant_types": ["client_credentials"],"token_endpoint_auth_method": "client_secret_post"}')

CLIENT_ID=$(echo "$REGISTRATION_RESPONSE" | jq -r '.client_id')
CLIENT_SECRET=$(echo "$REGISTRATION_RESPONSE" | jq -r '.client_secret')

echo "Client ID: $CLIENT_ID"

# Get token WITH resource parameter
echo -e "\n=== Getting token WITH resource parameter ==="
TOKEN_RESPONSE=$(curl -k -s -X POST "https://localhost:7088/connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials&client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&resource=https://localhost:7001/mcp")

echo "$TOKEN_RESPONSE" | jq .

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')

# Introspect token
echo -e "\n=== Token Introspection Response ==="
INTROSPECT_RESPONSE=$(curl -k -s -X POST "https://localhost:7088/connect/introspect" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "token=${ACCESS_TOKEN}&client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}")

echo "$INTROSPECT_RESPONSE" | jq .

# Try to decode if it's a JWT
echo -e "\n=== Attempting JWT decode ==="
if [[ "$ACCESS_TOKEN" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]]; then
    echo "Token appears to be JWT format"
    PAYLOAD=$(echo "$ACCESS_TOKEN" | cut -d. -f2)
    # Add padding if needed
    PADDING=$((4 - ${#PAYLOAD} % 4))
    if [ $PADDING -ne 4 ]; then
        PAYLOAD="${PAYLOAD}$(printf '=' %.0s $(seq 1 $PADDING))"
    fi
    echo "$PAYLOAD" | base64 -d 2>/dev/null | jq . || echo "Not a valid JWT payload"
else
    echo "Token is opaque (reference token)"
fi

# Cleanup
curl -k -s -X DELETE "https://localhost:7088/connect/register/${CLIENT_ID}" \
    -H "Authorization: Bearer $(echo "$REGISTRATION_RESPONSE" | jq -r '.registration_access_token')" > /dev/null
