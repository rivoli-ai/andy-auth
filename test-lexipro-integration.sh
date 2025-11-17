#!/bin/bash

# Test script for Andy.Auth + Lexipro integration
# This script gets an OAuth token from Andy.Auth and calls Lexipro API

set -e

echo "========================================="
echo "Andy.Auth + Lexipro Integration Test"
echo "========================================="
echo ""

# Configuration
ANDY_AUTH_URL="https://localhost:7088"
LEXIPRO_API_URL="https://localhost:7156"
CLIENT_ID="lexipro-api"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}Step 1: Check Andy.Auth.Server health${NC}"
if curl -k -s "${ANDY_AUTH_URL}/health" > /dev/null; then
    echo -e "${GREEN}✓ Andy.Auth.Server is running${NC}"
else
    echo -e "${RED}✗ Andy.Auth.Server is not responding${NC}"
    echo "Please start it with: cd src/Andy.Auth.Server && dotnet run"
    exit 1
fi

echo ""
echo -e "${BLUE}Step 2: Check Lexipro API health${NC}"
if curl -k -s "${LEXIPRO_API_URL}/health" > /dev/null; then
    echo -e "${GREEN}✓ Lexipro API is running${NC}"
else
    echo -e "${RED}✗ Lexipro API is not responding${NC}"
    echo "Please start it with: cd ../lexipro/src/Lexipro.Api && dotnet run"
    exit 1
fi

echo ""
echo -e "${BLUE}Step 3: Get OpenID Configuration${NC}"
echo "Fetching from: ${ANDY_AUTH_URL}/.well-known/openid-configuration"
OIDC_CONFIG=$(curl -k -s "${ANDY_AUTH_URL}/.well-known/openid-configuration")
TOKEN_ENDPOINT=$(echo $OIDC_CONFIG | grep -o '"token_endpoint":"[^"]*' | cut -d'"' -f4)
echo -e "${GREEN}✓ Token endpoint: ${TOKEN_ENDPOINT}${NC}"

echo ""
echo -e "${BLUE}Step 4: Get OAuth Access Token${NC}"
echo "Note: For this test, we'll use the Resource Owner Password Credentials flow"
echo "with the test user credentials."
echo ""
echo "Test User Credentials:"
echo "  Email: test@andy.local"
echo "  Password: Test123!"
echo ""

# Try to get token using password grant (ROPC)
echo "Attempting to get access token..."
TOKEN_RESPONSE=$(curl -k -s -X POST "${TOKEN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "username=test@andy.local" \
  -d "password=Test123!" \
  -d "client_id=${CLIENT_ID}" \
  -d "scope=openid profile email" 2>&1)

# Check if we got an access token
if echo "$TOKEN_RESPONSE" | grep -q "access_token"; then
    ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
    echo -e "${GREEN}✓ Successfully obtained access token!${NC}"
    echo "Token (first 50 chars): ${ACCESS_TOKEN:0:50}..."
else
    echo -e "${RED}✗ Failed to get access token${NC}"
    echo "Response: $TOKEN_RESPONSE"
    echo ""
    echo "This might mean:"
    echo "1. Password grant is not enabled (expected for production)"
    echo "2. We need to use Authorization Code flow instead"
    echo ""
    echo "Alternative: Get a token manually"
    echo "1. Visit: ${ANDY_AUTH_URL}/Account/Login"
    echo "2. Login with: test@andy.local / Test123!"
    echo "3. Use browser dev tools to capture the token"
    echo "4. Then run: export ACCESS_TOKEN='your-token-here'"
    echo "5. And test: curl -k -H \"Authorization: Bearer \$ACCESS_TOKEN\" ${LEXIPRO_API_URL}/api/books"
    exit 1
fi

echo ""
echo -e "${BLUE}Step 5: Test Lexipro API with Access Token${NC}"
echo "Calling: ${LEXIPRO_API_URL}/api/books"
echo ""

API_RESPONSE=$(curl -k -s -w "\n%{http_code}" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Accept: application/json" \
  "${LEXIPRO_API_URL}/api/books")

# Extract HTTP status code (last line)
HTTP_CODE=$(echo "$API_RESPONSE" | tail -n1)
# Extract response body (everything except last line)
RESPONSE_BODY=$(echo "$API_RESPONSE" | sed '$d')

echo "HTTP Status: $HTTP_CODE"
echo ""

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✓ Successfully called Lexipro API!${NC}"
    echo ""
    echo "Response:"
    echo "$RESPONSE_BODY" | head -20
    if [ $(echo "$RESPONSE_BODY" | wc -l) -gt 20 ]; then
        echo "... (truncated)"
    fi
elif [ "$HTTP_CODE" = "401" ]; then
    echo -e "${RED}✗ Authentication failed (401 Unauthorized)${NC}"
    echo "The token was rejected by Lexipro API."
    echo ""
    echo "Response:"
    echo "$RESPONSE_BODY"
else
    echo -e "${RED}✗ API call failed with status: $HTTP_CODE${NC}"
    echo ""
    echo "Response:"
    echo "$RESPONSE_BODY"
fi

echo ""
echo -e "${BLUE}Step 6: Test MCP OAuth Protected Resource Metadata${NC}"
echo "Calling: ${LEXIPRO_API_URL}/.well-known/oauth-protected-resource"
MCP_METADATA=$(curl -k -s "${LEXIPRO_API_URL}/.well-known/oauth-protected-resource")
echo "$MCP_METADATA" | head -10
echo ""

if echo "$MCP_METADATA" | grep -q "andy-auth"; then
    echo -e "${GREEN}✓ MCP metadata correctly points to Andy.Auth!${NC}"
elif echo "$MCP_METADATA" | grep -q "localhost:7088"; then
    echo -e "${GREEN}✓ MCP metadata correctly points to Andy.Auth!${NC}"
else
    echo -e "${RED}⚠ MCP metadata might not be configured correctly${NC}"
fi

echo ""
echo "========================================="
echo -e "${GREEN}Integration Test Complete!${NC}"
echo "========================================="
echo ""
echo "Summary:"
echo "  Andy.Auth.Server: ${ANDY_AUTH_URL}"
echo "  Lexipro API: ${LEXIPRO_API_URL}"
echo "  Authentication: ✓"
echo "  API Access: $([ "$HTTP_CODE" = "200" ] && echo '✓' || echo '✗')"
echo ""
