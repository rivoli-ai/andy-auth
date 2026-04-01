#!/bin/bash

###############################################################################
# Wait for Railway Deployment and Test UAT
#
# This script waits for Railway to finish deploying and then runs the
# automated MCP compliance test against UAT.
###############################################################################

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}Waiting for Railway deployment to complete...${NC}"
echo ""
echo "Railway is deploying the latest changes to UAT."
echo "This typically takes 3-5 minutes."
echo ""
echo "You can monitor the deployment at:"
echo "https://railway.app/"
echo ""

# Wait intervals: 30s, 1m, 1m, 1m, 2m (total ~5.5 minutes)
WAIT_TIMES=(30 60 60 60 120)

for i in "${!WAIT_TIMES[@]}"; do
    WAIT_TIME=${WAIT_TIMES[$i]}
    ATTEMPT=$((i + 1))

    echo -e "${BLUE}Attempt $ATTEMPT/${#WAIT_TIMES[@]}: Waiting ${WAIT_TIME}s before checking...${NC}"
    sleep $WAIT_TIME

    echo "Checking if UAT is ready..."

    # Try to fetch discovery document
    if curl -s --max-time 5 "https://andy-auth-uat-api-production.up.railway.app/.well-known/openid-configuration" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ UAT is responding!${NC}"
        echo ""
        echo "Waiting 10 more seconds to ensure deployment is fully complete..."
        sleep 10

        echo ""
        echo -e "${GREEN}Running MCP compliance test on UAT...${NC}"
        echo ""

        ./test-mcp-automated.sh uat

        exit 0
    else
        echo -e "${YELLOW}Not ready yet, continuing to wait...${NC}"
        echo ""
    fi
done

echo ""
echo -e "${YELLOW}Deployment is taking longer than expected.${NC}"
echo "Please check the Railway dashboard and run manually once ready:"
echo ""
echo "  ./test-mcp-automated.sh uat"
echo ""
