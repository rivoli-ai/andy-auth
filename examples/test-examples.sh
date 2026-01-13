#!/bin/bash
#
# Test all Andy Auth example projects
# Reports compilation and runtime status for each example
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Results arrays
declare -a RESULTS_NAME
declare -a RESULTS_COMPILE
declare -a RESULTS_RUN
declare -a RESULTS_NOTES

# Helper functions
print_header() {
    echo ""
    echo "========================================"
    echo " $1"
    echo "========================================"
}

print_status() {
    local name="$1"
    local status="$2"
    local note="$3"

    if [ "$status" = "OK" ]; then
        echo -e "  ${GREEN}✓${NC} $name"
    elif [ "$status" = "SKIP" ]; then
        echo -e "  ${YELLOW}○${NC} $name ${YELLOW}(skipped: $note)${NC}"
    else
        echo -e "  ${RED}✗${NC} $name ${RED}($note)${NC}"
    fi
}

wait_for_server() {
    local port="$1"
    local max_attempts="${2:-10}"
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        if curl -s "http://localhost:$port" > /dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
        ((attempt++))
    done
    return 1
}

kill_port() {
    local port="$1"
    lsof -ti:"$port" 2>/dev/null | xargs kill -9 2>/dev/null || true
}

add_result() {
    RESULTS_NAME+=("$1")
    RESULTS_COMPILE+=("$2")
    RESULTS_RUN+=("$3")
    RESULTS_NOTES+=("$4")
}

# Suppress SSL warnings for Python
export PYTHONWARNINGS="ignore:Unverified HTTPS request"

print_header "Testing Andy Auth Examples"
echo "Date: $(date)"
echo ""

# ============================================
# C# / ASP.NET Core
# ============================================
echo "Testing: C# / ASP.NET Core..."
cd "$SCRIPT_DIR/csharp-web"

COMPILE_OK="FAIL"
RUN_OK="FAIL"
NOTES=""

if dotnet build -v q 2>&1 | grep -q "Build succeeded"; then
    COMPILE_OK="OK"

    kill_port 5000
    dotnet run --no-build > /dev/null 2>&1 &
    PID=$!

    if wait_for_server 5000; then
        RESPONSE=$(curl -s http://localhost:5000 2>&1)
        if echo "$RESPONSE" | grep -q "Andy Auth"; then
            RUN_OK="OK"
        else
            NOTES="No response"
        fi
    else
        NOTES="Server didn't start"
    fi

    kill $PID 2>/dev/null || true
    wait $PID 2>/dev/null || true
else
    NOTES="Build failed"
fi

add_result "C# / ASP.NET Core" "$COMPILE_OK" "$RUN_OK" "$NOTES"
print_status "C# / ASP.NET Core" "$RUN_OK" "$NOTES"

# ============================================
# Python / Flask
# ============================================
echo "Testing: Python / Flask..."
cd "$SCRIPT_DIR/python-flask"

COMPILE_OK="FAIL"
RUN_OK="FAIL"
NOTES=""

if python3 -m py_compile app.py andy_auth_client.py 2>/dev/null; then
    COMPILE_OK="OK"

    kill_port 5002
    python3 -c "
import urllib3; urllib3.disable_warnings()
import sys; sys.path.insert(0, '.')
from app import app
app.run(port=5002, debug=False, use_reloader=False)
" > /dev/null 2>&1 &
    PID=$!

    if wait_for_server 5002; then
        RESPONSE=$(curl -s http://localhost:5002 2>&1)
        if echo "$RESPONSE" | grep -q "Andy Auth"; then
            RUN_OK="OK"
        else
            NOTES="No response"
        fi
    else
        NOTES="Server didn't start"
    fi

    kill $PID 2>/dev/null || true
    wait $PID 2>/dev/null || true
else
    NOTES="Syntax error"
fi

add_result "Python / Flask" "$COMPILE_OK" "$RUN_OK" "$NOTES"
print_status "Python / Flask" "$RUN_OK" "$NOTES"

# ============================================
# JavaScript / Express
# ============================================
echo "Testing: JavaScript / Express..."
cd "$SCRIPT_DIR/javascript-express"

COMPILE_OK="FAIL"
RUN_OK="FAIL"
NOTES=""

if [ -d "node_modules" ] || npm install --silent 2>/dev/null; then
    COMPILE_OK="OK"

    kill_port 3000
    node server.js > /dev/null 2>&1 &
    PID=$!

    if wait_for_server 3000; then
        RESPONSE=$(curl -s http://localhost:3000 2>&1)
        if echo "$RESPONSE" | grep -q "Andy Auth"; then
            RUN_OK="OK"
        else
            NOTES="No response"
        fi
    else
        NOTES="Server didn't start"
    fi

    kill $PID 2>/dev/null || true
    wait $PID 2>/dev/null || true
else
    NOTES="npm install failed"
fi

add_result "JavaScript / Express" "$COMPILE_OK" "$RUN_OK" "$NOTES"
print_status "JavaScript / Express" "$RUN_OK" "$NOTES"

# ============================================
# TypeScript / Express
# ============================================
echo "Testing: TypeScript / Express..."
cd "$SCRIPT_DIR/typescript-express"

COMPILE_OK="FAIL"
RUN_OK="FAIL"
NOTES=""

if [ -d "node_modules" ] || npm install --silent 2>/dev/null; then
    if [ -f "dist/server.js" ] || npm run build --silent 2>/dev/null; then
        COMPILE_OK="OK"

        kill_port 3001
        PORT=3001 node dist/server.js > /dev/null 2>&1 &
        PID=$!

        if wait_for_server 3001; then
            RESPONSE=$(curl -s http://localhost:3001 2>&1)
            if echo "$RESPONSE" | grep -q "Andy Auth"; then
                RUN_OK="OK"
            else
                NOTES="No response"
            fi
        else
            NOTES="Server didn't start"
        fi

        kill $PID 2>/dev/null || true
        wait $PID 2>/dev/null || true
    else
        NOTES="TypeScript compilation failed"
    fi
else
    NOTES="npm install failed"
fi

add_result "TypeScript / Express" "$COMPILE_OK" "$RUN_OK" "$NOTES"
print_status "TypeScript / Express" "$RUN_OK" "$NOTES"

# ============================================
# Java / Spring Boot
# ============================================
echo "Testing: Java / Spring Boot..."
cd "$SCRIPT_DIR/java-spring"

COMPILE_OK="FAIL"
RUN_OK="SKIP"
NOTES=""

if command -v mvn &> /dev/null; then
    if mvn compile -q 2>&1; then
        COMPILE_OK="OK"
        RUN_OK="SKIP"
        NOTES="Requires auth server for OIDC discovery"
    else
        NOTES="Maven build failed"
    fi
else
    COMPILE_OK="SKIP"
    RUN_OK="SKIP"
    NOTES="Maven not installed"
fi

add_result "Java / Spring Boot" "$COMPILE_OK" "$RUN_OK" "$NOTES"
if [ "$COMPILE_OK" = "OK" ]; then
    print_status "Java / Spring Boot" "SKIP" "$NOTES"
else
    print_status "Java / Spring Boot" "$COMPILE_OK" "$NOTES"
fi

# ============================================
# Go
# ============================================
echo "Testing: Go..."
cd "$SCRIPT_DIR/go-oauth"

COMPILE_OK="FAIL"
RUN_OK="FAIL"
NOTES=""

if command -v go &> /dev/null; then
    if go build -o /tmp/go-oauth-test . 2>/dev/null; then
        COMPILE_OK="OK"

        kill_port 8080
        /tmp/go-oauth-test > /dev/null 2>&1 &
        PID=$!

        if wait_for_server 8080; then
            RESPONSE=$(curl -s http://localhost:8080 2>&1)
            if echo "$RESPONSE" | grep -q "Andy Auth"; then
                RUN_OK="OK"
            else
                NOTES="No response"
            fi
        else
            NOTES="Server didn't start"
        fi

        kill $PID 2>/dev/null || true
        wait $PID 2>/dev/null || true
        rm -f /tmp/go-oauth-test
    else
        NOTES="Go build failed"
    fi
else
    COMPILE_OK="SKIP"
    RUN_OK="SKIP"
    NOTES="Go not installed"
fi

add_result "Go" "$COMPILE_OK" "$RUN_OK" "$NOTES"
print_status "Go" "$RUN_OK" "$NOTES"

# ============================================
# Rust / Axum
# ============================================
echo "Testing: Rust / Axum..."
cd "$SCRIPT_DIR/rust-oauth"

COMPILE_OK="FAIL"
RUN_OK="FAIL"
NOTES=""

if command -v cargo &> /dev/null; then
    if cargo build --release -q 2>/dev/null; then
        COMPILE_OK="OK"

        kill_port 3002
        PORT=3002 ./target/release/andy-auth-rust-example > /dev/null 2>&1 &
        PID=$!

        if wait_for_server 3002; then
            RESPONSE=$(curl -s http://localhost:3002 2>&1)
            if echo "$RESPONSE" | grep -q "Andy Auth"; then
                RUN_OK="OK"
            else
                NOTES="No response"
            fi
        else
            NOTES="Server didn't start"
        fi

        kill $PID 2>/dev/null || true
        wait $PID 2>/dev/null || true
    else
        NOTES="Cargo build failed"
    fi
else
    COMPILE_OK="SKIP"
    RUN_OK="SKIP"
    NOTES="Rust/Cargo not installed"
fi

add_result "Rust / Axum" "$COMPILE_OK" "$RUN_OK" "$NOTES"
print_status "Rust / Axum" "$RUN_OK" "$NOTES"

# ============================================
# Summary
# ============================================
print_header "Summary"

# Count results
COMPILE_PASS=0
COMPILE_FAIL=0
COMPILE_SKIP=0
RUN_PASS=0
RUN_FAIL=0
RUN_SKIP=0

for i in "${!RESULTS_NAME[@]}"; do
    case "${RESULTS_COMPILE[$i]}" in
        OK) ((COMPILE_PASS++)) ;;
        FAIL) ((COMPILE_FAIL++)) ;;
        SKIP) ((COMPILE_SKIP++)) ;;
    esac
    case "${RESULTS_RUN[$i]}" in
        OK) ((RUN_PASS++)) ;;
        FAIL) ((RUN_FAIL++)) ;;
        SKIP) ((RUN_SKIP++)) ;;
    esac
done

# Print table
printf "\n%-25s %-12s %-12s %s\n" "Example" "Compiles" "Runs" "Notes"
printf "%-25s %-12s %-12s %s\n" "-------" "--------" "----" "-----"

for i in "${!RESULTS_NAME[@]}"; do
    NAME="${RESULTS_NAME[$i]}"

    if [ "${RESULTS_COMPILE[$i]}" = "OK" ]; then
        COMPILE="${GREEN}✓ OK${NC}"
    elif [ "${RESULTS_COMPILE[$i]}" = "SKIP" ]; then
        COMPILE="${YELLOW}○ Skip${NC}"
    else
        COMPILE="${RED}✗ Fail${NC}"
    fi

    if [ "${RESULTS_RUN[$i]}" = "OK" ]; then
        RUN="${GREEN}✓ OK${NC}"
    elif [ "${RESULTS_RUN[$i]}" = "SKIP" ]; then
        RUN="${YELLOW}○ Skip${NC}"
    else
        RUN="${RED}✗ Fail${NC}"
    fi

    printf "%-25s %-22b %-22b %s\n" "$NAME" "$COMPILE" "$RUN" "${RESULTS_NOTES[$i]}"
done

echo ""
echo "Compilation: $COMPILE_PASS passed, $COMPILE_FAIL failed, $COMPILE_SKIP skipped"
echo "Runtime:     $RUN_PASS passed, $RUN_FAIL failed, $RUN_SKIP skipped"
echo ""

# Exit with error if any failures
if [ $COMPILE_FAIL -gt 0 ] || [ $RUN_FAIL -gt 0 ]; then
    exit 1
fi

exit 0
