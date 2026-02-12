#!/bin/bash
#
# MCP Security Testing Script (Bash version)
#
# Quick security tests for any MCP server endpoint.
# Tests authentication, authorization, and common security issues.
#
# Usage:
#   ./test_mcp_security.sh http://localhost:8000/mcp
#   ./test_mcp_security.sh https://mcp.example.com/mcp --token YOUR_TOKEN
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Parse arguments
BASE_URL="$1"
BEARER_TOKEN=""

if [ -z "$BASE_URL" ]; then
    echo "Usage: $0 <mcp-url> [--token TOKEN]"
    echo ""
    echo "Examples:"
    echo "  $0 http://localhost:8000/mcp"
    echo "  $0 https://mcp.example.com/mcp --token YOUR_TOKEN"
    exit 1
fi

# Check for --token flag
if [ "$2" = "--token" ] && [ -n "$3" ]; then
    BEARER_TOKEN="$3"
fi

# Counters
PASSED=0
FAILED=0
WARNED=0

print_test() {
    echo -e "${BOLD}🔍 Test: $1${NC}"
}

print_pass() {
    echo -e "  ${GREEN}✅ PASS:${NC} $1"
    ((PASSED++))
}

print_fail() {
    echo -e "  ${RED}❌ FAIL:${NC} $1"
    ((FAILED++))
}

print_warn() {
    echo -e "  ${YELLOW}⚠️  WARN:${NC} $1"
    ((WARNED++))
}

print_info() {
    echo -e "  ${BLUE}ℹ️  INFO:${NC} $1"
}

print_header() {
    echo -e "\n${BOLD}${CYAN}============================================================${NC}"
    echo -e "${BOLD}${CYAN}$1${NC}"
    echo -e "${BOLD}${CYAN}============================================================${NC}\n"
}

# Header
print_header "MCP Security Testing"
echo -e "Target: $BASE_URL\n"

# Test 1: Unauthenticated access
print_test "Unauthenticated Access to tools/list"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  2>/dev/null || echo "000")

if [ "$STATUS" = "401" ] || [ "$STATUS" = "403" ]; then
    print_pass "Server requires authentication ($STATUS)"
elif [ "$STATUS" = "200" ]; then
    print_fail "🚨 SECURITY ISSUE: Server allows unauthenticated access!"
    
    # Try to get tools list
    RESPONSE=$(curl -s -X POST "$BASE_URL" \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' 2>/dev/null)
    
    if command -v jq &> /dev/null; then
        TOOLS_COUNT=$(echo "$RESPONSE" | jq -r '.result.tools | length' 2>/dev/null || echo "?")
        print_warn "Exposed $TOOLS_COUNT tools without authentication"
    fi
elif [ "$STATUS" = "000" ]; then
    print_fail "Server unreachable or connection failed"
else
    print_warn "Unexpected status code: $STATUS"
fi

# Test 2: Invalid token
print_test "Invalid Token Rejection"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer fake_invalid_token_12345" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  2>/dev/null || echo "000")

if [ "$STATUS" = "401" ] || [ "$STATUS" = "403" ]; then
    print_pass "Server rejects invalid tokens"
elif [ "$STATUS" = "200" ]; then
    print_fail "🚨 SECURITY ISSUE: Server accepts invalid tokens!"
else
    print_warn "Unexpected status code: $STATUS"
fi

# Test 3: Valid token (if provided)
if [ -n "$BEARER_TOKEN" ]; then
    print_test "Valid Token Access"
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL" \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer $BEARER_TOKEN" \
      -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
      2>/dev/null || echo "000")
    
    if [ "$STATUS" = "200" ]; then
        print_pass "Authenticated access successful"
    elif [ "$STATUS" = "401" ] || [ "$STATUS" = "403" ]; then
        print_fail "Valid token was rejected (check if token is still valid)"
    else
        print_warn "Unexpected status code: $STATUS"
    fi
else
    print_test "Valid Token Access (SKIPPED - no token provided)"
    print_info "Use --token YOUR_TOKEN to test with valid token"
fi

# Test 4: Unauthorized tool execution
print_test "Unauthorized Tool Execution"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test_tool","arguments":{}}}' \
  2>/dev/null || echo "000")

if [ "$STATUS" = "401" ] || [ "$STATUS" = "403" ]; then
    print_pass "Tool execution requires authentication"
elif [ "$STATUS" = "200" ]; then
    print_fail "🚨 SECURITY ISSUE: Can execute tools without auth!"
elif [ "$STATUS" = "404" ] || [ "$STATUS" = "400" ]; then
    print_warn "Tool not found (but endpoint might be open)"
else
    print_info "Status: $STATUS"
fi

# Test 5: Unauthorized initialize
print_test "Unauthorized initialize"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"}}}' \
  2>/dev/null || echo "000")

if [ "$STATUS" = "401" ] || [ "$STATUS" = "403" ]; then
    print_pass "Initialize requires authentication"
elif [ "$STATUS" = "200" ]; then
    print_warn "Initialize method is open (may be intentional)"
else
    print_info "Status: $STATUS"
fi

# Test 6: Information disclosure
print_test "Error Information Disclosure"
RESPONSE=$(curl -s -X POST "$BASE_URL" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"invalid_method_xyz"}' \
  2>/dev/null)

DISCLOSED=()
if echo "$RESPONSE" | grep -q "/home/\|/usr/\|C:\\"; then
    DISCLOSED+=("file paths")
fi
if echo "$RESPONSE" | grep -qi "exception:\|traceback\|at line"; then
    DISCLOSED+=("stack traces")
fi

if [ ${#DISCLOSED[@]} -gt 0 ]; then
    print_warn "Error messages may disclose: ${DISCLOSED[*]}"
else
    print_pass "No obvious information disclosure in errors"
fi

# Summary
print_header "SUMMARY"
TOTAL=$((PASSED + FAILED + WARNED))

echo "Total Tests: $TOTAL"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo -e "${YELLOW}Warnings: $WARNED${NC}"
echo ""

if [ $FAILED -gt 0 ]; then
    echo -e "${RED}${BOLD}⚠️  SECURITY ISSUES DETECTED!${NC}"
    echo -e "${RED}Review failed tests above and fix issues.${NC}"
    echo ""
    exit 1
elif [ $WARNED -gt 0 ]; then
    echo -e "${YELLOW}⚠️  Some warnings detected. Review recommended.${NC}"
    echo ""
    exit 0
else
    echo -e "${GREEN}✅ All tests passed! Server appears secure.${NC}"
    echo ""
    exit 0
fi
