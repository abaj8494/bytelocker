#!/bin/bash
# Bytelocker Test Suite Runner
# Requires: busted (Lua testing framework)
#
# Installation:
#   luarocks install busted
#   luarocks install luacov (optional, for coverage)
#
# Usage:
#   ./run_tests.sh           # Run all tests
#   ./run_tests.sh -v        # Verbose output
#   ./run_tests.sh -c        # With coverage
#   ./run_tests.sh <file>    # Run specific test file

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}  Bytelocker Test Suite${NC}"
echo -e "${GREEN}======================================${NC}"
echo

# Check for busted
if ! command -v busted &> /dev/null; then
    echo -e "${RED}Error: busted is not installed${NC}"
    echo "Install with: luarocks install busted"
    exit 1
fi

# Check for LuaJIT (required for bit operations)
if ! command -v luajit &> /dev/null; then
    echo -e "${YELLOW}Warning: LuaJIT not found, using standard lua${NC}"
    echo "Some bit operations may not work correctly"
    LUA_CMD="lua"
else
    LUA_CMD="luajit"
fi

# Create temp directory for test data
mkdir -p /tmp/bytelocker_test_data

# Parse arguments
COVERAGE=""
VERBOSE=""
SPECIFIC_FILE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--coverage)
            COVERAGE="--coverage"
            shift
            ;;
        -v|--verbose)
            VERBOSE="--verbose"
            shift
            ;;
        *)
            SPECIFIC_FILE="$1"
            shift
            ;;
    esac
done

# Run tests
echo -e "Running tests with ${LUA_CMD}..."
echo

if [ -n "$SPECIFIC_FILE" ]; then
    echo -e "${YELLOW}Running specific test file: ${SPECIFIC_FILE}${NC}"
    busted $VERBOSE $COVERAGE --lua=$LUA_CMD "$SPECIFIC_FILE"
else
    echo -e "${YELLOW}Running all test suites:${NC}"
    echo "  - bit_operations_spec.lua"
    echo "  - ciphers_spec.lua"
    echo "  - password_cipher_spec.lua"
    echo "  - base64_spec.lua"
    echo "  - format_detection_spec.lua"
    echo "  - encryption_roundtrip_spec.lua"
    echo "  - edge_cases_spec.lua"
    echo "  - integration_spec.lua"
    echo

    busted $VERBOSE $COVERAGE --lua=$LUA_CMD spec/
fi

# Show coverage report if requested
if [ -n "$COVERAGE" ]; then
    echo
    echo -e "${YELLOW}Coverage Report:${NC}"
    if command -v luacov &> /dev/null; then
        luacov
        cat luacov.report.out | head -100
    else
        echo "Install luacov for coverage reports: luarocks install luacov"
    fi
fi

# Cleanup
rm -rf /tmp/bytelocker_test_data

echo
echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}  Test Suite Complete${NC}"
echo -e "${GREEN}======================================${NC}"
