# Bytelocker Makefile
# Run tests and manage the project

.PHONY: test test-verbose test-coverage test-ci clean help

# Default target
all: test

# Run all tests
test:
	@echo "Running Bytelocker test suite..."
	@busted spec/

# Run tests with verbose output
test-verbose:
	@busted --verbose spec/

# Run tests with coverage
test-coverage:
	@busted --coverage spec/
	@luacov
	@echo "\nCoverage Summary:"
	@cat luacov.report.out | grep -A 1000 "^Summary" | head -50

# Run individual test files
test-bit:
	@busted spec/bit_operations_spec.lua

test-ciphers:
	@busted spec/ciphers_spec.lua

test-password:
	@busted spec/password_cipher_spec.lua

test-base64:
	@busted spec/base64_spec.lua

test-format:
	@busted spec/format_detection_spec.lua

test-roundtrip:
	@busted spec/encryption_roundtrip_spec.lua

test-edge:
	@busted spec/edge_cases_spec.lua

test-integration:
	@busted spec/integration_spec.lua

# CI mode (TAP output for CI systems)
test-ci:
	@busted --output=TAP spec/

# Clean up test artifacts
clean:
	@rm -f luacov.stats.out luacov.report.out
	@rm -rf /tmp/bytelocker_test_data
	@echo "Cleaned up test artifacts"

# Install test dependencies
deps:
	@echo "Installing test dependencies..."
	luarocks install busted
	luarocks install luacov
	@echo "Done!"

# Help
help:
	@echo "Bytelocker Test Suite"
	@echo ""
	@echo "Usage:"
	@echo "  make test          - Run all tests"
	@echo "  make test-verbose  - Run tests with verbose output"
	@echo "  make test-coverage - Run tests with coverage report"
	@echo "  make test-ci       - Run tests in CI mode (TAP output)"
	@echo ""
	@echo "Individual test suites:"
	@echo "  make test-bit         - Bit operations tests"
	@echo "  make test-ciphers     - Cipher implementation tests"
	@echo "  make test-password    - Password/cipher management tests"
	@echo "  make test-base64      - Base64 encoding/decoding tests"
	@echo "  make test-format      - Format detection tests"
	@echo "  make test-roundtrip   - Encryption roundtrip tests"
	@echo "  make test-edge        - Edge case tests"
	@echo "  make test-integration - Integration tests"
	@echo ""
	@echo "Other:"
	@echo "  make deps   - Install test dependencies"
	@echo "  make clean  - Clean up test artifacts"
	@echo "  make help   - Show this help message"
