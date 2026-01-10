# Bytelocker Test Suite

Comprehensive test suite for the Bytelocker Neovim encryption plugin.

## Test Coverage

The test suite aims for 100% coverage across all functionality:

| Test File | Coverage Area |
|-----------|---------------|
| `bit_operations_spec.lua` | 8-bit rotate left/right (rol8, ror8) |
| `ciphers_spec.lua` | All cipher implementations (shift, xor, caesar) |
| `password_cipher_spec.lua` | Password/cipher persistence and management |
| `base64_spec.lua` | Base64 encoding/decoding |
| `format_detection_spec.lua` | Encrypted content detection |
| `encryption_roundtrip_spec.lua` | End-to-end encryption/decryption |
| `edge_cases_spec.lua` | Edge cases, unicode, binary, boundaries |
| `integration_spec.lua` | High-level API and workflows |

## Requirements

### LuaJIT + Busted (Recommended)

The tests require LuaJIT for the `bit` module and busted for the test framework.

```bash
# macOS (via Homebrew)
brew install luajit luarocks
luarocks --lua-version=5.1 install busted

# Ubuntu/Debian
sudo apt-get install luajit luarocks
sudo luarocks install busted

# Arch Linux
sudo pacman -S luajit luarocks
sudo luarocks install busted
```

### For Coverage Reports

```bash
luarocks install luacov
```

## Running Tests

### Using Make (Recommended)

```bash
# Run all tests
make test

# Run with verbose output
make test-verbose

# Run with coverage
make test-coverage

# Run specific test suite
make test-ciphers
make test-base64
make test-edge
# etc.

# Show help
make help
```

### Using Busted Directly

```bash
# Run all tests
busted --lua=luajit spec/

# Run specific file
busted --lua=luajit spec/ciphers_spec.lua

# Verbose output
busted --lua=luajit --verbose spec/

# With coverage
busted --lua=luajit --coverage spec/
luacov
```

### Using the Shell Script

```bash
./run_tests.sh        # Run all
./run_tests.sh -v     # Verbose
./run_tests.sh -c     # Coverage
```

## Test Structure

```
spec/
├── README.md                    # This file
├── mocks/
│   └── vim_mock.lua             # Neovim API mock
├── bytelocker_testable.lua      # Testable module with exposed internals
├── bit_operations_spec.lua      # Unit tests for bit operations
├── ciphers_spec.lua             # Unit tests for cipher algorithms
├── password_cipher_spec.lua     # Tests for state management
├── base64_spec.lua              # Tests for base64 encoding
├── format_detection_spec.lua    # Tests for format detection
├── encryption_roundtrip_spec.lua# Integration tests for encryption flow
├── edge_cases_spec.lua          # Edge case and stress tests
└── integration_spec.lua         # High-level API tests
```

## Test Categories

### Unit Tests

Test individual functions in isolation:
- `rol8()` / `ror8()` - bit rotation
- `shift_encrypt_block()` / `shift_decrypt_block()`
- `xor_encrypt_block()` / `xor_decrypt_block()`
- `caesar_encrypt_block()` / `caesar_decrypt_block()`
- `prepare_password()`
- `base64_encode()` / `base64_decode()`
- `is_encrypted()` / `is_text_encrypted()` / `is_file_encrypted()`

### Property-Based Tests

Test mathematical properties that should always hold:
- `decrypt(encrypt(x)) == x` for all inputs
- `ror8(rol8(x, n), n) == x` for all x, n
- `base64_decode(base64_encode(x)) == x` for all x

### Edge Case Tests

Test unusual and boundary inputs:
- Empty strings
- Single bytes (0, 255, special values)
- Block size boundaries (15, 16, 17 bytes)
- Unicode and emoji
- Binary data with all byte values
- Very long content (100KB+)
- Special characters (shell, regex, quotes)

### Integration Tests

Test complete workflows:
- Full encryption/decryption cycle
- Cipher persistence across sessions
- Password persistence
- Error handling and recovery
- Multi-cipher workflows

## Mock System

The test suite includes a comprehensive Neovim API mock (`spec/mocks/vim_mock.lua`) that simulates:

- `vim.fn.*` - stdpath, inputsecret, getpos, etc.
- `vim.api.*` - buffer operations, mode detection
- `vim.notify` - notification capture
- `vim.split`, `vim.tbl_deep_extend`
- `vim.keymap`, `vim.g`

## Writing New Tests

```lua
-- Example test file
local vim_mock = require("spec.mocks.vim_mock")
_G.vim = vim_mock.vim

local bl = require("spec.bytelocker_testable")

describe("My Feature", function()
    before_each(function()
        vim_mock.reset()
        bl.reset()
    end)

    it("should do something", function()
        -- Arrange
        bl.set_cipher("shift")

        -- Act
        local result = bl.encrypt_for_file("test", "password")

        -- Assert
        assert.is_true(bl.is_file_encrypted(result))
    end)
end)
```

## CI Integration

For CI systems, use TAP output:

```bash
make test-ci
# or
busted --lua=luajit --output=TAP spec/
```

## Troubleshooting

### "module 'bit' not found"

You need LuaJIT. The `bit` module is built into LuaJIT but not standard Lua.

```bash
# Verify LuaJIT
luajit -v

# Run tests with LuaJIT
busted --lua=luajit spec/
```

### "module 'busted' not found"

Install busted via luarocks:

```bash
luarocks install busted
```

### Tests pass locally but fail in CI

Ensure CI uses LuaJIT:

```yaml
# GitHub Actions example
- uses: leafo/gh-actions-lua@v10
  with:
    luaVersion: "luajit-2.1"
```
