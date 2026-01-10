-- Integration tests for high-level functions
-- Tests the complete workflow through the public API

local vim_mock = require("spec.mocks.vim_mock")
_G.vim = vim_mock.vim

local bl = require("spec.bytelocker_testable")

-- Since we can't fully test Neovim-specific functions without a real Neovim,
-- we focus on testing the core logic and state management

describe("Integration Tests", function()
    before_each(function()
        vim_mock.reset()
        bl.reset()
    end)

    after_each(function()
        -- Cleanup
        os.remove(bl.password_file)
        os.remove(bl.cipher_file)
    end)

    describe("Complete Encryption Workflow", function()
        local password = "integration_test_password"

        it("should encrypt and decrypt a document", function()
            -- Simulate a multi-line document
            local document = [[
# My Secret Document

This is a secret document with multiple lines.
It contains sensitive information.

## Section 1
Some confidential data here.

## Section 2
More secrets...

End of document.
]]
            bl.set_cipher("shift")
            local encrypted = bl.encrypt_for_file(document, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(document, decrypted)
        end)

        it("should encrypt code files", function()
            local code = [[
function hello()
    print("Hello, World!")
end

local function secret_function(password)
    return password:reverse()
end

return {
    hello = hello,
    secret = secret_function
}
]]
            bl.set_cipher("xor")
            local encrypted = bl.encrypt_for_file(code, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(code, decrypted)
        end)

        it("should encrypt JSON data", function()
            local json = [[{
    "api_key": "sk-secret-key-12345",
    "database": {
        "host": "localhost",
        "password": "db_secret_pass"
    },
    "users": [
        {"name": "admin", "token": "xyz123"}
    ]
}]]
            bl.set_cipher("caesar")
            local encrypted = bl.encrypt_for_file(json, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(json, decrypted)
        end)
    end)

    describe("Cipher Persistence Workflow", function()
        it("should persist cipher choice across sessions", function()
            -- First "session"
            bl.save_cipher("xor")

            -- Simulate new session
            bl.config.cipher = "shift"  -- Reset
            bl.config._cipher_selected = false

            -- Load saved cipher
            local saved = bl.load_cipher()
            assert.are.equal("xor", saved)
        end)

        it("should use persisted cipher for encryption", function()
            local password = "cipher_persist_test"
            local plaintext = "Test content"

            -- Set and save cipher
            bl.set_cipher("caesar")
            bl.save_cipher("caesar")

            -- Encrypt
            local encrypted1 = bl.encrypt_for_file(plaintext, password)

            -- Simulate new session with loaded cipher
            bl.config.cipher = "shift"  -- Wrong default
            local saved = bl.load_cipher()
            bl.set_cipher(saved)

            -- Should decrypt correctly
            local decrypted = bl.decrypt_from_file(encrypted1, password)
            assert.are.equal(plaintext, decrypted)
        end)
    end)

    describe("Password Persistence Workflow", function()
        it("should persist password across sessions", function()
            local original = "my_secret_password_123"

            -- First "session"
            bl.save_password(original)

            -- Simulate new session
            bl.stored_password = nil

            -- Load saved password
            local loaded = bl.load_password()
            assert.are.equal(original, loaded)
        end)

        it("should use persisted password for decryption", function()
            local password = "persist_decrypt_test"
            local plaintext = "Secret data to encrypt"

            -- Encrypt and save password
            bl.set_cipher("shift")
            local encrypted = bl.encrypt_for_file(plaintext, password)
            bl.save_password(password)

            -- Simulate new session
            bl.stored_password = nil

            -- Load password and decrypt
            local loaded_password = bl.load_password()
            local decrypted = bl.decrypt_from_file(encrypted, loaded_password)
            assert.are.equal(plaintext, decrypted)
        end)
    end)

    describe("Error Recovery Scenarios", function()
        it("should handle corrupted encrypted file gracefully", function()
            local corrupted = "---BYTELOCKER-ENCRYPTED-FILE---\ngarbage_not_base64!!!\n---END-BYTELOCKER-ENCRYPTED-FILE---"

            assert.has.errors(function()
                bl.decrypt_from_file(corrupted, "any_password")
            end)
        end)

        it("should handle missing file header gracefully", function()
            assert.has.errors(function()
                bl.decrypt_from_file("not encrypted at all", "any_password")
            end)
        end)

        it("should handle empty encrypted file gracefully", function()
            -- Empty string should return empty
            local result = bl.decrypt_from_file("", "any_password")
            assert.are.equal("", result)
        end)
    end)

    describe("Format Conversion Scenarios", function()
        local password = "format_convert_test"

        it("should correctly identify plain text vs encrypted", function()
            local plaintext = "This is plain text"

            assert.is_false(bl.is_file_encrypted(plaintext))

            bl.set_cipher("shift")
            local encrypted = bl.encrypt_for_file(plaintext, password)

            assert.is_true(bl.is_file_encrypted(encrypted))
        end)

        it("should not double-encrypt (detection should work)", function()
            local plaintext = "Original content"

            bl.set_cipher("shift")
            local encrypted1 = bl.encrypt_for_file(plaintext, password)

            -- Check it's encrypted
            assert.is_true(bl.is_file_encrypted(encrypted1))

            -- Decrypt and verify
            local decrypted = bl.decrypt_from_file(encrypted1, password)
            assert.are.equal(plaintext, decrypted)
        end)
    end)

    describe("Multi-Cipher Workflow", function()
        local password = "multi_cipher_test"

        it("should handle re-encryption with different cipher", function()
            local plaintext = "Content to re-encrypt"

            -- Encrypt with shift
            bl.set_cipher("shift")
            local encrypted_shift = bl.encrypt_for_file(plaintext, password)

            -- Decrypt
            local decrypted1 = bl.decrypt_from_file(encrypted_shift, password)
            assert.are.equal(plaintext, decrypted1)

            -- Re-encrypt with xor
            bl.set_cipher("xor")
            local encrypted_xor = bl.encrypt_for_file(decrypted1, password)

            -- Decrypt with xor
            local decrypted2 = bl.decrypt_from_file(encrypted_xor, password)
            assert.are.equal(plaintext, decrypted2)
        end)

        it("should fail when decrypting with wrong cipher", function()
            local plaintext = "Test content"

            -- Encrypt with shift
            bl.set_cipher("shift")
            local encrypted = bl.encrypt_for_file(plaintext, password)

            -- Try to decrypt with xor
            bl.set_cipher("xor")
            local decrypted = bl.decrypt_from_file(encrypted, password)

            -- Should not match (wrong cipher)
            assert.are_not.equal(plaintext, decrypted)
        end)
    end)

    describe("Data Integrity Verification", function()
        local password = "integrity_test"

        it("should detect tampering in header", function()
            bl.set_cipher("shift")
            local encrypted = bl.encrypt_for_file("secret data", password)

            -- Tamper with header
            local tampered = encrypted:gsub("BYTELOCKER", "BYTELOCKXX")

            assert.has.errors(function()
                bl.decrypt_from_file(tampered, password)
            end)
        end)

        it("should detect tampering in footer", function()
            bl.set_cipher("shift")
            local encrypted = bl.encrypt_for_file("secret data", password)

            -- Tamper with footer
            local tampered = encrypted:gsub("END%-BYTELOCKER", "XXX-BYTELOCKER")

            assert.has.errors(function()
                bl.decrypt_from_file(tampered, password)
            end)
        end)

        -- Note: Tampering with content will either error or produce garbage
        it("should detect or corrupt when content is tampered", function()
            local plaintext = "secret data"
            bl.set_cipher("shift")
            local encrypted = bl.encrypt_for_file(plaintext, password)

            -- Find and tamper with base64 content (change a character)
            local lines = {}
            for line in encrypted:gmatch("[^\n]+") do
                table.insert(lines, line)
            end
            -- Modify base64 content (second line) - use valid base64 char to avoid decode error
            if #lines >= 2 then
                local base64_line = lines[2]
                if #base64_line > 5 then
                    -- Change a character to another valid base64 character
                    local char = base64_line:sub(6, 6)
                    local new_char = char == "A" and "B" or "A"
                    lines[2] = base64_line:sub(1, 5) .. new_char .. base64_line:sub(7)
                end
            end
            local tampered = table.concat(lines, "\n")

            -- Should either error or produce different output
            local success, result = pcall(bl.decrypt_from_file, tampered, password)
            if success then
                -- If decryption succeeded, result should be garbage (not match original)
                assert.are_not.equal(plaintext, result)
            else
                -- If decryption failed, that's also acceptable (integrity check)
                assert.is_true(true)
            end
        end)
    end)
end)

describe("API Contract Tests", function()
    before_each(function()
        vim_mock.reset()
        bl.reset()
    end)

    describe("encrypt_text_only", function()
        it("should accept string content and password", function()
            bl.set_cipher("shift")
            local result = bl.encrypt_text_only("content", "password")
            assert.is_string(result)
        end)

        it("should return empty for empty input", function()
            bl.set_cipher("shift")
            local result = bl.encrypt_text_only("", "password")
            assert.are.equal("", result)
        end)

        it("should handle nil content", function()
            bl.set_cipher("shift")
            local result = bl.encrypt_text_only(nil, "password")
            assert.are.equal("", result)
        end)
    end)

    describe("decrypt_text_only", function()
        it("should accept encrypted content and password", function()
            bl.set_cipher("shift")
            local encrypted = bl.encrypt_text_only("test", "password")
            local result = bl.decrypt_text_only(encrypted, "password")
            assert.is_string(result)
        end)

        it("should return empty for empty input", function()
            bl.set_cipher("shift")
            local result = bl.decrypt_text_only("", "password")
            assert.are.equal("", result)
        end)
    end)

    describe("encrypt_for_file", function()
        it("should return ASCII-safe string", function()
            bl.set_cipher("shift")
            local result = bl.encrypt_for_file("test content", "password")

            for i = 1, #result do
                local byte = string.byte(result, i)
                assert.is_true(byte == 10 or (byte >= 32 and byte < 127),
                    string.format("Non-ASCII byte at position %d", i))
            end
        end)

        it("should include file markers", function()
            bl.set_cipher("shift")
            local result = bl.encrypt_for_file("test", "password")

            assert.is_truthy(result:match("^%-%-%-BYTELOCKER"))
            assert.is_truthy(result:match("END%-BYTELOCKER%-ENCRYPTED%-FILE%-%-%-$"))
        end)
    end)

    describe("decrypt_from_file", function()
        it("should restore original content", function()
            bl.set_cipher("shift")
            local original = "Test content 123"
            local encrypted = bl.encrypt_for_file(original, "password")
            local result = bl.decrypt_from_file(encrypted, "password")

            assert.are.equal(original, result)
        end)

        it("should error on invalid format", function()
            assert.has.errors(function()
                bl.decrypt_from_file("invalid content", "password")
            end)
        end)
    end)
end)

describe("Constants Validation", function()
    it("should have 16-byte block size", function()
        assert.are.equal(16, bl.CIPHER_BLOCK_SIZE)
    end)

    it("should have 9-byte magic header", function()
        assert.are.equal(9, #bl.MAGIC_HEADER)
        assert.are.equal("BYTELOCKR", bl.MAGIC_HEADER)
    end)

    it("should have exactly 3 cipher types", function()
        local count = 0
        for _ in pairs(bl.CIPHERS) do
            count = count + 1
        end
        assert.are.equal(3, count)
    end)

    it("should have shift as default cipher", function()
        bl.reset()
        assert.are.equal("shift", bl.config.cipher)
    end)
end)
