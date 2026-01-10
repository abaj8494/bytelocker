-- Integration tests for encryption/decryption roundtrips
-- Tests end-to-end encryption flow through all layers

local vim_mock = require("spec.mocks.vim_mock")
_G.vim = vim_mock.vim

local bl = require("spec.bytelocker_testable")

describe("Text Encryption Roundtrip (encrypt_text_only / decrypt_text_only)", function()
    local password = "roundtrip_test_password"

    before_each(function()
        vim_mock.reset()
        bl.reset()
    end)

    describe("basic functionality", function()
        it("should roundtrip simple text", function()
            bl.set_cipher("shift")
            local plaintext = "Hello, World!"
            local encrypted = bl.encrypt_text_only(plaintext, password)
            local decrypted = bl.decrypt_text_only(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should handle empty string", function()
            bl.set_cipher("shift")
            local plaintext = ""
            local encrypted = bl.encrypt_text_only(plaintext, password)
            local decrypted = bl.decrypt_text_only(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should add magic header", function()
            bl.set_cipher("shift")
            local encrypted = bl.encrypt_text_only("test", password)
            assert.are.equal(bl.MAGIC_HEADER, encrypted:sub(1, #bl.MAGIC_HEADER))
        end)
    end)

    describe("all ciphers", function()
        it("should roundtrip with shift cipher", function()
            bl.set_cipher("shift")
            local plaintext = "Testing shift cipher roundtrip!"
            local encrypted = bl.encrypt_text_only(plaintext, password)
            local decrypted = bl.decrypt_text_only(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should roundtrip with xor cipher", function()
            bl.set_cipher("xor")
            local plaintext = "Testing XOR cipher roundtrip!"
            local encrypted = bl.encrypt_text_only(plaintext, password)
            local decrypted = bl.decrypt_text_only(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should roundtrip with caesar cipher", function()
            bl.set_cipher("caesar")
            local plaintext = "Testing Caesar cipher roundtrip!"
            local encrypted = bl.encrypt_text_only(plaintext, password)
            local decrypted = bl.decrypt_text_only(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)
    end)

    describe("length preservation", function()
        it("should preserve exact length for various sizes", function()
            bl.set_cipher("shift")
            for length = 1, 100 do
                local plaintext = string.rep("x", length)
                local encrypted = bl.encrypt_text_only(plaintext, password)
                local decrypted = bl.decrypt_text_only(encrypted, password)
                assert.are.equal(length, #decrypted,
                    string.format("Length mismatch for input length %d", length))
            end
        end)

        it("should preserve length at block boundaries", function()
            bl.set_cipher("shift")
            -- Test lengths around 16-byte block size
            local critical_lengths = {15, 16, 17, 31, 32, 33, 47, 48, 49}
            for _, length in ipairs(critical_lengths) do
                local plaintext = string.rep("a", length)
                local encrypted = bl.encrypt_text_only(plaintext, password)
                local decrypted = bl.decrypt_text_only(encrypted, password)
                assert.are.equal(plaintext, decrypted,
                    string.format("Failed at block boundary length %d", length))
            end
        end)
    end)

    describe("error handling", function()
        it("should error on missing magic header", function()
            assert.has.errors(function()
                bl.decrypt_text_only("not encrypted data", password)
            end)
        end)

        it("should error on truncated content", function()
            assert.has.errors(function()
                bl.decrypt_text_only("BYTEL", password)  -- Too short
            end)
        end)

        it("should error on just magic header without length", function()
            assert.has.errors(function()
                bl.decrypt_text_only(bl.MAGIC_HEADER, password)  -- Missing length bytes
            end)
        end)
    end)
end)

describe("File Encryption Roundtrip (encrypt_for_file / decrypt_from_file)", function()
    local password = "file_roundtrip_password"

    before_each(function()
        vim_mock.reset()
        bl.reset()
    end)

    describe("basic functionality", function()
        it("should roundtrip simple text", function()
            bl.set_cipher("shift")
            local plaintext = "Hello, World!"
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should handle empty string", function()
            bl.set_cipher("shift")
            local plaintext = ""
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should wrap with file markers", function()
            bl.set_cipher("shift")
            local encrypted = bl.encrypt_for_file("test", password)
            assert.is_true(encrypted:match("^%-%-%-BYTELOCKER%-ENCRYPTED%-FILE%-%-%-") ~= nil)
            assert.is_true(encrypted:match("%-%-%-END%-BYTELOCKER%-ENCRYPTED%-FILE%-%-%-$") ~= nil)
        end)

        it("should produce ASCII-safe output", function()
            bl.set_cipher("shift")
            -- Use binary input to ensure base64 encoding works
            local binary = ""
            for i = 0, 255 do
                binary = binary .. string.char(i)
            end
            local encrypted = bl.encrypt_for_file(binary, password)

            -- Check all characters are printable ASCII or newlines
            for i = 1, #encrypted do
                local byte = string.byte(encrypted, i)
                assert.is_true(byte == 10 or (byte >= 32 and byte < 127),
                    string.format("Non-ASCII byte %d at position %d", byte, i))
            end
        end)
    end)

    describe("all ciphers", function()
        for cipher_name, _ in pairs(bl.CIPHERS) do
            it(string.format("should roundtrip with %s cipher", cipher_name), function()
                bl.set_cipher(cipher_name)
                local plaintext = "Testing " .. cipher_name .. " file encryption!"
                local encrypted = bl.encrypt_for_file(plaintext, password)
                local decrypted = bl.decrypt_from_file(encrypted, password)
                assert.are.equal(plaintext, decrypted)
            end)
        end
    end)

    describe("multiline content", function()
        it("should preserve newlines", function()
            bl.set_cipher("shift")
            local plaintext = "Line 1\nLine 2\nLine 3"
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should preserve trailing newline", function()
            bl.set_cipher("shift")
            local plaintext = "Content with trailing newline\n"
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should preserve multiple consecutive newlines", function()
            bl.set_cipher("shift")
            local plaintext = "Line 1\n\n\nLine 4"
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should preserve Windows line endings", function()
            bl.set_cipher("shift")
            local plaintext = "Line 1\r\nLine 2\r\n"
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)
    end)

    describe("error handling", function()
        it("should error on missing header", function()
            assert.has.errors(function()
                bl.decrypt_from_file("not encrypted content", password)
            end)
        end)

        it("should error on missing footer", function()
            local bad_content = "---BYTELOCKER-ENCRYPTED-FILE---\nbase64data"
            assert.has.errors(function()
                bl.decrypt_from_file(bad_content, password)
            end)
        end)

        it("should error on corrupted base64", function()
            local bad_content = "---BYTELOCKER-ENCRYPTED-FILE---\n!!invalid!!\n---END-BYTELOCKER-ENCRYPTED-FILE---"
            assert.has.errors(function()
                bl.decrypt_from_file(bad_content, password)
            end)
        end)
    end)
end)

describe("Password Sensitivity", function()
    local correct_password = "correct_password"
    local wrong_password = "wrong_password"

    before_each(function()
        vim_mock.reset()
        bl.reset()
        bl.set_cipher("shift")
    end)

    describe("text encryption", function()
        it("should fail to decrypt with wrong password", function()
            local plaintext = "Secret message"
            local encrypted = bl.encrypt_text_only(plaintext, correct_password)

            -- Should not error but produce garbage
            local decrypted = bl.decrypt_text_only(encrypted, wrong_password)
            assert.are_not.equal(plaintext, decrypted)
        end)

        it("should succeed with correct password", function()
            local plaintext = "Secret message"
            local encrypted = bl.encrypt_text_only(plaintext, correct_password)
            local decrypted = bl.decrypt_text_only(encrypted, correct_password)
            assert.are.equal(plaintext, decrypted)
        end)
    end)

    describe("file encryption", function()
        it("should fail to decrypt with wrong password", function()
            local plaintext = "Secret file content"
            local encrypted = bl.encrypt_for_file(plaintext, correct_password)

            -- Should not error but produce garbage
            local decrypted = bl.decrypt_from_file(encrypted, wrong_password)
            assert.are_not.equal(plaintext, decrypted)
        end)

        it("should succeed with correct password", function()
            local plaintext = "Secret file content"
            local encrypted = bl.encrypt_for_file(plaintext, correct_password)
            local decrypted = bl.decrypt_from_file(encrypted, correct_password)
            assert.are.equal(plaintext, decrypted)
        end)
    end)

    describe("password variations", function()
        it("should differentiate case-sensitive passwords", function()
            local plaintext = "Test content"
            -- Use xor cipher which is more sensitive to password differences
            -- Note: shift cipher uses key % 8, so 'P'(80) and 'p'(112) both give 0
            bl.set_cipher("caesar")
            local encrypted = bl.encrypt_text_only(plaintext, "Password")
            local decrypted = bl.decrypt_text_only(encrypted, "password")
            assert.are_not.equal(plaintext, decrypted)
            bl.set_cipher("shift")  -- Reset
        end)

        it("should differentiate similar passwords", function()
            local plaintext = "Test content"
            local encrypted = bl.encrypt_text_only(plaintext, "password1")
            local decrypted = bl.decrypt_text_only(encrypted, "password2")
            assert.are_not.equal(plaintext, decrypted)
        end)
    end)
end)

describe("Cipher Compatibility", function()
    local password = "cipher_compat_test"

    before_each(function()
        vim_mock.reset()
        bl.reset()
    end)

    it("should not decrypt across different ciphers", function()
        local plaintext = "Cross-cipher test"

        -- Encrypt with shift
        bl.set_cipher("shift")
        local encrypted_shift = bl.encrypt_text_only(plaintext, password)

        -- Try to decrypt with xor
        bl.set_cipher("xor")
        local decrypted = bl.decrypt_text_only(encrypted_shift, password)
        assert.are_not.equal(plaintext, decrypted)

        -- Try to decrypt with caesar
        bl.set_cipher("caesar")
        decrypted = bl.decrypt_text_only(encrypted_shift, password)
        assert.are_not.equal(plaintext, decrypted)
    end)

    it("each cipher should produce different ciphertext", function()
        local plaintext = "Same plaintext for all ciphers"
        local ciphertexts = {}

        for cipher, _ in pairs(bl.CIPHERS) do
            bl.set_cipher(cipher)
            ciphertexts[cipher] = bl.encrypt_text_only(plaintext, password)
        end

        -- All ciphertexts should be different
        assert.are_not.equal(ciphertexts.shift, ciphertexts.xor)
        assert.are_not.equal(ciphertexts.shift, ciphertexts.caesar)
        assert.are_not.equal(ciphertexts.xor, ciphertexts.caesar)
    end)
end)

describe("Large Content Handling", function()
    local password = "large_content_test"

    before_each(function()
        vim_mock.reset()
        bl.reset()
        bl.set_cipher("shift")
    end)

    it("should handle 1KB content", function()
        local plaintext = string.rep("x", 1024)
        local encrypted = bl.encrypt_for_file(plaintext, password)
        local decrypted = bl.decrypt_from_file(encrypted, password)
        assert.are.equal(plaintext, decrypted)
    end)

    it("should handle 10KB content", function()
        local plaintext = string.rep("Large content test. ", 500)  -- ~10KB
        local encrypted = bl.encrypt_for_file(plaintext, password)
        local decrypted = bl.decrypt_from_file(encrypted, password)
        assert.are.equal(plaintext, decrypted)
    end)

    it("should handle 100KB content", function()
        local plaintext = string.rep("x", 102400)  -- 100KB
        local encrypted = bl.encrypt_for_file(plaintext, password)
        local decrypted = bl.decrypt_from_file(encrypted, password)
        assert.are.equal(plaintext, decrypted)
    end)

    it("should handle content with varied byte patterns", function()
        local plaintext = ""
        for i = 1, 10000 do
            plaintext = plaintext .. string.char(i % 256)
        end
        local encrypted = bl.encrypt_for_file(plaintext, password)
        local decrypted = bl.decrypt_from_file(encrypted, password)
        assert.are.equal(plaintext, decrypted)
    end)
end)
