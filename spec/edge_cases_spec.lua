-- Edge case tests for bytelocker
-- Tests unusual inputs, boundary conditions, and stress scenarios

local bl = require("spec.helpers.test_utils")

describe("Edge Cases", function()
    local password = "edge_case_test_pw"

    before_each(function()
        bl.reset()
        bl.set_cipher("shift")
    end)

    describe("Empty and Minimal Content", function()
        it("should handle empty string encryption", function()
            local encrypted = bl.encrypt_for_file("", password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal("", decrypted)
        end)

        it("should handle single character", function()
            local plaintext = "x"
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should handle single newline", function()
            local plaintext = "\n"
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should handle single null byte", function()
            local plaintext = string.char(0)
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should handle single 0xFF byte", function()
            local plaintext = string.char(0xFF)
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)
    end)

    describe("Binary Content", function()
        it("should handle all byte values (0-255)", function()
            local plaintext = ""
            for i = 0, 255 do
                plaintext = plaintext .. string.char(i)
            end
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should handle repeated null bytes", function()
            local plaintext = string.rep(string.char(0), 100)
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should handle repeated 0xFF bytes", function()
            local plaintext = string.rep(string.char(0xFF), 100)
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should handle alternating null and 0xFF bytes", function()
            local plaintext = ""
            for _ = 1, 100 do
                plaintext = plaintext .. string.char(0) .. string.char(0xFF)
            end
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should handle random-like binary data", function()
            local plaintext = ""
            for i = 1, 1000 do
                plaintext = plaintext .. string.char((i * 37 + 17) % 256)
            end
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)
    end)

    describe("Unicode and UTF-8 Content", function()
        it("should handle basic UTF-8 characters", function()
            local plaintext = "Héllo Wörld! 你好世界 🎉"
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should handle emoji", function()
            local plaintext = "🔐🔑🔒💀☠️🤖"
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should handle Chinese characters", function()
            local plaintext = "加密测试文本"
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should handle Japanese characters", function()
            local plaintext = "暗号化テスト"
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should handle Arabic characters", function()
            local plaintext = "اختبار التشفير"
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should handle mixed scripts", function()
            local plaintext = "English, Français, Deutsch, 中文, العربية, 日本語"
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)
    end)

    describe("Special Characters", function()
        it("should handle control characters", function()
            local plaintext = "\t\r\n\x00\x01\x02\x03"
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should handle shell special characters", function()
            local plaintext = "$PATH `command` $(subshell) && || ; | > < >> <<"
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should handle regex special characters", function()
            local plaintext = "^$.*+?[]{}()|\\/"
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should handle quote characters", function()
            local plaintext = [["'`'"'"single"double`backtick`]]
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)
    end)

    describe("Block Boundary Conditions", function()
        -- Block size is 16 bytes
        it("should handle content exactly 1 block (16 bytes)", function()
            local plaintext = string.rep("x", 16)
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should handle content exactly 2 blocks (32 bytes)", function()
            local plaintext = string.rep("x", 32)
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should handle content 1 byte short of block (15 bytes)", function()
            local plaintext = string.rep("x", 15)
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should handle content 1 byte over block (17 bytes)", function()
            local plaintext = string.rep("x", 17)
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should preserve exact length for all sizes 1-100", function()
            for length = 1, 100 do
                local plaintext = string.rep("x", length)
                local encrypted = bl.encrypt_for_file(plaintext, password)
                local decrypted = bl.decrypt_from_file(encrypted, password)
                assert.are.equal(length, #decrypted,
                    string.format("Length mismatch for size %d", length))
            end
        end)
    end)

    describe("Password Edge Cases", function()
        it("should handle single character password", function()
            local plaintext = "Secret content"
            local encrypted = bl.encrypt_for_file(plaintext, "x")
            local decrypted = bl.decrypt_from_file(encrypted, "x")
            assert.are.equal(plaintext, decrypted)
        end)

        it("should handle very long password (1000 chars)", function()
            local long_pw = string.rep("password", 125)  -- 1000 chars
            local plaintext = "Secret content"
            local encrypted = bl.encrypt_for_file(plaintext, long_pw)
            local decrypted = bl.decrypt_from_file(encrypted, long_pw)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should handle password with special characters", function()
            local special_pw = "p@$$w0rd!#$%^&*()[]{}|\\;:'\",.<>?/~`"
            local plaintext = "Secret content"
            local encrypted = bl.encrypt_for_file(plaintext, special_pw)
            local decrypted = bl.decrypt_from_file(encrypted, special_pw)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should handle password with unicode", function()
            local unicode_pw = "密码🔑"
            local plaintext = "Secret content"
            local encrypted = bl.encrypt_for_file(plaintext, unicode_pw)
            local decrypted = bl.decrypt_from_file(encrypted, unicode_pw)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should handle password with null bytes", function()
            local null_pw = "pass\x00word"
            local plaintext = "Secret content"
            local encrypted = bl.encrypt_for_file(plaintext, null_pw)
            local decrypted = bl.decrypt_from_file(encrypted, null_pw)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should handle numeric password", function()
            local plaintext = "Secret content"
            local encrypted = bl.encrypt_for_file(plaintext, "12345678901234567890")
            local decrypted = bl.decrypt_from_file(encrypted, "12345678901234567890")
            assert.are.equal(plaintext, decrypted)
        end)
    end)

    describe("Whitespace Handling", function()
        it("should preserve leading whitespace", function()
            local plaintext = "    indented content"
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should preserve trailing whitespace", function()
            local plaintext = "content with trailing spaces    "
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should preserve multiple consecutive spaces", function()
            local plaintext = "word1     word2"
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should preserve tabs", function()
            local plaintext = "col1\tcol2\tcol3"
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should preserve only whitespace content", function()
            local plaintext = "   \t\t   \n\n   "
            local encrypted = bl.encrypt_for_file(plaintext, password)
            local decrypted = bl.decrypt_from_file(encrypted, password)
            assert.are.equal(plaintext, decrypted)
        end)
    end)

    describe("All Ciphers with Edge Cases", function()
        local edge_cases = {
            {name = "empty", content = ""},
            {name = "single char", content = "x"},
            {name = "null byte", content = string.char(0)},
            {name = "0xFF byte", content = string.char(0xFF)},
            {name = "exactly 16 bytes", content = string.rep("x", 16)},
            {name = "exactly 15 bytes", content = string.rep("x", 15)},
        }

        -- Test all edge cases with all ciphers
        for cipher_name, _ in pairs(bl.CIPHERS) do
            describe(string.format("with %s cipher", cipher_name), function()
                before_each(function()
                    bl.set_cipher(cipher_name)
                end)

                for _, case in ipairs(edge_cases) do
                    it(string.format("should handle %s", case.name), function()
                        local encrypted = bl.encrypt_for_file(case.content, password)
                        local decrypted = bl.decrypt_from_file(encrypted, password)
                        assert.are.equal(case.content, decrypted)
                    end)
                end

                it("should handle all bytes (0-255)", function()
                    local content = ""
                    for i = 0, 255 do content = content .. string.char(i) end
                    local encrypted = bl.encrypt_for_file(content, password)
                    local decrypted = bl.decrypt_from_file(encrypted, password)
                    assert.are.equal(content, decrypted)
                end)

                it("should handle unicode and emoji", function()
                    local content = "Hello 世界 🔐"
                    local encrypted = bl.encrypt_for_file(content, password)
                    local decrypted = bl.decrypt_from_file(encrypted, password)
                    assert.are.equal(content, decrypted)
                end)
            end)
        end
    end)
end)

describe("Stress Tests", function()
    local password = "stress_test_pw"

    before_each(function()
        bl.reset()
        bl.set_cipher("shift")
    end)

    describe("Repeated Operations", function()
        it("should handle multiple consecutive encryptions", function()
            for i = 1, 100 do
                local plaintext = string.format("Test message %d", i)
                local encrypted = bl.encrypt_for_file(plaintext, password)
                local decrypted = bl.decrypt_from_file(encrypted, password)
                assert.are.equal(plaintext, decrypted)
            end
        end)

        it("should handle alternating encrypt/decrypt", function()
            local plaintexts = {}
            local encrypteds = {}

            -- Encrypt many
            for i = 1, 50 do
                plaintexts[i] = string.format("Message %d", i)
                encrypteds[i] = bl.encrypt_for_file(plaintexts[i], password)
            end

            -- Decrypt all
            for i = 1, 50 do
                local decrypted = bl.decrypt_from_file(encrypteds[i], password)
                assert.are.equal(plaintexts[i], decrypted)
            end
        end)
    end)

    describe("Cipher Switching", function()
        it("should correctly handle rapid cipher switching", function()
            local cipher_list = {"shift", "xor", "caesar"}
            local plaintext = "Test message for cipher switching"

            for _, cipher in ipairs(cipher_list) do
                bl.set_cipher(cipher)
                local encrypted = bl.encrypt_for_file(plaintext, password)
                local decrypted = bl.decrypt_from_file(encrypted, password)
                assert.are.equal(plaintext, decrypted,
                    string.format("Failed for cipher %s", cipher))
            end
        end)
    end)
end)
