-- Unit tests for password and cipher management
-- Tests persistence, obfuscation, and state management

local bl = require("spec.helpers.test_utils")

describe("Password Management", function()
    before_each(function()
        bl.reset()
    end)

    after_each(function()
        -- Clean up test files
        os.remove(bl.password_file)
    end)

    describe("save_password", function()
        it("should save password to disk", function()
            bl.save_password("test_password")
            local file = io.open(bl.password_file, 'rb')
            assert.is_not_nil(file)
            file:close()
        end)

        it("should obfuscate the password (not store plaintext)", function()
            local original = "secret123"
            bl.save_password(original)

            local file = io.open(bl.password_file, 'rb')
            local stored = file:read('*all')
            file:close()

            assert.are_not.equal(original, stored)
        end)

        it("should not crash on nil password", function()
            assert.has_no.errors(function()
                bl.save_password(nil)
            end)
        end)

        it("should handle empty password", function()
            bl.save_password("")
            local file = io.open(bl.password_file, 'rb')
            if file then
                local stored = file:read('*all')
                file:close()
                assert.are.equal(0, #stored)
            end
        end)

        it("should handle special characters", function()
            local special = "p@$$w0rd!#$%^&*()"
            bl.save_password(special)
            local loaded = bl.load_password()
            assert.are.equal(special, loaded)
        end)

        it("should handle unicode characters", function()
            local unicode = "密码测试"
            bl.save_password(unicode)
            local loaded = bl.load_password()
            assert.are.equal(unicode, loaded)
        end)

        it("should handle binary data in password", function()
            local binary = "pass\x00\xFF\x01word"
            bl.save_password(binary)
            local loaded = bl.load_password()
            assert.are.equal(binary, loaded)
        end)
    end)

    describe("load_password", function()
        it("should return nil when no file exists", function()
            os.remove(bl.password_file)
            local loaded = bl.load_password()
            assert.is_nil(loaded)
        end)

        it("should correctly deobfuscate saved password", function()
            local original = "my_secret_password"
            bl.save_password(original)
            local loaded = bl.load_password()
            assert.are.equal(original, loaded)
        end)

        it("should return nil for empty file", function()
            local file = io.open(bl.password_file, 'wb')
            file:write("")
            file:close()

            local loaded = bl.load_password()
            assert.is_nil(loaded)
        end)

        it("should handle very long passwords", function()
            local long = string.rep("x", 10000)
            bl.save_password(long)
            local loaded = bl.load_password()
            assert.are.equal(long, loaded)
        end)
    end)

    describe("obfuscation roundtrip", function()
        it("should roundtrip all printable ASCII characters", function()
            for code = 32, 126 do
                local char = string.char(code)
                local pw = "prefix" .. char .. "suffix"
                bl.save_password(pw)
                local loaded = bl.load_password()
                assert.are.equal(pw, loaded,
                    string.format("Failed for char code %d ('%s')", code, char))
            end
        end)

        it("should roundtrip all byte values (0-255)", function()
            for code = 0, 255 do
                local char = string.char(code)
                bl.save_password(char)
                local loaded = bl.load_password()
                assert.are.equal(char, loaded,
                    string.format("Failed for byte value %d", code))
            end
        end)

        it("should handle obfuscation overflow correctly", function()
            -- Test bytes that would overflow when +42 is applied
            -- 214 + 42 = 256 -> should wrap to 0
            local test_bytes = {214, 215, 250, 255}
            for _, byte in ipairs(test_bytes) do
                local pw = string.char(byte)
                bl.save_password(pw)
                local loaded = bl.load_password()
                assert.are.equal(pw, loaded,
                    string.format("Failed for byte value %d", byte))
            end
        end)
    end)
end)

describe("Cipher Management", function()
    before_each(function()
        bl.reset()
    end)

    after_each(function()
        os.remove(bl.cipher_file)
    end)

    describe("save_cipher", function()
        it("should save cipher to disk", function()
            bl.save_cipher("xor")
            local file = io.open(bl.cipher_file, 'r')
            assert.is_not_nil(file)
            local content = file:read('*all')
            file:close()
            assert.are.equal("xor", content)
        end)

        it("should not crash on nil cipher", function()
            assert.has_no.errors(function()
                bl.save_cipher(nil)
            end)
        end)

        it("should overwrite existing cipher", function()
            bl.save_cipher("shift")
            bl.save_cipher("caesar")
            local loaded = bl.load_cipher()
            assert.are.equal("caesar", loaded)
        end)
    end)

    describe("load_cipher", function()
        it("should return nil when no file exists", function()
            os.remove(bl.cipher_file)
            local loaded = bl.load_cipher()
            assert.is_nil(loaded)
        end)

        it("should load valid cipher", function()
            bl.save_cipher("caesar")
            local loaded = bl.load_cipher()
            assert.are.equal("caesar", loaded)
        end)

        it("should return nil for invalid cipher", function()
            local file = io.open(bl.cipher_file, 'w')
            file:write("invalid_cipher")
            file:close()

            local loaded = bl.load_cipher()
            assert.is_nil(loaded)
        end)

        it("should return nil for empty file", function()
            local file = io.open(bl.cipher_file, 'w')
            file:write("")
            file:close()

            local loaded = bl.load_cipher()
            assert.is_nil(loaded)
        end)

        it("should accept all valid cipher types", function()
            for cipher, _ in pairs(bl.CIPHERS) do
                bl.save_cipher(cipher)
                local loaded = bl.load_cipher()
                assert.are.equal(cipher, loaded,
                    string.format("Failed for cipher: %s", cipher))
            end
        end)
    end)

    describe("set_cipher", function()
        it("should set cipher in config", function()
            bl.set_cipher("xor")
            assert.are.equal("xor", bl.config.cipher)
        end)

        it("should mark cipher as selected", function()
            bl.config._cipher_selected = false
            bl.set_cipher("caesar")
            assert.is_true(bl.config._cipher_selected)
        end)
    end)
end)

describe("State Reset", function()
    before_each(function()
        bl.reset()
    end)

    after_each(function()
        os.remove(bl.password_file)
        os.remove(bl.cipher_file)
    end)

    it("should reset config to defaults", function()
        bl.config.cipher = "caesar"
        bl.config._cipher_selected = true
        bl.stored_password = "secret"

        bl.reset()

        assert.are.equal("shift", bl.config.cipher)
        assert.is_false(bl.config._cipher_selected)
        assert.is_nil(bl.stored_password)
    end)

    it("should remove password file", function()
        bl.save_password("test")
        assert.is_not_nil(io.open(bl.password_file, 'r'))

        bl.reset()

        local file = io.open(bl.password_file, 'r')
        assert.is_nil(file)
    end)

    it("should remove cipher file", function()
        bl.save_cipher("xor")
        assert.is_not_nil(io.open(bl.cipher_file, 'r'))

        bl.reset()

        local file = io.open(bl.cipher_file, 'r')
        assert.is_nil(file)
    end)
end)

describe("Configuration Constants", function()
    it("should have correct CIPHER_BLOCK_SIZE", function()
        assert.are.equal(16, bl.CIPHER_BLOCK_SIZE)
    end)

    it("should have correct MAGIC_HEADER", function()
        assert.are.equal("BYTELOCKR", bl.MAGIC_HEADER)
        assert.are.equal(9, #bl.MAGIC_HEADER)
    end)

    it("should have all expected ciphers defined", function()
        assert.is_not_nil(bl.CIPHERS.shift)
        assert.is_not_nil(bl.CIPHERS.xor)
        assert.is_not_nil(bl.CIPHERS.caesar)
    end)

    it("should have name and description for all ciphers", function()
        for cipher_name, cipher_info in pairs(bl.CIPHERS) do
            assert.is_not_nil(cipher_info.name,
                string.format("Cipher %s missing name", cipher_name))
            assert.is_not_nil(cipher_info.description,
                string.format("Cipher %s missing description", cipher_name))
        end
    end)
end)
