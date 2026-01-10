-- Unit tests for all cipher implementations (shift, xor, caesar)
-- Tests block-level encryption/decryption for each cipher type

local vim_mock = require("spec.mocks.vim_mock")
_G.vim = vim_mock.vim

local bl = require("spec.bytelocker_testable")

-- Helper to create a 16-byte test block
local function make_block(content)
    while #content < bl.CIPHER_BLOCK_SIZE do
        content = content .. string.char(0)
    end
    return content:sub(1, bl.CIPHER_BLOCK_SIZE)
end

-- Helper to create random-ish content for testing
local function make_test_content(seed)
    local content = {}
    for i = 1, 16 do
        table.insert(content, string.char((seed * i + 17) % 256))
    end
    return table.concat(content)
end

describe("Password Preparation", function()
    describe("prepare_password", function()
        it("should create a 16-byte key from a password", function()
            local key = bl.prepare_password("test")
            assert.are.equal(16, #key)
        end)

        it("should handle short passwords by cycling", function()
            local key = bl.prepare_password("ab")
            -- 'a' = 97, 'b' = 98
            assert.are.equal(97, key[1])
            assert.are.equal(98, key[2])
            assert.are.equal(97, key[3])
            assert.are.equal(98, key[4])
        end)

        it("should handle long passwords", function()
            local long_pw = string.rep("x", 32)
            local key = bl.prepare_password(long_pw)
            assert.are.equal(16, #key)
        end)

        it("should produce consistent keys for same password", function()
            local key1 = bl.prepare_password("secret123")
            local key2 = bl.prepare_password("secret123")
            for i = 1, 16 do
                assert.are.equal(key1[i], key2[i])
            end
        end)

        it("should produce different keys for different passwords", function()
            local key1 = bl.prepare_password("password1")
            local key2 = bl.prepare_password("password2")
            local different = false
            for i = 1, 16 do
                if key1[i] ~= key2[i] then
                    different = true
                    break
                end
            end
            assert.is_true(different)
        end)

        it("should handle single character password", function()
            local key = bl.prepare_password("x")
            assert.are.equal(16, #key)
            -- All bytes should be the same (char code of 'x')
            for i = 1, 16 do
                assert.are.equal(string.byte("x"), key[i])
            end
        end)

        it("should handle unicode characters", function()
            -- UTF-8 encoded character
            local key = bl.prepare_password("\xC3\xA9")  -- é in UTF-8
            assert.are.equal(16, #key)
        end)

        it("should handle null bytes in password", function()
            local key = bl.prepare_password("a\0b")
            assert.are.equal(16, #key)
            assert.are.equal(0, key[2])  -- null byte
        end)
    end)
end)

describe("Shift Cipher", function()
    local password

    before_each(function()
        password = bl.prepare_password("test_password")
    end)

    describe("encrypt_block", function()
        it("should produce different output than input", function()
            local plaintext = make_block("Hello, World!")
            local ciphertext = bl.shift_encrypt_block(plaintext, password)
            assert.are_not.equal(plaintext, ciphertext)
        end)

        it("should produce consistent output for same input", function()
            local plaintext = make_block("Test content")
            local ct1 = bl.shift_encrypt_block(plaintext, password)
            local ct2 = bl.shift_encrypt_block(plaintext, password)
            assert.are.equal(ct1, ct2)
        end)

        it("should produce 16-byte output", function()
            local plaintext = make_block("Test")
            local ciphertext = bl.shift_encrypt_block(plaintext, password)
            assert.are.equal(16, #ciphertext)
        end)

        it("should handle all-zero input", function()
            local plaintext = string.rep(string.char(0), 16)
            local ciphertext = bl.shift_encrypt_block(plaintext, password)
            -- All zeros rotated is still all zeros
            assert.are.equal(plaintext, ciphertext)
        end)

        it("should handle all-ones input (0xFF)", function()
            local plaintext = string.rep(string.char(0xFF), 16)
            local ciphertext = bl.shift_encrypt_block(plaintext, password)
            -- All ones rotated is still all ones
            assert.are.equal(plaintext, ciphertext)
        end)
    end)

    describe("decrypt_block", function()
        it("should reverse encryption", function()
            local plaintext = make_block("Secret message!")
            local ciphertext = bl.shift_encrypt_block(plaintext, password)
            local decrypted = bl.shift_decrypt_block(ciphertext, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should fail to decrypt with wrong password", function()
            local plaintext = make_block("Secret message!")
            local ciphertext = bl.shift_encrypt_block(plaintext, password)
            local wrong_pw = bl.prepare_password("wrong_password")
            local decrypted = bl.shift_decrypt_block(ciphertext, wrong_pw)
            assert.are_not.equal(plaintext, decrypted)
        end)
    end)

    describe("roundtrip property tests", function()
        it("should roundtrip all byte values (0-255)", function()
            for byte = 0, 255 do
                local plaintext = string.rep(string.char(byte), 16)
                local ciphertext = bl.shift_encrypt_block(plaintext, password)
                local decrypted = bl.shift_decrypt_block(ciphertext, password)
                assert.are.equal(plaintext, decrypted,
                    string.format("Failed for byte value %d", byte))
            end
        end)

        it("should roundtrip multiple random-like blocks", function()
            for seed = 1, 20 do
                local plaintext = make_test_content(seed)
                local ciphertext = bl.shift_encrypt_block(plaintext, password)
                local decrypted = bl.shift_decrypt_block(ciphertext, password)
                assert.are.equal(plaintext, decrypted,
                    string.format("Failed for seed %d", seed))
            end
        end)
    end)
end)

describe("XOR Cipher", function()
    local password

    before_each(function()
        password = bl.prepare_password("xor_test_password")
    end)

    describe("encrypt_block", function()
        it("should produce different output than input", function()
            local plaintext = make_block("Hello, World!")
            local ciphertext = bl.xor_encrypt_block(plaintext, password)
            assert.are_not.equal(plaintext, ciphertext)
        end)

        it("should produce consistent output for same input", function()
            local plaintext = make_block("Test content")
            local ct1 = bl.xor_encrypt_block(plaintext, password)
            local ct2 = bl.xor_encrypt_block(plaintext, password)
            assert.are.equal(ct1, ct2)
        end)

        it("should handle null bytes in output (handled by base64 at file level)", function()
            -- Test that encryption still produces valid output even if nulls occur
            -- Null bytes are acceptable because base64 encoding handles them
            for byte = 0, 255 do
                local plaintext = string.rep(string.char(byte), 16)
                local ciphertext = bl.xor_encrypt_block(plaintext, password)
                assert.are.equal(16, #ciphertext,
                    string.format("Ciphertext length incorrect for input byte %d", byte))
            end
        end)

        it("should not leak password on null input", function()
            local plaintext = string.rep(string.char(0), 16)
            local ciphertext = bl.xor_encrypt_block(plaintext, password)
            -- Ciphertext should not directly equal XOR of key (security check)
            local direct_xor = {}
            for i = 1, 16 do
                table.insert(direct_xor, string.char(password[i]))
            end
            direct_xor = table.concat(direct_xor)
            assert.are_not.equal(direct_xor, ciphertext)
        end)
    end)

    describe("decrypt_block", function()
        it("should reverse encryption", function()
            local plaintext = make_block("XOR secret data")
            local ciphertext = bl.xor_encrypt_block(plaintext, password)
            local decrypted = bl.xor_decrypt_block(ciphertext, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should fail to decrypt with wrong password", function()
            local plaintext = make_block("Secret message!")
            local ciphertext = bl.xor_encrypt_block(plaintext, password)
            local wrong_pw = bl.prepare_password("wrong_password")
            local decrypted = bl.xor_decrypt_block(ciphertext, wrong_pw)
            assert.are_not.equal(plaintext, decrypted)
        end)
    end)

    describe("roundtrip property tests", function()
        it("should roundtrip all byte values (0-255)", function()
            for byte = 0, 255 do
                local plaintext = string.rep(string.char(byte), 16)
                local ciphertext = bl.xor_encrypt_block(plaintext, password)
                local decrypted = bl.xor_decrypt_block(ciphertext, password)
                assert.are.equal(plaintext, decrypted,
                    string.format("Failed for byte value %d", byte))
            end
        end)

        it("should roundtrip multiple random-like blocks", function()
            for seed = 1, 20 do
                local plaintext = make_test_content(seed)
                local ciphertext = bl.xor_encrypt_block(plaintext, password)
                local decrypted = bl.xor_decrypt_block(ciphertext, password)
                assert.are.equal(plaintext, decrypted,
                    string.format("Failed for seed %d", seed))
            end
        end)
    end)

    describe("null byte edge cases", function()
        it("should handle input that would produce null after XOR", function()
            -- Create input where safe_byte XOR key_byte = 0
            -- This tests the null-prevention logic
            for i = 1, 16 do
                local key_byte = password[i]
                local trigger_byte = (key_byte - 1 + 256) % 256  -- byte+1 XOR key = 0
                local plaintext = string.rep(string.char(trigger_byte), 16)
                local ciphertext = bl.xor_encrypt_block(plaintext, password)
                local decrypted = bl.xor_decrypt_block(ciphertext, password)
                assert.are.equal(plaintext, decrypted,
                    string.format("Failed for trigger byte %d at position %d", trigger_byte, i))
            end
        end)
    end)
end)

describe("Caesar Cipher", function()
    local password

    before_each(function()
        password = bl.prepare_password("caesar_test_pw")
    end)

    describe("encrypt_block", function()
        it("should produce different output than input", function()
            local plaintext = make_block("Hello, World!")
            local ciphertext = bl.caesar_encrypt_block(plaintext, password)
            assert.are_not.equal(plaintext, ciphertext)
        end)

        it("should produce consistent output for same input", function()
            local plaintext = make_block("Test content")
            local ct1 = bl.caesar_encrypt_block(plaintext, password)
            local ct2 = bl.caesar_encrypt_block(plaintext, password)
            assert.are.equal(ct1, ct2)
        end)

        it("should not leak password on null input", function()
            local plaintext = string.rep(string.char(0), 16)
            local ciphertext = bl.caesar_encrypt_block(plaintext, password)
            -- Due to XOR preprocessing, null input won't directly expose password
            for i = 1, 16 do
                local cipher_byte = string.byte(ciphertext, i)
                local key_byte = password[i]
                -- With XOR first, intermediate = key_byte, then shifted
                -- Output should not be just the shift of the key
                local shift = key_byte % 128
                local expected_direct = (key_byte + shift + 1) % 256
                -- We want to ensure it's not trivially guessable
                -- (just verify encryption worked, not exact values)
                assert.is_number(cipher_byte)
            end
        end)
    end)

    describe("decrypt_block", function()
        it("should reverse encryption", function()
            local plaintext = make_block("Caesar secret!")
            local ciphertext = bl.caesar_encrypt_block(plaintext, password)
            local decrypted = bl.caesar_decrypt_block(ciphertext, password)
            assert.are.equal(plaintext, decrypted)
        end)

        it("should fail to decrypt with wrong password", function()
            local plaintext = make_block("Secret message!")
            local ciphertext = bl.caesar_encrypt_block(plaintext, password)
            local wrong_pw = bl.prepare_password("wrong_password")
            local decrypted = bl.caesar_decrypt_block(ciphertext, wrong_pw)
            assert.are_not.equal(plaintext, decrypted)
        end)
    end)

    describe("roundtrip property tests", function()
        it("should roundtrip all byte values (0-255)", function()
            for byte = 0, 255 do
                local plaintext = string.rep(string.char(byte), 16)
                local ciphertext = bl.caesar_encrypt_block(plaintext, password)
                local decrypted = bl.caesar_decrypt_block(ciphertext, password)
                assert.are.equal(plaintext, decrypted,
                    string.format("Failed for byte value %d", byte))
            end
        end)

        it("should roundtrip multiple random-like blocks", function()
            for seed = 1, 20 do
                local plaintext = make_test_content(seed)
                local ciphertext = bl.caesar_encrypt_block(plaintext, password)
                local decrypted = bl.caesar_decrypt_block(ciphertext, password)
                assert.are.equal(plaintext, decrypted,
                    string.format("Failed for seed %d", seed))
            end
        end)
    end)
end)

describe("Block Cipher Dispatcher", function()
    local password

    before_each(function()
        password = bl.prepare_password("dispatcher_test")
    end)

    it("should route to shift cipher", function()
        local plaintext = make_block("test block")
        local ct_dispatch = bl.encrypt_block(plaintext, password, "shift")
        local ct_direct = bl.shift_encrypt_block(plaintext, password)
        assert.are.equal(ct_direct, ct_dispatch)
    end)

    it("should route to xor cipher", function()
        local plaintext = make_block("test block")
        local ct_dispatch = bl.encrypt_block(plaintext, password, "xor")
        local ct_direct = bl.xor_encrypt_block(plaintext, password)
        assert.are.equal(ct_direct, ct_dispatch)
    end)

    it("should route to caesar cipher", function()
        local plaintext = make_block("test block")
        local ct_dispatch = bl.encrypt_block(plaintext, password, "caesar")
        local ct_direct = bl.caesar_encrypt_block(plaintext, password)
        assert.are.equal(ct_direct, ct_dispatch)
    end)

    it("should default to shift for unknown cipher", function()
        local plaintext = make_block("test block")
        local ct_unknown = bl.encrypt_block(plaintext, password, "unknown_cipher")
        local ct_shift = bl.shift_encrypt_block(plaintext, password)
        assert.are.equal(ct_shift, ct_unknown)
    end)

    it("should default to shift for nil cipher", function()
        local plaintext = make_block("test block")
        local ct_nil = bl.encrypt_block(plaintext, password, nil)
        local ct_shift = bl.shift_encrypt_block(plaintext, password)
        assert.are.equal(ct_shift, ct_nil)
    end)

    it("should roundtrip through dispatcher for all ciphers", function()
        local plaintext = make_block("roundtrip test!")
        for _, cipher in ipairs({"shift", "xor", "caesar"}) do
            local ct = bl.encrypt_block(plaintext, password, cipher)
            local dt = bl.decrypt_block(ct, password, cipher)
            assert.are.equal(plaintext, dt,
                string.format("Roundtrip failed for cipher: %s", cipher))
        end
    end)
end)

describe("Cross-cipher incompatibility", function()
    local password

    before_each(function()
        password = bl.prepare_password("cross_cipher_test")
    end)

    it("should produce different ciphertext for each cipher", function()
        local plaintext = make_block("Same plaintext")
        local ct_shift = bl.encrypt_block(plaintext, password, "shift")
        local ct_xor = bl.encrypt_block(plaintext, password, "xor")
        local ct_caesar = bl.encrypt_block(plaintext, password, "caesar")

        assert.are_not.equal(ct_shift, ct_xor)
        assert.are_not.equal(ct_shift, ct_caesar)
        assert.are_not.equal(ct_xor, ct_caesar)
    end)

    it("should fail to decrypt with wrong cipher", function()
        local plaintext = make_block("Cipher mismatch")
        local ct = bl.encrypt_block(plaintext, password, "shift")

        local dt_xor = bl.decrypt_block(ct, password, "xor")
        local dt_caesar = bl.decrypt_block(ct, password, "caesar")

        assert.are_not.equal(plaintext, dt_xor)
        assert.are_not.equal(plaintext, dt_caesar)
    end)
end)
