-- Testable version of bytelocker that exposes internal functions
-- This module wraps the main bytelocker module and provides access to
-- internal functions for comprehensive unit testing

local M = {}

-- Constants (exported for testing)
M.CIPHER_BLOCK_SIZE = 16
M.MAGIC_HEADER = "BYTELOCKR"

-- Available cipher methods
M.CIPHERS = {
    shift = {
        name = "Shift Cipher",
        description = "Bitwise rotation cipher (original method)"
    },
    xor = {
        name = "XOR Cipher",
        description = "XOR-based encryption"
    },
    caesar = {
        name = "Caesar Cipher",
        description = "Character shifting cipher"
    }
}

-- Configuration (mutable for testing)
M.config = {
    cipher = "shift",
    setup_keymaps = false,
    _cipher_selected = false
}

-- Storage
M.stored_password = nil
M.password_file = vim.fn.stdpath('data') .. '/bytelocker_session.dat'
M.cipher_file = vim.fn.stdpath('data') .. '/bytelocker_cipher.dat'

-- Use bit operations (compatible with LuaJIT and Lua 5.3+)
local bit = require("spec.mocks.bit_compat")
local band, bor, bxor = bit.band, bit.bor, bit.bxor
local lshift, rshift = bit.lshift, bit.rshift

-- Export bit operations for direct testing
M.bit = bit

-- 8-bit left rotate
function M.rol8(value, bits)
    value = band(value, 0xFF)
    bits = bits % 8
    return band(bor(lshift(value, bits), rshift(value, 8 - bits)), 0xFF)
end

-- 8-bit right rotate
function M.ror8(value, bits)
    value = band(value, 0xFF)
    bits = bits % 8
    return band(bor(rshift(value, bits), lshift(value, 8 - bits)), 0xFF)
end

-- Prepare password to 16-byte key
function M.prepare_password(password)
    local prepared = {}
    for i = 1, M.CIPHER_BLOCK_SIZE do
        local char_code = string.byte(password, ((i - 1) % #password) + 1)
        table.insert(prepared, char_code % 256)
    end
    return prepared
end

-- SHIFT CIPHER
function M.shift_encrypt_block(plaintext_block, password)
    local encrypted = {}
    for i = 1, M.CIPHER_BLOCK_SIZE do
        local byte_val = string.byte(plaintext_block, i) or 0
        local shift_amount = password[i] % 8
        byte_val = M.rol8(byte_val, shift_amount)
        table.insert(encrypted, string.char(byte_val))
    end
    return table.concat(encrypted)
end

function M.shift_decrypt_block(ciphertext_block, password)
    local decrypted = {}
    for i = 1, M.CIPHER_BLOCK_SIZE do
        local byte_val = string.byte(ciphertext_block, i) or 0
        local shift_amount = password[i] % 8
        byte_val = M.ror8(byte_val, shift_amount)
        table.insert(decrypted, string.char(byte_val))
    end
    return table.concat(decrypted)
end

-- XOR CIPHER (FIXED - add+rotate+XOR for password protection)
-- Uses +1 to prevent password leakage on null input, rotation to mix bits, XOR with key.
-- Null bytes in output are handled by Base64 encoding at the file level.
function M.xor_encrypt_block(plaintext_block, password)
    local encrypted = {}
    for i = 1, M.CIPHER_BLOCK_SIZE do
        local byte_val = string.byte(plaintext_block, i) or 0
        local key_byte = password[i]

        -- Add 1 to prevent null input from leaking password
        local safe_byte = (byte_val + 1) % 256

        -- Rotate by key-dependent amount (1-7 bits)
        local rotation = (key_byte % 7) + 1
        local rotated = M.rol8(safe_byte, rotation)

        -- XOR with key
        local encrypted_byte = bxor(rotated, key_byte)

        table.insert(encrypted, string.char(encrypted_byte))
    end
    return table.concat(encrypted)
end

function M.xor_decrypt_block(ciphertext_block, password)
    local decrypted = {}
    for i = 1, M.CIPHER_BLOCK_SIZE do
        local byte_val = string.byte(ciphertext_block, i) or 0
        local key_byte = password[i]
        local rotation = (key_byte % 7) + 1

        -- Reverse XOR
        local rotated = bxor(byte_val, key_byte)

        -- Reverse rotation
        local safe_byte = M.ror8(rotated, rotation)

        -- Reverse +1
        local decrypted_byte = (safe_byte - 1 + 256) % 256

        table.insert(decrypted, string.char(decrypted_byte))
    end
    return table.concat(decrypted)
end

-- CAESAR CIPHER
function M.caesar_encrypt_block(plaintext_block, password)
    local encrypted = {}
    for i = 1, M.CIPHER_BLOCK_SIZE do
        local byte_val = string.byte(plaintext_block, i) or 0
        local key_byte = password[i]
        local intermediate = bxor(byte_val, key_byte)
        local shift = key_byte % 128
        local encrypted_byte = (intermediate + shift + 1) % 256
        table.insert(encrypted, string.char(encrypted_byte))
    end
    return table.concat(encrypted)
end

function M.caesar_decrypt_block(ciphertext_block, password)
    local decrypted = {}
    for i = 1, M.CIPHER_BLOCK_SIZE do
        local byte_val = string.byte(ciphertext_block, i) or 0
        local key_byte = password[i]
        local shift = key_byte % 128
        local intermediate = (byte_val - shift - 1 + 256) % 256
        local decrypted_byte = bxor(intermediate, key_byte)
        table.insert(decrypted, string.char(decrypted_byte))
    end
    return table.concat(decrypted)
end

-- Block dispatcher
function M.encrypt_block(plaintext_block, password, cipher_type)
    if cipher_type == "xor" then
        return M.xor_encrypt_block(plaintext_block, password)
    elseif cipher_type == "caesar" then
        return M.caesar_encrypt_block(plaintext_block, password)
    else
        return M.shift_encrypt_block(plaintext_block, password)
    end
end

function M.decrypt_block(ciphertext_block, password, cipher_type)
    if cipher_type == "xor" then
        return M.xor_decrypt_block(ciphertext_block, password)
    elseif cipher_type == "caesar" then
        return M.caesar_decrypt_block(ciphertext_block, password)
    else
        return M.shift_decrypt_block(ciphertext_block, password)
    end
end

-- BASE64 ENCODING/DECODING
local base64_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

function M.base64_encode(data)
    local result = {}

    for i = 1, #data, 3 do
        local b1 = string.byte(data, i) or 0
        local b2 = string.byte(data, i + 1) or 0
        local b3 = string.byte(data, i + 2) or 0

        local combined = lshift(b1, 16) + lshift(b2, 8) + b3

        local c1 = band(rshift(combined, 18), 0x3F) + 1
        local c2 = band(rshift(combined, 12), 0x3F) + 1
        local c3 = band(rshift(combined, 6), 0x3F) + 1
        local c4 = band(combined, 0x3F) + 1

        table.insert(result, base64_chars:sub(c1, c1))
        table.insert(result, base64_chars:sub(c2, c2))

        if i + 1 <= #data then
            table.insert(result, base64_chars:sub(c3, c3))
        else
            table.insert(result, '=')
        end

        if i + 2 <= #data then
            table.insert(result, base64_chars:sub(c4, c4))
        else
            table.insert(result, '=')
        end
    end

    return table.concat(result)
end

function M.base64_decode(data)
    data = data:gsub('%s+', ''):gsub('=+$', '')

    local result = {}
    local decode_table = {}

    for i = 1, #base64_chars do
        decode_table[base64_chars:sub(i, i)] = i - 1
    end

    for i = 1, #data, 4 do
        local c1 = decode_table[data:sub(i, i)] or 0
        local c2 = decode_table[data:sub(i + 1, i + 1)] or 0
        local c3 = decode_table[data:sub(i + 2, i + 2)] or 0
        local c4 = decode_table[data:sub(i + 3, i + 3)] or 0

        local combined = lshift(c1, 18) + lshift(c2, 12) + lshift(c3, 6) + c4

        table.insert(result, string.char(band(rshift(combined, 16), 0xFF)))
        if i + 2 <= #data then
            table.insert(result, string.char(band(rshift(combined, 8), 0xFF)))
        end
        if i + 3 <= #data then
            table.insert(result, string.char(band(combined, 0xFF)))
        end
    end

    return table.concat(result)
end

-- Detection functions
function M.is_encrypted(content)
    if #content == 0 then return false end
    return string.byte(content, 1) == 0
end

function M.is_text_encrypted(text)
    if #text < #M.MAGIC_HEADER then return false end
    local header = text:sub(1, #M.MAGIC_HEADER)
    return header == M.MAGIC_HEADER
end

function M.is_file_encrypted(content)
    if #content == 0 then return false end
    local header = "---BYTELOCKER-ENCRYPTED-FILE---"
    return content:sub(1, #header) == header
end

-- Text encryption (binary with magic header)
function M.encrypt_text_only(content, password)
    if not content or content == "" then return "" end

    local prepared_password = M.prepare_password(password)
    local original_length = #content
    local length_bytes = string.char(
        band(rshift(original_length, 24), 0xFF),
        band(rshift(original_length, 16), 0xFF),
        band(rshift(original_length, 8), 0xFF),
        band(original_length, 0xFF)
    )

    local result = {M.MAGIC_HEADER, length_bytes}

    for i = 1, #content, M.CIPHER_BLOCK_SIZE do
        local block = content:sub(i, i + M.CIPHER_BLOCK_SIZE - 1)
        while #block < M.CIPHER_BLOCK_SIZE do
            block = block .. string.char(0)
        end
        local encrypted_block = M.encrypt_block(block, prepared_password, M.config.cipher)
        table.insert(result, encrypted_block)
    end

    return table.concat(result)
end

function M.decrypt_text_only(content, password)
    if not content or content == "" then return "" end

    if #content < #M.MAGIC_HEADER + 4 then
        error("Invalid encrypted text format: too short")
    end

    local header = content:sub(1, #M.MAGIC_HEADER)
    if header ~= M.MAGIC_HEADER then
        error("Invalid encrypted text format: missing magic header")
    end

    local prepared_password = M.prepare_password(password)

    local length_bytes = content:sub(#M.MAGIC_HEADER + 1, #M.MAGIC_HEADER + 4)
    local original_length =
        lshift(string.byte(length_bytes, 1), 24) +
        lshift(string.byte(length_bytes, 2), 16) +
        lshift(string.byte(length_bytes, 3), 8) +
        string.byte(length_bytes, 4)

    content = content:sub(#M.MAGIC_HEADER + 5)

    local result = {}

    for i = 1, #content, M.CIPHER_BLOCK_SIZE do
        local block = content:sub(i, i + M.CIPHER_BLOCK_SIZE - 1)
        while #block < M.CIPHER_BLOCK_SIZE do
            block = block .. string.char(0)
        end
        local decrypted_block = M.decrypt_block(block, prepared_password, M.config.cipher)
        table.insert(result, decrypted_block)
    end

    local decrypted = table.concat(result)
    return decrypted:sub(1, original_length)
end

-- File-safe encryption (with base64)
function M.encrypt_for_file(content, password)
    if not content or content == "" then return "" end

    local binary_encrypted = M.encrypt_text_only(content, password)
    local base64_encrypted = M.base64_encode(binary_encrypted)

    local file_header = "---BYTELOCKER-ENCRYPTED-FILE---\n"
    local file_footer = "\n---END-BYTELOCKER-ENCRYPTED-FILE---"

    return file_header .. base64_encrypted .. file_footer
end

function M.decrypt_from_file(content, password)
    if not content or content == "" then return "" end

    local header = "---BYTELOCKER-ENCRYPTED-FILE---\n"
    local footer = "\n---END-BYTELOCKER-ENCRYPTED-FILE---"

    if not content:match("^" .. header:gsub("%-", "%%-")) then
        error("Invalid encrypted file format: missing header")
    end

    if not content:match(footer:gsub("%-", "%%-") .. "$") then
        error("Invalid encrypted file format: missing footer")
    end

    local base64_content = content:sub(#header + 1, -(#footer + 1))

    local success, binary_encrypted = pcall(M.base64_decode, base64_content)
    if not success then
        error("Invalid encrypted file format: corrupted base64 data")
    end

    return M.decrypt_text_only(binary_encrypted, password)
end

-- Password management
function M.save_password(password)
    if not password then return end

    local obfuscated = {}
    for i = 1, #password do
        local byte = string.byte(password, i)
        table.insert(obfuscated, string.char((byte + 42) % 256))
    end

    local file = io.open(M.password_file, 'wb')
    if file then
        file:write(table.concat(obfuscated))
        file:close()
    end
end

function M.load_password()
    local file = io.open(M.password_file, 'rb')
    if not file then return nil end

    local obfuscated = file:read('*all')
    file:close()

    if #obfuscated == 0 then return nil end

    local password = {}
    for i = 1, #obfuscated do
        local byte = string.byte(obfuscated, i)
        table.insert(password, string.char((byte - 42) % 256))
    end

    return table.concat(password)
end

-- Cipher management
function M.save_cipher(cipher)
    if not cipher then return end

    local file = io.open(M.cipher_file, 'w')
    if file then
        file:write(cipher)
        file:close()
    end
end

function M.load_cipher()
    local file = io.open(M.cipher_file, 'r')
    if not file then return nil end

    local cipher = file:read('*all')
    file:close()

    if cipher and cipher ~= "" and M.CIPHERS[cipher] then
        return cipher
    end

    return nil
end

-- Reset test state
function M.reset()
    M.config = {
        cipher = "shift",
        setup_keymaps = false,
        _cipher_selected = false
    }
    M.stored_password = nil
    -- Clean up files
    os.remove(M.password_file)
    os.remove(M.cipher_file)
end

-- Set cipher for testing
function M.set_cipher(cipher)
    M.config.cipher = cipher
    M.config._cipher_selected = true
end

return M
