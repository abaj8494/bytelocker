-- Test utilities for bytelocker tests
-- Provides state management and file I/O for integration testing

local core = require("bytelocker.core")

local M = {}

-- Re-export everything from core
for k, v in pairs(core) do
    M[k] = v
end

-- Test state
M.config = {
    cipher = "shift",
    _cipher_selected = false
}

M.stored_password = nil

-- File paths (using test temp directory)
M.password_file = "/tmp/bytelocker_test_data/bytelocker_session.dat"
M.cipher_file = "/tmp/bytelocker_test_data/bytelocker_cipher.dat"

-- Ensure temp directory exists
os.execute("mkdir -p /tmp/bytelocker_test_data")

-- Set cipher for testing
function M.set_cipher(cipher)
    M.config.cipher = cipher
    M.config._cipher_selected = true
end

-- Reset test state
function M.reset()
    M.config = {
        cipher = "shift",
        _cipher_selected = false
    }
    M.stored_password = nil
    os.remove(M.password_file)
    os.remove(M.cipher_file)
end

-- Password file I/O
function M.save_password(password)
    if not password then return end
    local obfuscated = core.obfuscate_password(password)
    local file = io.open(M.password_file, 'wb')
    if file then
        file:write(obfuscated)
        file:close()
    end
end

function M.load_password()
    local file = io.open(M.password_file, 'rb')
    if not file then return nil end
    local obfuscated = file:read('*all')
    file:close()
    return core.deobfuscate_password(obfuscated)
end

-- Cipher file I/O
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
    if cipher and cipher ~= "" and core.CIPHERS[cipher] then
        return cipher
    end
    return nil
end

-- Wrappers that use the test config cipher
function M.encrypt_text_only(content, password)
    return core.encrypt_text_only(content, password, M.config.cipher)
end

function M.decrypt_text_only(content, password)
    return core.decrypt_text_only(content, password, M.config.cipher)
end

function M.encrypt_for_file(content, password)
    return core.encrypt_for_file(content, password, M.config.cipher)
end

function M.decrypt_from_file(content, password)
    return core.decrypt_from_file(content, password, M.config.cipher)
end

return M
