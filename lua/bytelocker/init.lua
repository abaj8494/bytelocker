local M = {}

-- Constants
local CIPHER_BLOCK_SIZE = 16

-- Available cipher methods
local CIPHERS = {
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

-- Default configuration
local config = {
    cipher = "shift",
    setup_keymaps = false
}

-- Helper function to generate a deterministic "password" from a string
local function prepare_password(password)
    local prepared = {}
    for i = 1, CIPHER_BLOCK_SIZE do
        local char_code = string.byte(password, ((i - 1) % #password) + 1)
        table.insert(prepared, char_code % 256)
    end
    return prepared
end

-- Bitwise left rotate function (fixed for perfect reversibility)
local function rol(value, bits)
    value = value % 256
    bits = bits % 8  -- Ensure bits is within valid range
    return ((value << bits) | (value >> (8 - bits))) % 256
end

-- Bitwise right rotate function (fixed for perfect reversibility)
local function ror(value, bits)
    value = value % 256
    bits = bits % 8  -- Ensure bits is within valid range
    return ((value >> bits) | (value << (8 - bits))) % 256
end

-- SHIFT CIPHER IMPLEMENTATION
local function shift_encrypt_block(plaintext_block, password)
    local encrypted = {}
    for i = 1, CIPHER_BLOCK_SIZE do
        local byte_val = string.byte(plaintext_block, i) or 0
        local shift_amount = password[i] % 8  -- Limit shift to prevent overflow
        
        -- Apply rotation encryption
        byte_val = rol(byte_val, shift_amount)
        
        table.insert(encrypted, string.char(byte_val))
    end
    return table.concat(encrypted)
end

local function shift_decrypt_block(ciphertext_block, password)
    local decrypted = {}
    for i = 1, CIPHER_BLOCK_SIZE do
        local byte_val = string.byte(ciphertext_block, i) or 0
        local shift_amount = password[i] % 8  -- Limit shift to prevent overflow
        
        -- Apply rotation decryption (reverse of encryption)
        byte_val = ror(byte_val, shift_amount)
        
        table.insert(decrypted, string.char(byte_val))
    end
    return table.concat(decrypted)
end

-- XOR CIPHER IMPLEMENTATION
local function xor_encrypt_block(plaintext_block, password)
    local encrypted = {}
    for i = 1, CIPHER_BLOCK_SIZE do
        local byte_val = string.byte(plaintext_block, i) or 0
        local key_byte = password[i]
        
        -- XOR encryption
        local encrypted_byte = byte_val ~ key_byte
        table.insert(encrypted, string.char(encrypted_byte))
    end
    return table.concat(encrypted)
end

local function xor_decrypt_block(ciphertext_block, password)
    -- XOR is symmetric, so decryption is the same as encryption
    return xor_encrypt_block(ciphertext_block, password)
end

-- CAESAR CIPHER IMPLEMENTATION
local function caesar_encrypt_block(plaintext_block, password)
    local encrypted = {}
    for i = 1, CIPHER_BLOCK_SIZE do
        local byte_val = string.byte(plaintext_block, i) or 0
        local shift = password[i] % 256
        
        -- Caesar shift
        local encrypted_byte = (byte_val + shift) % 256
        table.insert(encrypted, string.char(encrypted_byte))
    end
    return table.concat(encrypted)
end

local function caesar_decrypt_block(ciphertext_block, password)
    local decrypted = {}
    for i = 1, CIPHER_BLOCK_SIZE do
        local byte_val = string.byte(ciphertext_block, i) or 0
        local shift = password[i] % 256
        
        -- Caesar unshift
        local decrypted_byte = (byte_val - shift + 256) % 256
        table.insert(decrypted, string.char(decrypted_byte))
    end
    return table.concat(decrypted)
end

-- Cipher method dispatcher
local function encrypt_block(plaintext_block, password, cipher_type)
    if cipher_type == "xor" then
        return xor_encrypt_block(plaintext_block, password)
    elseif cipher_type == "caesar" then
        return caesar_encrypt_block(plaintext_block, password)
    else -- default to shift
        return shift_encrypt_block(plaintext_block, password)
    end
end

local function decrypt_block(ciphertext_block, password, cipher_type)
    if cipher_type == "xor" then
        return xor_decrypt_block(ciphertext_block, password)
    elseif cipher_type == "caesar" then
        return caesar_decrypt_block(ciphertext_block, password)
    else -- default to shift
        return shift_decrypt_block(ciphertext_block, password)
    end
end

-- Check if file is encrypted (first byte is null)
local function is_encrypted(content)
    if #content == 0 then
        return false
    end
    return string.byte(content, 1) == 0
end

-- IMPROVED ENCRYPTION: Store original length to prevent data loss
local function encrypt_content(content, password)
    local prepared_password = prepare_password(password)
    
    -- Store the original content length in the first 4 bytes after the null marker
    local original_length = #content
    local length_bytes = string.char(
        (original_length >> 24) & 0xFF,
        (original_length >> 16) & 0xFF,
        (original_length >> 8) & 0xFF,
        original_length & 0xFF
    )
    
    local result = {string.char(0), length_bytes} -- Start with null byte + length
    
    -- Process content in 16-byte blocks
    for i = 1, #content, CIPHER_BLOCK_SIZE do
        local block = content:sub(i, i + CIPHER_BLOCK_SIZE - 1)
        
        -- Pad block to 16 bytes with null characters
        while #block < CIPHER_BLOCK_SIZE do
            block = block .. string.char(0)
        end
        
        local encrypted_block = encrypt_block(block, prepared_password, config.cipher)
        table.insert(result, encrypted_block)
    end
    
    return table.concat(result)
end

-- IMPROVED DECRYPTION: Use stored length to restore exact original content
local function decrypt_content(content, password)
    local prepared_password = prepare_password(password)
    
    -- Skip the first null byte and read the original length
    if #content < 5 then
        error("Invalid encrypted file format")
    end
    
    local length_bytes = content:sub(2, 5)
    local original_length = 
        (string.byte(length_bytes, 1) << 24) +
        (string.byte(length_bytes, 2) << 16) +
        (string.byte(length_bytes, 3) << 8) +
        string.byte(length_bytes, 4)
    
    -- Skip null byte and length bytes
    content = content:sub(6)
    
    local result = {}
    
    -- Process content in 16-byte blocks
    for i = 1, #content, CIPHER_BLOCK_SIZE do
        local block = content:sub(i, i + CIPHER_BLOCK_SIZE - 1)
        
        -- Pad block to 16 bytes with null characters if needed
        while #block < CIPHER_BLOCK_SIZE do
            block = block .. string.char(0)
        end
        
        local decrypted_block = decrypt_block(block, prepared_password, config.cipher)
        table.insert(result, decrypted_block)
    end
    
    local decrypted = table.concat(result)
    
    -- Return exactly the original length to prevent data loss
    return decrypted:sub(1, original_length)
end

-- User cipher selection
local function select_cipher()
    local choices = {}
    local cipher_keys = {}
    
    for key, cipher in pairs(CIPHERS) do
        table.insert(choices, string.format("%s - %s", cipher.name, cipher.description))
        table.insert(cipher_keys, key)
    end
    
    local choice = vim.fn.inputlist(vim.tbl_flatten({
        "Select encryption cipher:",
        choices
    }))
    
    if choice > 0 and choice <= #cipher_keys then
        return cipher_keys[choice]
    else
        return "shift" -- default
    end
end

-- Main toggle function - encrypts if plain text, decrypts if encrypted
function M.toggle_encryption()
    local buf = vim.api.nvim_get_current_buf()
    local filename = vim.api.nvim_buf_get_name(buf)
    
    if filename == "" then
        vim.notify("Buffer has no filename", vim.log.levels.ERROR)
        return
    end
    
    -- Check if file exists and we can read it
    local file = io.open(filename, "rb")
    if not file then
        vim.notify("Cannot read file: " .. filename, vim.log.levels.ERROR)
        return
    end
    
    local content = file:read("*all")
    file:close()
    
    -- Get password from user
    local password = vim.fn.inputsecret("Enter password: ")
    if password == "" then
        vim.notify("Password cannot be empty", vim.log.levels.ERROR)
        return
    end
    
    local new_content
    local operation
    
    if is_encrypted(content) then
        new_content = decrypt_content(content, password)
        operation = "decrypted"
    else
        new_content = encrypt_content(content, password)
        operation = "encrypted"
    end
    
    -- Write the result back to file
    file = io.open(filename, "wb")
    if not file then
        vim.notify("Cannot write to file: " .. filename, vim.log.levels.ERROR)
        return
    end
    
    file:write(new_content)
    file:close()
    
    -- Reload the buffer
    vim.cmd("edit!")
    
    vim.notify("File " .. operation .. " successfully using " .. config.cipher .. " cipher", vim.log.levels.INFO)
end

-- Encrypt current buffer content
function M.encrypt()
    local buf = vim.api.nvim_get_current_buf()
    local filename = vim.api.nvim_buf_get_name(buf)
    
    if filename == "" then
        vim.notify("Buffer has no filename", vim.log.levels.ERROR)
        return
    end
    
    local file = io.open(filename, "rb")
    if not file then
        vim.notify("Cannot read file: " .. filename, vim.log.levels.ERROR)
        return
    end
    
    local content = file:read("*all")
    file:close()
    
    if is_encrypted(content) then
        vim.notify("File is already encrypted", vim.log.levels.WARN)
        return
    end
    
    local password = vim.fn.inputsecret("Enter password: ")
    if password == "" then
        vim.notify("Password cannot be empty", vim.log.levels.ERROR)
        return
    end
    
    local encrypted_content = encrypt_content(content, password)
    
    file = io.open(filename, "wb")
    if not file then
        vim.notify("Cannot write to file: " .. filename, vim.log.levels.ERROR)
        return
    end
    
    file:write(encrypted_content)
    file:close()
    
    vim.cmd("edit!")
    vim.notify("File encrypted successfully using " .. config.cipher .. " cipher", vim.log.levels.INFO)
end

-- Decrypt current buffer content
function M.decrypt()
    local buf = vim.api.nvim_get_current_buf()
    local filename = vim.api.nvim_buf_get_name(buf)
    
    if filename == "" then
        vim.notify("Buffer has no filename", vim.log.levels.ERROR)
        return
    end
    
    local file = io.open(filename, "rb")
    if not file then
        vim.notify("Cannot read file: " .. filename, vim.log.levels.ERROR)
        return
    end
    
    local content = file:read("*all")
    file:close()
    
    if not is_encrypted(content) then
        vim.notify("File is not encrypted", vim.log.levels.WARN)
        return
    end
    
    local password = vim.fn.inputsecret("Enter password: ")
    if password == "" then
        vim.notify("Password cannot be empty", vim.log.levels.ERROR)
        return
    end
    
    local decrypted_content = decrypt_content(content, password)
    
    file = io.open(filename, "wb")
    if not file then
        vim.notify("Cannot write to file: " .. filename, vim.log.levels.ERROR)
        return
    end
    
    file:write(decrypted_content)
    file:close()
    
    vim.cmd("edit!")
    vim.notify("File decrypted successfully", vim.log.levels.INFO)
end

-- Change cipher method
function M.change_cipher()
    local new_cipher = select_cipher()
    config.cipher = new_cipher
    vim.notify("Cipher changed to: " .. CIPHERS[new_cipher].name, vim.log.levels.INFO)
end

-- Setup function for plugin configuration
function M.setup(opts)
    opts = opts or {}
    
    -- Merge user config with defaults
    config = vim.tbl_deep_extend("force", config, opts)
    
    -- If cipher is not set, prompt user to select one
    if not opts.cipher then
        vim.notify("Welcome to Bytelocker! Please select your default cipher.", vim.log.levels.INFO)
        config.cipher = select_cipher()
    end
    
    -- Create user commands
    vim.api.nvim_create_user_command('BytelockerToggle', M.toggle_encryption, {
        desc = 'Toggle encryption/decryption of current file'
    })
    
    vim.api.nvim_create_user_command('BytelockerEncrypt', M.encrypt, {
        desc = 'Encrypt current file'
    })
    
    vim.api.nvim_create_user_command('BytelockerDecrypt', M.decrypt, {
        desc = 'Decrypt current file'
    })
    
    vim.api.nvim_create_user_command('BytelockerChangeCipher', M.change_cipher, {
        desc = 'Change the encryption cipher method'
    })
    
    -- Set up keymaps with 'E' (updated to use capital E)
    if config.setup_keymaps then
        vim.keymap.set('n', '<leader>Et', M.toggle_encryption, { desc = 'Bytelocker: Toggle encryption' })
        vim.keymap.set('n', '<leader>Ee', M.encrypt, { desc = 'Bytelocker: Encrypt file' })
        vim.keymap.set('n', '<leader>Ed', M.decrypt, { desc = 'Bytelocker: Decrypt file' })
        vim.keymap.set('n', '<leader>Ec', M.change_cipher, { desc = 'Bytelocker: Change cipher' })
    end
end

return M 