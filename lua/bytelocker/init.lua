local M = {}

-- Constants
local CIPHER_BLOCK_SIZE = 16

-- Helper function to generate a deterministic "password" from a string
local function prepare_password(password)
    local prepared = {}
    for i = 1, CIPHER_BLOCK_SIZE do
        local char_code = string.byte(password, ((i - 1) % #password) + 1)
        table.insert(prepared, char_code % 256)
    end
    return prepared
end

-- Bitwise left rotate function
local function rol(value, bits)
    value = value % 256
    return ((value << bits) | (value >> (8 - bits))) % 256
end

-- Bitwise right rotate function
local function ror(value, bits)
    value = value % 256
    return ((value >> bits) | (value << (8 - bits))) % 256
end

-- Shift encrypt a 16-byte block
local function shift_encrypt(plaintext_block, password)
    local encrypted = {}
    for i = 1, CIPHER_BLOCK_SIZE do
        local byte_val = string.byte(plaintext_block, i) or 0
        local shift_amount = password[i]
        
        -- Apply rotation encryption
        for _ = 1, shift_amount do
            byte_val = rol(byte_val, 1)
        end
        
        table.insert(encrypted, string.char(byte_val))
    end
    return table.concat(encrypted)
end

-- Shift decrypt a 16-byte block
local function shift_decrypt(ciphertext_block, password)
    local decrypted = {}
    for i = 1, CIPHER_BLOCK_SIZE do
        local byte_val = string.byte(ciphertext_block, i) or 0
        local shift_amount = password[i]
        
        -- Apply rotation decryption (reverse of encryption)
        for _ = 1, shift_amount do
            byte_val = ror(byte_val, 1)
        end
        
        table.insert(decrypted, string.char(byte_val))
    end
    return table.concat(decrypted)
end

-- Check if file is encrypted (first byte is null)
local function is_encrypted(content)
    if #content == 0 then
        return false
    end
    return string.byte(content, 1) == 0
end

-- Encrypt file content
local function encrypt_content(content, password)
    local prepared_password = prepare_password(password)
    local result = {string.char(0)} -- Start with null byte to mark as encrypted
    
    -- Process content in 16-byte blocks
    for i = 1, #content, CIPHER_BLOCK_SIZE do
        local block = content:sub(i, i + CIPHER_BLOCK_SIZE - 1)
        
        -- Pad block to 16 bytes with null characters
        while #block < CIPHER_BLOCK_SIZE do
            block = block .. string.char(0)
        end
        
        local encrypted_block = shift_encrypt(block, prepared_password)
        table.insert(result, encrypted_block)
    end
    
    return table.concat(result)
end

-- Decrypt file content
local function decrypt_content(content, password)
    local prepared_password = prepare_password(password)
    
    -- Skip the first null byte that marks the file as encrypted
    content = content:sub(2)
    
    local result = {}
    
    -- Process content in 16-byte blocks
    for i = 1, #content, CIPHER_BLOCK_SIZE do
        local block = content:sub(i, i + CIPHER_BLOCK_SIZE - 1)
        
        -- Pad block to 16 bytes with null characters if needed
        while #block < CIPHER_BLOCK_SIZE do
            block = block .. string.char(0)
        end
        
        local decrypted_block = shift_decrypt(block, prepared_password)
        table.insert(result, decrypted_block)
    end
    
    local decrypted = table.concat(result)
    
    -- Remove trailing null characters
    local last_non_null = #decrypted
    for i = #decrypted, 1, -1 do
        if string.byte(decrypted, i) ~= 0 then
            last_non_null = i
            break
        end
    end
    
    return decrypted:sub(1, last_non_null)
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
    
    vim.notify("File " .. operation .. " successfully", vim.log.levels.INFO)
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
    vim.notify("File encrypted successfully", vim.log.levels.INFO)
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

-- Setup function for plugin configuration
function M.setup(opts)
    opts = opts or {}
    
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
    
    -- Set up default keymaps if requested
    if opts.setup_keymaps then
        vim.keymap.set('n', '<leader>bt', M.toggle_encryption, { desc = 'Bytelocker: Toggle encryption' })
        vim.keymap.set('n', '<leader>be', M.encrypt, { desc = 'Bytelocker: Encrypt file' })
        vim.keymap.set('n', '<leader>bd', M.decrypt, { desc = 'Bytelocker: Decrypt file' })
    end
end

return M 