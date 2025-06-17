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

-- Store password in memory
local stored_password = nil

-- Helper function to generate a deterministic "password" from a string
local function prepare_password(password)
    local prepared = {}
    for i = 1, CIPHER_BLOCK_SIZE do
        local char_code = string.byte(password, ((i - 1) % #password) + 1)
        table.insert(prepared, char_code % 256)
    end
    return prepared
end

-- Use Neovim's built-in bit operations
local bit = require("bit")
local band, bor, bxor = bit.band, bit.bor, bit.bxor
local lshift, rshift = bit.lshift, bit.rshift
local rol, ror = bit.rol, bit.ror

-- Helper functions for 8-bit rotations using Neovim's 32-bit operations
local function rol8(value, bits)
    value = band(value, 0xFF)  -- Ensure 8-bit value
    bits = bits % 8  -- Ensure bits is within valid range
    return band(bor(lshift(value, bits), rshift(value, 8 - bits)), 0xFF)
end

local function ror8(value, bits)
    value = band(value, 0xFF)  -- Ensure 8-bit value
    bits = bits % 8  -- Ensure bits is within valid range
    return band(bor(rshift(value, bits), lshift(value, 8 - bits)), 0xFF)
end

-- SHIFT CIPHER IMPLEMENTATION
local function shift_encrypt_block(plaintext_block, password)
    local encrypted = {}
    for i = 1, CIPHER_BLOCK_SIZE do
        local byte_val = string.byte(plaintext_block, i) or 0
        local shift_amount = password[i] % 8  -- Limit shift to prevent overflow
        
        -- Apply rotation encryption
        byte_val = rol8(byte_val, shift_amount)
        
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
        byte_val = ror8(byte_val, shift_amount)
        
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
        local encrypted_byte = bxor(byte_val, key_byte)
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
        band(rshift(original_length, 24), 0xFF),
        band(rshift(original_length, 16), 0xFF),
        band(rshift(original_length, 8), 0xFF),
        band(original_length, 0xFF)
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
        lshift(string.byte(length_bytes, 1), 24) +
        lshift(string.byte(length_bytes, 2), 16) +
        lshift(string.byte(length_bytes, 3), 8) +
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
    local choices = {"Select encryption cipher:"}
    local cipher_keys = {}
    
    local index = 1
    for key, cipher in pairs(CIPHERS) do
        table.insert(choices, string.format("%d. %s - %s", index, cipher.name, cipher.description))
        table.insert(cipher_keys, key)
        index = index + 1
    end
    
    local choice = vim.fn.inputlist(choices)
    
    if choice > 0 and choice <= #cipher_keys then
        return cipher_keys[choice]
    else
        return "shift" -- default
    end
end

-- Helper function to ensure cipher is configured
local function ensure_cipher_configured()
    if not config.cipher or config.cipher == "shift" and not config._cipher_selected then
        vim.notify("Please select your encryption cipher:", vim.log.levels.INFO)
        config.cipher = select_cipher()
        config._cipher_selected = true
        vim.notify("Cipher set to: " .. CIPHERS[config.cipher].name, vim.log.levels.INFO)
    end
end

-- Helper function to get or prompt for password
local function get_password()
    if stored_password then
        return stored_password
    end
    
    local password = vim.fn.inputsecret("Enter password: ")
    if password == "" then
        return nil
    end
    
    stored_password = password
    vim.notify("Password stored for this session", vim.log.levels.INFO)
    return password
end

-- Clear stored password
function M.clear_password()
    stored_password = nil
    vim.notify("Stored password cleared", vim.log.levels.INFO)
end

-- Helper function to check if there's a visual selection
local function get_visual_selection()
    local mode = vim.fn.mode()
    if mode ~= 'v' and mode ~= 'V' and mode ~= '' then
        return nil
    end
    
    local start_pos = vim.fn.getpos("'<")
    local end_pos = vim.fn.getpos("'>")
    
    if start_pos[2] == 0 or end_pos[2] == 0 then
        return nil
    end
    
    local start_line = start_pos[2]
    local start_col = start_pos[3]
    local end_line = end_pos[2]
    local end_col = end_pos[3]
    
    local lines = vim.api.nvim_buf_get_lines(0, start_line - 1, end_line, false)
    
    if #lines == 0 then
        return nil
    end
    
    -- Handle single line selection
    if #lines == 1 then
        local text = lines[1]:sub(start_col, end_col)
        return {
            text = text,
            start_line = start_line,
            start_col = start_col,
            end_line = end_line,
            end_col = end_col
        }
    end
    
    -- Handle multi-line selection
    lines[1] = lines[1]:sub(start_col)
    lines[#lines] = lines[#lines]:sub(1, end_col)
    
    return {
        text = table.concat(lines, '\n'),
        start_line = start_line,
        start_col = start_col,
        end_line = end_line,
        end_col = end_col
    }
end

-- Helper function to replace visual selection with new text
local function replace_visual_selection(selection, new_text)
    local lines = vim.split(new_text, '\n')
    
    if #lines == 1 then
        -- Single line replacement
        local current_line = vim.api.nvim_buf_get_lines(0, selection.start_line - 1, selection.start_line, false)[1]
        local before = current_line:sub(1, selection.start_col - 1)
        local after = current_line:sub(selection.end_col + 1)
        local new_line = before .. new_text .. after
        vim.api.nvim_buf_set_lines(0, selection.start_line - 1, selection.start_line, false, {new_line})
    else
        -- Multi-line replacement
        local first_line = vim.api.nvim_buf_get_lines(0, selection.start_line - 1, selection.start_line, false)[1]
        local last_line = vim.api.nvim_buf_get_lines(0, selection.end_line - 1, selection.end_line, false)[1]
        
        local before = first_line:sub(1, selection.start_col - 1)
        local after = last_line:sub(selection.end_col + 1)
        
        lines[1] = before .. lines[1]
        lines[#lines] = lines[#lines] .. after
        
        vim.api.nvim_buf_set_lines(0, selection.start_line - 1, selection.end_line, false, lines)
    end
end

-- Encrypt/decrypt text only (without file format headers)
local function encrypt_text_only(content, password)
    local prepared_password = prepare_password(password)
    local result = {}
    
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

local function decrypt_text_only(content, password)
    local prepared_password = prepare_password(password)
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
    
    -- Remove trailing null characters that were added as padding
    return decrypted:gsub("%z+$", "")
end

-- Check if text appears to be encrypted (contains many null or non-printable characters)
local function is_text_encrypted(text)
    if #text == 0 then return false end
    
    local null_count = 0
    local non_printable_count = 0
    
    for i = 1, math.min(#text, 100) do -- Check first 100 characters
        local byte = string.byte(text, i)
        if byte == 0 then
            null_count = null_count + 1
        elseif byte < 32 or byte > 126 then
            non_printable_count = non_printable_count + 1
        end
    end
    
    -- Consider encrypted if more than 20% are null or non-printable
    return (null_count + non_printable_count) / math.min(#text, 100) > 0.2
end

-- Main toggle function - encrypts if plain text, decrypts if encrypted
function M.toggle_encryption()
    -- Ensure cipher is configured before proceeding
    ensure_cipher_configured()
    
    -- Check if there's a visual selection
    local selection = get_visual_selection()
    
    if selection then
        -- Handle selected text encryption/decryption
        local password = get_password()
        if not password then
            vim.notify("Password cannot be empty", vim.log.levels.ERROR)
            return
        end
        
        local new_text
        local operation
        
        if is_text_encrypted(selection.text) then
            new_text = decrypt_text_only(selection.text, password)
            operation = "decrypted"
        else
            new_text = encrypt_text_only(selection.text, password)
            operation = "encrypted"
        end
        
        replace_visual_selection(selection, new_text)
        vim.notify("Selected text " .. operation .. " successfully using " .. config.cipher .. " cipher", vim.log.levels.INFO)
        
        -- Exit visual mode
        vim.cmd("normal! ")
        return
    end
    
    -- Handle full file encryption/decryption (existing logic)
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
    local password = get_password()
    if not password then
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
    -- Ensure cipher is configured before proceeding
    ensure_cipher_configured()
    
    -- Check if there's a visual selection
    local selection = get_visual_selection()
    
    if selection then
        -- Handle selected text encryption
        if is_text_encrypted(selection.text) then
            vim.notify("Selected text is already encrypted", vim.log.levels.WARN)
            return
        end
        
        local password = get_password()
        if not password then
            vim.notify("Password cannot be empty", vim.log.levels.ERROR)
            return
        end
        
        local encrypted_text = encrypt_text_only(selection.text, password)
        replace_visual_selection(selection, encrypted_text)
        vim.notify("Selected text encrypted successfully using " .. config.cipher .. " cipher", vim.log.levels.INFO)
        
        -- Exit visual mode
        vim.cmd("normal! ")
        return
    end
    
    -- Handle full file encryption (existing logic)
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
    
    local password = get_password()
    if not password then
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
    -- Ensure cipher is configured before proceeding
    ensure_cipher_configured()
    
    -- Check if there's a visual selection
    local selection = get_visual_selection()
    
    if selection then
        -- Handle selected text decryption
        if not is_text_encrypted(selection.text) then
            vim.notify("Selected text is not encrypted", vim.log.levels.WARN)
            return
        end
        
        local password = get_password()
        if not password then
            vim.notify("Password cannot be empty", vim.log.levels.ERROR)
            return
        end
        
        local decrypted_text = decrypt_text_only(selection.text, password)
        replace_visual_selection(selection, decrypted_text)
        vim.notify("Selected text decrypted successfully", vim.log.levels.INFO)
        
        -- Exit visual mode
        vim.cmd("normal! ")
        return
    end
    
    -- Handle full file decryption (existing logic)
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
    
    local password = get_password()
    if not password then
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
    config._cipher_selected = true
    vim.notify("Cipher changed to: " .. CIPHERS[new_cipher].name, vim.log.levels.INFO)
end

-- Setup function for plugin configuration
function M.setup(opts)
    opts = opts or {}
    
    -- Merge user config with defaults
    config = vim.tbl_deep_extend("force", config, opts)
    
    -- Mark cipher as selected if user provided one
    if opts.cipher then
        config._cipher_selected = true
    end
    
    -- Create user commands
    vim.api.nvim_create_user_command('BytelockerToggle', M.toggle_encryption, {
        desc = 'Toggle encryption/decryption of current file or selected text'
    })
    
    vim.api.nvim_create_user_command('BytelockerEncrypt', M.encrypt, {
        desc = 'Encrypt current file or selected text'
    })
    
    vim.api.nvim_create_user_command('BytelockerDecrypt', M.decrypt, {
        desc = 'Decrypt current file or selected text'
    })
    
    vim.api.nvim_create_user_command('BytelockerChangeCipher', M.change_cipher, {
        desc = 'Change the encryption cipher method'
    })
    
    vim.api.nvim_create_user_command('BytelockerClearPassword', M.clear_password, {
        desc = 'Clear stored password'
    })
    
    -- Set up keymaps with 'E' (updated to use capital E)
    if config.setup_keymaps then
        vim.keymap.set('n', 'E', M.toggle_encryption, { desc = 'Bytelocker: Toggle encryption' })
        vim.keymap.set('v', 'E', M.toggle_encryption, { desc = 'Bytelocker: Toggle encryption (selection)' })
        vim.keymap.set('n', '<leader>E', M.change_cipher, { desc = 'Bytelocker: Change cipher' })
        vim.keymap.set('n', '<leader>eP', M.clear_password, { desc = 'Bytelocker: Clear password' })
    end
end

return M 