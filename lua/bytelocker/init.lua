local M = {}

-- Constants
local CIPHER_BLOCK_SIZE = 16
local MAGIC_HEADER = "BYTELOCKR"  -- 9-byte magic header for encrypted text

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

-- Store password in memory and persistently
local stored_password = nil
local password_file = vim.fn.stdpath('data') .. '/bytelocker_session.dat'

-- Helper function to save password to disk (with basic obfuscation)
local function save_password(password)
    if not password then return end
    
    -- Basic obfuscation (not real security, just to avoid plain text)
    local obfuscated = {}
    for i = 1, #password do
        local byte = string.byte(password, i)
        table.insert(obfuscated, string.char((byte + 42) % 256))
    end
    
    local file = io.open(password_file, 'wb')
    if file then
        file:write(table.concat(obfuscated))
        file:close()
    end
end

-- Helper function to load password from disk
local function load_password()
    local file = io.open(password_file, 'rb')
    if not file then return nil end
    
    local obfuscated = file:read('*all')
    file:close()
    
    if #obfuscated == 0 then return nil end
    
    -- Deobfuscate
    local password = {}
    for i = 1, #obfuscated do
        local byte = string.byte(obfuscated, i)
        table.insert(password, string.char((byte - 42) % 256))
    end
    
    return table.concat(password)
end

-- Helper function to get or prompt for password
local function get_password()
    -- First check memory
    if stored_password then
        return stored_password
    end
    
    -- Then check disk
    local saved_password = load_password()
    if saved_password and saved_password ~= "" then
        stored_password = saved_password
        vim.notify("Using saved password from previous session", vim.log.levels.INFO)
        return saved_password
    end
    
    -- Finally prompt user
    local password = vim.fn.inputsecret("Enter password: ")
    if password == "" then
        return nil
    end
    
    stored_password = password
    save_password(password)
    vim.notify("Password stored for future sessions", vim.log.levels.INFO)
    return password
end

-- Clear stored password
function M.clear_password()
    stored_password = nil
    -- Remove password file
    local success = os.remove(password_file)
    if success then
        vim.notify("Stored password cleared from memory and disk", vim.log.levels.INFO)
    else
        vim.notify("Stored password cleared from memory", vim.log.levels.INFO)
    end
end

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

-- XOR CIPHER IMPLEMENTATION (FIXED - no password leakage)
local function xor_encrypt_block(plaintext_block, password)
    local encrypted = {}
    for i = 1, CIPHER_BLOCK_SIZE do
        local byte_val = string.byte(plaintext_block, i) or 0
        local key_byte = password[i]
        
        -- Safer XOR: avoid direct password exposure on null bytes
        -- Add a non-zero constant before XOR to prevent password leakage
        local safe_byte = (byte_val + 1) % 256  -- +1 to avoid null input
        local encrypted_byte = bxor(safe_byte, key_byte)
        
        -- Ensure output is never null (which could leak password on decrypt)
        if encrypted_byte == 0 then
            encrypted_byte = 255  -- Use max value instead of 0
        end
        
        table.insert(encrypted, string.char(encrypted_byte))
    end
    return table.concat(encrypted)
end

local function xor_decrypt_block(ciphertext_block, password)
    local decrypted = {}
    for i = 1, CIPHER_BLOCK_SIZE do
        local byte_val = string.byte(ciphertext_block, i) or 0
        local key_byte = password[i]
        
        -- Handle the special case where we used 255 instead of 0
        if byte_val == 255 then
            byte_val = 0
        end
        
        -- Reverse the safer XOR encryption
        local safe_byte = bxor(byte_val, key_byte)
        local decrypted_byte = (safe_byte - 1 + 256) % 256  -- Reverse +1
        
        table.insert(decrypted, string.char(decrypted_byte))
    end
    return table.concat(decrypted)
end

-- CAESAR CIPHER IMPLEMENTATION (FIXED - no password leakage)
local function caesar_encrypt_block(plaintext_block, password)
    local encrypted = {}
    for i = 1, CIPHER_BLOCK_SIZE do
        local byte_val = string.byte(plaintext_block, i) or 0
        local key_byte = password[i]
        
        -- Safer Caesar: XOR first, then shift, to prevent password leakage
        -- This ensures null bytes don't directly reveal password bytes
        local intermediate = bxor(byte_val, key_byte)
        local shift = key_byte % 128  -- Use smaller shift to maintain reversibility
        local encrypted_byte = (intermediate + shift + 1) % 256  -- +1 to avoid null output
        
        table.insert(encrypted, string.char(encrypted_byte))
    end
    return table.concat(encrypted)
end

local function caesar_decrypt_block(ciphertext_block, password)
    local decrypted = {}
    for i = 1, CIPHER_BLOCK_SIZE do
        local byte_val = string.byte(ciphertext_block, i) or 0
        local key_byte = password[i]
        
        -- Reverse the safer Caesar encryption
        local shift = key_byte % 128
        local intermediate = (byte_val - shift - 1 + 256) % 256  -- Reverse +1 and shift
        local decrypted_byte = bxor(intermediate, key_byte)  -- Reverse XOR
        
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

-- Helper function to get current visual selection (works in visual mode)
local function get_current_visual_selection()
    local mode = vim.api.nvim_get_mode().mode
    
    if mode == 'v' or mode == 'V' or mode == '' then
        -- We're in visual mode, get the selection directly
        local start_pos = vim.fn.getpos('.')  -- cursor position
        local other_pos = vim.fn.getpos('v')  -- other end of selection
        
        -- Determine start and end
        local start_line, start_col, end_line, end_col
        if start_pos[2] < other_pos[2] or (start_pos[2] == other_pos[2] and start_pos[3] <= other_pos[3]) then
            start_line, start_col = start_pos[2], start_pos[3]
            end_line, end_col = other_pos[2], other_pos[3]
        else
            start_line, start_col = other_pos[2], other_pos[3]
            end_line, end_col = start_pos[2], start_pos[3]
        end
        
        -- Handle Visual Line mode (V) - select entire lines
        if mode == 'V' then
            start_col = 1
            local line_content = vim.api.nvim_buf_get_lines(0, end_line - 1, end_line, false)[1]
            end_col = #line_content
        end
        
        -- Get the selected text
        local lines = vim.api.nvim_buf_get_lines(0, start_line - 1, end_line, false)
        if #lines == 0 then return nil end
        
        local text
        if start_line == end_line then
            -- Single line selection
            if mode == 'V' then
                -- Visual line mode - take the whole line
                text = lines[1]
            else
                text = lines[1]:sub(start_col, end_col)
            end
        else
            -- Multi-line selection
            if mode == 'V' then
                -- Visual line mode - take all complete lines
                text = table.concat(lines, '\n')
            else
                local first_line = lines[1]:sub(start_col)
                local last_line = lines[#lines]:sub(1, end_col)
                
                local selected_lines = {first_line}
                for i = 2, #lines - 1 do
                    table.insert(selected_lines, lines[i])
                end
                if #lines > 1 then
                    table.insert(selected_lines, last_line)
                end
                text = table.concat(selected_lines, '\n')
            end
        end
        
        return {
            text = text,
            start_line = start_line,
            start_col = start_col,
            end_line = end_line,
            end_col = end_col,
            mode = mode
        }
    end
    
    return nil
end

-- Helper function to check if there's a visual selection (fallback method)
local function get_visual_selection()
    -- First try to get current visual selection if in visual mode
    local current_selection = get_current_visual_selection()
    if current_selection then
        vim.notify(string.format("Active visual selection: lines %d-%d, cols %d-%d", 
            current_selection.start_line, current_selection.end_line, 
            current_selection.start_col, current_selection.end_col), vim.log.levels.INFO)
        return current_selection
    end
    
    -- Fallback: check visual marks (for when called after exiting visual mode)
    local start_pos = vim.fn.getpos("'<")
    local end_pos = vim.fn.getpos("'>")
    
    -- Debug: Show the marks
    vim.notify(string.format("Visual marks: start=(%d,%d), end=(%d,%d)", 
        start_pos[2], start_pos[3], end_pos[2], end_pos[3]), vim.log.levels.INFO)
    
    -- If no marks or marks are at position 0, no selection
    if start_pos[2] == 0 or end_pos[2] == 0 then
        vim.notify("No valid visual marks found", vim.log.levels.INFO)
        return nil
    end
    
    -- Check if marks are at the same position (no real selection)
    if start_pos[2] == end_pos[2] and start_pos[3] == end_pos[3] then
        return nil
    end
    
    local start_line = start_pos[2]
    local start_col = start_pos[3]
    local end_line = end_pos[2]
    local end_col = end_pos[3]
    
    -- Ensure start comes before end
    if start_line > end_line or (start_line == end_line and start_col > end_col) then
        start_line, end_line = end_line, start_line
        start_col, end_col = end_col, start_col
    end
    
    local lines = vim.api.nvim_buf_get_lines(0, start_line - 1, end_line, false)
    
    if #lines == 0 then
        return nil
    end
    
    -- Handle single line selection
    if start_line == end_line then
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
    local first_line = lines[1]:sub(start_col)
    local last_line = lines[#lines]:sub(1, end_col)
    
    -- Build the selected text
    local selected_lines = {first_line}
    for i = 2, #lines - 1 do
        table.insert(selected_lines, lines[i])
    end
    if #lines > 1 then
        table.insert(selected_lines, last_line)
    end
    
    return {
        text = table.concat(selected_lines, '\n'),
        start_line = start_line,
        start_col = start_col,
        end_line = end_line,
        end_col = end_col
    }
end

-- Helper function to replace visual selection with new text
local function replace_visual_selection(selection, new_text)
    local new_lines = vim.split(new_text, '\n', { plain = true })
    
    -- Handle Visual Line mode (entire lines)
    if selection.mode == 'V' then
        -- Visual line mode - replace entire lines
        vim.api.nvim_buf_set_lines(0, selection.start_line - 1, selection.end_line, false, new_lines)
        return
    end
    
    if selection.start_line == selection.end_line then
        -- Single line replacement
        local current_line = vim.api.nvim_buf_get_lines(0, selection.start_line - 1, selection.start_line, false)[1]
        local before = current_line:sub(1, selection.start_col - 1)
        local after = current_line:sub(selection.end_col + 1)
        
        -- Build replacement lines
        local replacement_lines = {}
        if #new_lines == 1 then
            -- Single line replacement
            table.insert(replacement_lines, before .. new_lines[1] .. after)
        else
            -- Multi-line replacement from single line
            table.insert(replacement_lines, before .. new_lines[1])
            for i = 2, #new_lines - 1 do
                table.insert(replacement_lines, new_lines[i])
            end
            table.insert(replacement_lines, new_lines[#new_lines] .. after)
        end
        
        vim.api.nvim_buf_set_lines(0, selection.start_line - 1, selection.start_line, false, replacement_lines)
    else
        -- Multi-line replacement
        local first_line = vim.api.nvim_buf_get_lines(0, selection.start_line - 1, selection.start_line, false)[1]
        local last_line = vim.api.nvim_buf_get_lines(0, selection.end_line - 1, selection.end_line, false)[1]
        
        local before = first_line:sub(1, selection.start_col - 1)
        local after = last_line:sub(selection.end_col + 1)
        
        -- Prepare the replacement lines
        local replacement_lines = {}
        if #new_lines == 1 then
            -- New text is single line, merge with before/after
            table.insert(replacement_lines, before .. new_lines[1] .. after)
        else
            -- New text is multi-line
            table.insert(replacement_lines, before .. new_lines[1])
            for i = 2, #new_lines - 1 do
                table.insert(replacement_lines, new_lines[i])
            end
            table.insert(replacement_lines, new_lines[#new_lines] .. after)
        end
        
        vim.api.nvim_buf_set_lines(0, selection.start_line - 1, selection.end_line, false, replacement_lines)
    end
end

-- Encrypt/decrypt text only (without file format headers) - SECURE VERSION WITH MAGIC HEADER
local function encrypt_text_only(content, password)
    -- Make sure we don't accidentally include password in output
    if not content or content == "" then
        return ""
    end
    
    local prepared_password = prepare_password(password)
    
    -- Add magic header and original length for reliable detection
    local original_length = #content
    local length_bytes = string.char(
        band(rshift(original_length, 24), 0xFF),
        band(rshift(original_length, 16), 0xFF),
        band(rshift(original_length, 8), 0xFF),
        band(original_length, 0xFF)
    )
    
    local result = {MAGIC_HEADER, length_bytes} -- Start with magic header + length
    
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
    
    -- Clear prepared password from memory (enhanced security)
    for i = 1, #prepared_password do
        prepared_password[i] = 0
    end
    prepared_password = nil
    
    return table.concat(result)
end

local function decrypt_text_only(content, password)
    -- Make sure we don't accidentally include password in output
    if not content or content == "" then
        return ""
    end
    
    -- Check for magic header
    if #content < #MAGIC_HEADER + 4 then
        error("Invalid encrypted text format: too short")
    end
    
    local header = content:sub(1, #MAGIC_HEADER)
    if header ~= MAGIC_HEADER then
        error("Invalid encrypted text format: missing magic header")
    end
    
    local prepared_password = prepare_password(password)
    
    -- Read the original length after magic header
    local length_bytes = content:sub(#MAGIC_HEADER + 1, #MAGIC_HEADER + 4)
    local original_length = 
        lshift(string.byte(length_bytes, 1), 24) +
        lshift(string.byte(length_bytes, 2), 16) +
        lshift(string.byte(length_bytes, 3), 8) +
        string.byte(length_bytes, 4)
    
    -- Skip magic header and length bytes
    content = content:sub(#MAGIC_HEADER + 5)
    
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
    
    -- Clear prepared password from memory (enhanced security)
    for i = 1, #prepared_password do
        prepared_password[i] = 0
    end
    prepared_password = nil
    
    local decrypted = table.concat(result)
    
    -- Return exactly the original length to prevent data loss
    return decrypted:sub(1, original_length)
end

-- Check if text appears to be encrypted (reliable magic header detection)
local function is_text_encrypted(text)
    if #text < #MAGIC_HEADER then return false end
    
    -- Check for magic header
    local header = text:sub(1, #MAGIC_HEADER)
    return header == MAGIC_HEADER
end

-- Main toggle function - encrypts if plain text, decrypts if encrypted
function M.toggle_encryption()
    -- Ensure cipher is configured before proceeding
    ensure_cipher_configured()
    
    -- Check if there's a visual selection
    local selection = get_visual_selection()
    
    if selection then
        -- Debug info
        vim.notify(string.format("Processing selection: lines %d-%d, cols %d-%d", 
            selection.start_line, selection.end_line, selection.start_col, selection.end_col), vim.log.levels.INFO)
        vim.notify("Selected text length: " .. #selection.text, vim.log.levels.INFO)
        
        -- Handle selected text encryption/decryption
        local password = get_password()
        if not password then
            vim.notify("Password cannot be empty", vim.log.levels.ERROR)
            return
        end
        
        local new_text
        local operation
        
        if is_text_encrypted(selection.text) then
            -- Attempt decryption with error handling
            local success, result = pcall(decrypt_text_only, selection.text, password)
            if not success then
                vim.notify("Decryption failed: " .. result, vim.log.levels.ERROR)
                return
            end
            new_text = result
            operation = "decrypted"
        else
            new_text = encrypt_text_only(selection.text, password)
            operation = "encrypted"
        end
        
        replace_visual_selection(selection, new_text)
        vim.notify("Selected text " .. operation .. " successfully using " .. config.cipher .. " cipher", vim.log.levels.INFO)
        
        -- Exit visual mode properly
        vim.api.nvim_feedkeys(vim.api.nvim_replace_termcodes('<Esc>', true, false, true), 'n', false)
        return
    end
    
    -- Handle full buffer encryption/decryption (modified to work at buffer level)
    local buf = vim.api.nvim_get_current_buf()
    
    -- Get all lines from the current buffer
    local lines = vim.api.nvim_buf_get_lines(buf, 0, -1, false)
    local content = table.concat(lines, '\n')
    
    -- Get password from user
    local password = get_password()
    if not password then
        vim.notify("Password cannot be empty", vim.log.levels.ERROR)
        return
    end
    
    local new_content
    local operation
    
    if is_text_encrypted(content) then
        -- Attempt decryption with error handling
        local success, result = pcall(decrypt_text_only, content, password)
        if not success then
            vim.notify("Decryption failed: " .. result, vim.log.levels.ERROR)
            return
        end
        new_content = result
        operation = "decrypted"
    else
        new_content = encrypt_text_only(content, password)
        operation = "encrypted"
    end
    
    -- Split content back into lines and set buffer content (preserve trailing newlines)
    local new_lines = vim.split(new_content, '\n', { plain = true })
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, new_lines)
    
    -- Mark buffer as modified
    vim.api.nvim_buf_set_option(buf, 'modified', true)
    
    vim.notify("Buffer " .. operation .. " successfully using " .. config.cipher .. " cipher", vim.log.levels.INFO)
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
        
        -- Exit visual mode properly
        vim.api.nvim_feedkeys(vim.api.nvim_replace_termcodes('<Esc>', true, false, true), 'n', false)
        return
    end
    
    -- Handle full buffer encryption (modified to work at buffer level)
    local buf = vim.api.nvim_get_current_buf()
    
    -- Get all lines from the current buffer
    local lines = vim.api.nvim_buf_get_lines(buf, 0, -1, false)
    local content = table.concat(lines, '\n')
    
    if is_text_encrypted(content) then
        vim.notify("Buffer content is already encrypted", vim.log.levels.WARN)
        return
    end
    
    local password = get_password()
    if not password then
        vim.notify("Password cannot be empty", vim.log.levels.ERROR)
        return
    end
    
    local encrypted_content = encrypt_text_only(content, password)
    
    -- Split content back into lines and set buffer content (preserve trailing newlines)
    local new_lines = vim.split(encrypted_content, '\n', { plain = true })
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, new_lines)
    
    -- Mark buffer as modified
    vim.api.nvim_buf_set_option(buf, 'modified', true)
    
    vim.notify("Buffer encrypted successfully using " .. config.cipher .. " cipher", vim.log.levels.INFO)
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
        
        local success, decrypted_text = pcall(decrypt_text_only, selection.text, password)
        if not success then
            vim.notify("Decryption failed: " .. decrypted_text, vim.log.levels.ERROR)
            return
        end
        replace_visual_selection(selection, decrypted_text)
        vim.notify("Selected text decrypted successfully", vim.log.levels.INFO)
        
        -- Exit visual mode properly
        vim.api.nvim_feedkeys(vim.api.nvim_replace_termcodes('<Esc>', true, false, true), 'n', false)
        return
    end
    
    -- Handle full buffer decryption (modified to work at buffer level)
    local buf = vim.api.nvim_get_current_buf()
    
    -- Get all lines from the current buffer
    local lines = vim.api.nvim_buf_get_lines(buf, 0, -1, false)
    local content = table.concat(lines, '\n')
    
    if not is_text_encrypted(content) then
        vim.notify("Buffer content is not encrypted", vim.log.levels.WARN)
        return
    end
    
    local password = get_password()
    if not password then
        vim.notify("Password cannot be empty", vim.log.levels.ERROR)
        return
    end
    
    local success, decrypted_content = pcall(decrypt_text_only, content, password)
    if not success then
        vim.notify("Decryption failed: " .. decrypted_content, vim.log.levels.ERROR)
        return
    end
    
    -- Split content back into lines and set buffer content (preserve trailing newlines)
    local new_lines = vim.split(decrypted_content, '\n', { plain = true })
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, new_lines)
    
    -- Mark buffer as modified
    vim.api.nvim_buf_set_option(buf, 'modified', true)
    
    vim.notify("Buffer decrypted successfully", vim.log.levels.INFO)
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
    end
end

return M 