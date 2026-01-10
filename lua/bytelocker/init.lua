local M = {}

-- Import core module for all encryption logic
local core = require("bytelocker.core")

-- Re-export constants for compatibility
M.CIPHERS = core.CIPHERS

-- Default configuration
local config = {
    cipher = "shift",
    setup_keymaps = false
}

-- Store password in memory and persistently
local stored_password = nil
local password_file = vim.fn.stdpath('data') .. '/bytelocker_session.dat'

-- Store cipher choice persistently
local cipher_file = vim.fn.stdpath('data') .. '/bytelocker_cipher.dat'

-- Helper function to save password to disk (with basic obfuscation)
local function save_password(password)
    if not password then return end
    local obfuscated = core.obfuscate_password(password)
    local file = io.open(password_file, 'wb')
    if file then
        file:write(obfuscated)
        file:close()
    end
end

-- Helper function to load password from disk
local function load_password()
    local file = io.open(password_file, 'rb')
    if not file then return nil end

    local obfuscated = file:read('*all')
    file:close()

    return core.deobfuscate_password(obfuscated)
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

-- Helper function to save cipher choice to disk
local function save_cipher(cipher)
    if not cipher then return end
    local file = io.open(cipher_file, 'w')
    if file then
        file:write(cipher)
        file:close()
    end
end

-- Helper function to load cipher choice from disk
local function load_cipher()
    local file = io.open(cipher_file, 'r')
    if not file then return nil end

    local cipher = file:read('*all')
    file:close()

    if cipher and cipher ~= "" and core.CIPHERS[cipher] then
        return cipher
    end

    return nil
end

-- Clear stored password
function M.clear_password()
    stored_password = nil
    local success = os.remove(password_file)
    if success then
        vim.notify("Stored password cleared from memory and disk", vim.log.levels.INFO)
    else
        vim.notify("Stored password cleared from memory", vim.log.levels.INFO)
    end
end

-- Clear stored cipher choice
function M.clear_cipher()
    config.cipher = "shift"
    config._cipher_selected = false
    local success = os.remove(cipher_file)
    if success then
        vim.notify("Stored cipher choice cleared and reset to default", vim.log.levels.INFO)
    else
        vim.notify("Cipher choice reset to default", vim.log.levels.INFO)
    end
end

-- User cipher selection
local function select_cipher()
    local choices = {"Select encryption cipher:"}
    local cipher_keys = {}

    local index = 1
    for key, cipher in pairs(core.CIPHERS) do
        table.insert(choices, string.format("%d. %s - %s", index, cipher.name, cipher.description))
        table.insert(cipher_keys, key)
        index = index + 1
    end

    local choice = vim.fn.inputlist(choices)

    local selected_cipher
    if choice > 0 and choice <= #cipher_keys then
        selected_cipher = cipher_keys[choice]
    else
        selected_cipher = "shift"
    end

    save_cipher(selected_cipher)
    return selected_cipher
end

-- Helper function to ensure cipher is configured
local function ensure_cipher_configured()
    if not config._cipher_selected then
        vim.notify("Please select your encryption cipher:", vim.log.levels.INFO)
        config.cipher = select_cipher()
        config._cipher_selected = true
        vim.notify("Cipher set to: " .. core.CIPHERS[config.cipher].name, vim.log.levels.INFO)
    end
end

-- Helper function to get current visual selection (works in visual mode)
local function get_current_visual_selection()
    local mode = vim.api.nvim_get_mode().mode

    if mode == 'v' or mode == 'V' or mode == '' then
        local start_pos = vim.fn.getpos('.')
        local other_pos = vim.fn.getpos('v')

        local start_line, start_col, end_line, end_col
        if start_pos[2] < other_pos[2] or (start_pos[2] == other_pos[2] and start_pos[3] <= other_pos[3]) then
            start_line, start_col = start_pos[2], start_pos[3]
            end_line, end_col = other_pos[2], other_pos[3]
        else
            start_line, start_col = other_pos[2], other_pos[3]
            end_line, end_col = start_pos[2], start_pos[3]
        end

        if mode == 'V' then
            start_col = 1
            local line_content = vim.api.nvim_buf_get_lines(0, end_line - 1, end_line, false)[1]
            end_col = #line_content
        end

        local lines = vim.api.nvim_buf_get_lines(0, start_line - 1, end_line, false)
        if #lines == 0 then return nil end

        local text
        if start_line == end_line then
            if mode == 'V' then
                text = lines[1]
            else
                text = lines[1]:sub(start_col, end_col)
            end
        else
            if mode == 'V' then
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
    local current_selection = get_current_visual_selection()
    if current_selection then
        vim.notify(string.format("Active visual selection: lines %d-%d, cols %d-%d",
            current_selection.start_line, current_selection.end_line,
            current_selection.start_col, current_selection.end_col), vim.log.levels.INFO)
        return current_selection
    end

    local start_pos = vim.fn.getpos("'<")
    local end_pos = vim.fn.getpos("'>")

    vim.notify(string.format("Visual marks: start=(%d,%d), end=(%d,%d)",
        start_pos[2], start_pos[3], end_pos[2], end_pos[3]), vim.log.levels.INFO)

    if start_pos[2] == 0 or end_pos[2] == 0 then
        vim.notify("No valid visual marks found", vim.log.levels.INFO)
        return nil
    end

    if start_pos[2] == end_pos[2] and start_pos[3] == end_pos[3] then
        return nil
    end

    local start_line = start_pos[2]
    local start_col = start_pos[3]
    local end_line = end_pos[2]
    local end_col = end_pos[3]

    if start_line > end_line or (start_line == end_line and start_col > end_col) then
        start_line, end_line = end_line, start_line
        start_col, end_col = end_col, start_col
    end

    local lines = vim.api.nvim_buf_get_lines(0, start_line - 1, end_line, false)

    if #lines == 0 then
        return nil
    end

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

    local first_line = lines[1]:sub(start_col)
    local last_line = lines[#lines]:sub(1, end_col)

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

    if selection.mode == 'V' then
        vim.api.nvim_buf_set_lines(0, selection.start_line - 1, selection.end_line, false, new_lines)
        return
    end

    if selection.start_line == selection.end_line then
        local current_line = vim.api.nvim_buf_get_lines(0, selection.start_line - 1, selection.start_line, false)[1]
        local before = current_line:sub(1, selection.start_col - 1)
        local after = current_line:sub(selection.end_col + 1)

        local replacement_lines = {}
        if #new_lines == 1 then
            table.insert(replacement_lines, before .. new_lines[1] .. after)
        else
            table.insert(replacement_lines, before .. new_lines[1])
            for i = 2, #new_lines - 1 do
                table.insert(replacement_lines, new_lines[i])
            end
            table.insert(replacement_lines, new_lines[#new_lines] .. after)
        end

        vim.api.nvim_buf_set_lines(0, selection.start_line - 1, selection.start_line, false, replacement_lines)
    else
        local first_line = vim.api.nvim_buf_get_lines(0, selection.start_line - 1, selection.start_line, false)[1]
        local last_line = vim.api.nvim_buf_get_lines(0, selection.end_line - 1, selection.end_line, false)[1]

        local before = first_line:sub(1, selection.start_col - 1)
        local after = last_line:sub(selection.end_col + 1)

        local replacement_lines = {}
        if #new_lines == 1 then
            table.insert(replacement_lines, before .. new_lines[1] .. after)
        else
            table.insert(replacement_lines, before .. new_lines[1])
            for i = 2, #new_lines - 1 do
                table.insert(replacement_lines, new_lines[i])
            end
            table.insert(replacement_lines, new_lines[#new_lines] .. after)
        end

        vim.api.nvim_buf_set_lines(0, selection.start_line - 1, selection.end_line, false, replacement_lines)
    end
end

-- Main toggle function - encrypts if plain text, decrypts if encrypted
function M.toggle_encryption()
    ensure_cipher_configured()

    local selection = get_visual_selection()

    if selection then
        vim.notify(string.format("Processing selection: lines %d-%d, cols %d-%d",
            selection.start_line, selection.end_line, selection.start_col, selection.end_col), vim.log.levels.INFO)
        vim.notify("Selected text length: " .. #selection.text, vim.log.levels.INFO)

        local password = get_password()
        if not password then
            vim.notify("Password cannot be empty", vim.log.levels.ERROR)
            return
        end

        local new_text
        local operation

        if core.is_file_encrypted(selection.text) then
            local success, result = pcall(core.decrypt_from_file, selection.text, password, config.cipher)
            if not success then
                vim.notify("Decryption failed: " .. result, vim.log.levels.ERROR)
                return
            end
            new_text = result
            operation = "decrypted"
        else
            new_text = core.encrypt_for_file(selection.text, password, config.cipher)
            operation = "encrypted"
        end

        replace_visual_selection(selection, new_text)
        vim.notify("Selected text " .. operation .. " successfully using " .. config.cipher .. " cipher", vim.log.levels.INFO)

        vim.api.nvim_feedkeys(vim.api.nvim_replace_termcodes('<Esc>', true, false, true), 'n', false)
        return
    end

    local buf = vim.api.nvim_get_current_buf()
    local lines = vim.api.nvim_buf_get_lines(buf, 0, -1, false)
    local content = table.concat(lines, '\n')

    local password = get_password()
    if not password then
        vim.notify("Password cannot be empty", vim.log.levels.ERROR)
        return
    end

    local new_content
    local operation

    if core.is_file_encrypted(content) then
        local success, result = pcall(core.decrypt_from_file, content, password, config.cipher)
        if not success then
            vim.notify("Decryption failed: " .. result, vim.log.levels.ERROR)
            return
        end
        new_content = result
        operation = "decrypted"
    else
        new_content = core.encrypt_for_file(content, password, config.cipher)
        operation = "encrypted"
    end

    local new_lines = vim.split(new_content, '\n', { plain = true })
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, new_lines)
    vim.api.nvim_buf_set_option(buf, 'modified', true)

    vim.notify("Buffer " .. operation .. " successfully using " .. config.cipher .. " cipher", vim.log.levels.INFO)
end

-- Encrypt current buffer content
function M.encrypt()
    ensure_cipher_configured()

    local selection = get_visual_selection()

    if selection then
        if core.is_file_encrypted(selection.text) then
            vim.notify("Selected text is already encrypted", vim.log.levels.WARN)
            return
        end

        local password = get_password()
        if not password then
            vim.notify("Password cannot be empty", vim.log.levels.ERROR)
            return
        end

        local encrypted_text = core.encrypt_for_file(selection.text, password, config.cipher)
        replace_visual_selection(selection, encrypted_text)
        vim.notify("Selected text encrypted successfully using " .. config.cipher .. " cipher", vim.log.levels.INFO)

        vim.api.nvim_feedkeys(vim.api.nvim_replace_termcodes('<Esc>', true, false, true), 'n', false)
        return
    end

    local buf = vim.api.nvim_get_current_buf()
    local lines = vim.api.nvim_buf_get_lines(buf, 0, -1, false)
    local content = table.concat(lines, '\n')

    if core.is_file_encrypted(content) then
        vim.notify("Buffer content is already encrypted", vim.log.levels.WARN)
        return
    end

    local password = get_password()
    if not password then
        vim.notify("Password cannot be empty", vim.log.levels.ERROR)
        return
    end

    local encrypted_content = core.encrypt_for_file(content, password, config.cipher)

    local new_lines = vim.split(encrypted_content, '\n', { plain = true })
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, new_lines)
    vim.api.nvim_buf_set_option(buf, 'modified', true)

    vim.notify("Buffer encrypted successfully using " .. config.cipher .. " cipher", vim.log.levels.INFO)
end

-- Decrypt current buffer content
function M.decrypt()
    ensure_cipher_configured()

    local selection = get_visual_selection()

    if selection then
        if not core.is_file_encrypted(selection.text) then
            vim.notify("Selected text is not encrypted", vim.log.levels.WARN)
            return
        end

        local password = get_password()
        if not password then
            vim.notify("Password cannot be empty", vim.log.levels.ERROR)
            return
        end

        local success, decrypted_text = pcall(core.decrypt_from_file, selection.text, password, config.cipher)
        if not success then
            vim.notify("Decryption failed: " .. decrypted_text, vim.log.levels.ERROR)
            return
        end
        replace_visual_selection(selection, decrypted_text)
        vim.notify("Selected text decrypted successfully", vim.log.levels.INFO)

        vim.api.nvim_feedkeys(vim.api.nvim_replace_termcodes('<Esc>', true, false, true), 'n', false)
        return
    end

    local buf = vim.api.nvim_get_current_buf()
    local lines = vim.api.nvim_buf_get_lines(buf, 0, -1, false)
    local content = table.concat(lines, '\n')

    if not core.is_file_encrypted(content) then
        vim.notify("Buffer content is not encrypted", vim.log.levels.WARN)
        return
    end

    local password = get_password()
    if not password then
        vim.notify("Password cannot be empty", vim.log.levels.ERROR)
        return
    end

    local success, decrypted_content = pcall(core.decrypt_from_file, content, password, config.cipher)
    if not success then
        vim.notify("Decryption failed: " .. decrypted_content, vim.log.levels.ERROR)
        return
    end

    local new_lines = vim.split(decrypted_content, '\n', { plain = true })
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, new_lines)
    vim.api.nvim_buf_set_option(buf, 'modified', true)

    vim.notify("Buffer decrypted successfully", vim.log.levels.INFO)
end

-- Change cipher method
function M.change_cipher()
    local new_cipher = select_cipher()
    config.cipher = new_cipher
    config._cipher_selected = true
    vim.notify("Cipher changed to: " .. core.CIPHERS[new_cipher].name .. " (saved for future sessions)", vim.log.levels.INFO)
end

-- Setup function for plugin configuration
function M.setup(opts)
    opts = opts or {}

    config = vim.tbl_deep_extend("force", config, opts)

    local user_provided_cipher = opts.cipher

    local saved_cipher = load_cipher()
    if saved_cipher then
        config.cipher = saved_cipher
        config._cipher_selected = true
    elseif user_provided_cipher then
        config._cipher_selected = true
        save_cipher(user_provided_cipher)
    end

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

    vim.api.nvim_create_user_command('BytelockerClearCipher', M.clear_cipher, {
        desc = 'Clear stored cipher choice and reset to default'
    })

    if config.setup_keymaps then
        vim.keymap.set('n', 'E', M.toggle_encryption, { desc = 'Bytelocker: Toggle encryption' })
        vim.keymap.set('v', 'E', M.toggle_encryption, { desc = 'Bytelocker: Toggle encryption (selection)' })
        vim.keymap.set('n', '<leader>E', M.change_cipher, { desc = 'Bytelocker: Change cipher' })
    end
end

return M
