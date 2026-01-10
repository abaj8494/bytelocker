-- Comprehensive Neovim API mocks for testing
-- This provides a minimal vim namespace that mimics Neovim's Lua API

local M = {}

-- Storage for test state
M._state = {
    buffers = { [0] = { lines = {}, modified = false } },
    current_buffer = 0,
    visual_marks = { ["<"] = { 0, 1, 1, 0 }, [">"] = { 0, 1, 1, 0 } },
    mode = { mode = "n", blocking = false },
    notifications = {},
    global_vars = {},
    stdpath_data = "/tmp/bytelocker_test_data",
    input_responses = {},
    inputlist_response = 1,
}

-- Reset state between tests
function M.reset()
    M._state = {
        buffers = { [0] = { lines = {}, modified = false } },
        current_buffer = 0,
        visual_marks = { ["<"] = { 0, 1, 1, 0 }, [">"] = { 0, 1, 1, 0 } },
        mode = { mode = "n", blocking = false },
        notifications = {},
        global_vars = {},
        stdpath_data = "/tmp/bytelocker_test_data",
        input_responses = {},
        inputlist_response = 1,
    }
    -- Create temp directory if it doesn't exist
    os.execute("mkdir -p " .. M._state.stdpath_data)
end

-- Helper to set buffer content
function M.set_buffer_content(lines, buf)
    buf = buf or 0
    M._state.buffers[buf] = M._state.buffers[buf] or { lines = {}, modified = false }
    M._state.buffers[buf].lines = lines
end

-- Helper to get buffer content
function M.get_buffer_content(buf)
    buf = buf or 0
    return M._state.buffers[buf] and M._state.buffers[buf].lines or {}
end

-- Helper to set visual selection
function M.set_visual_selection(start_line, start_col, end_line, end_col)
    M._state.visual_marks["<"] = { 0, start_line, start_col, 0 }
    M._state.visual_marks[">"] = { 0, end_line, end_col, 0 }
end

-- Helper to set current mode
function M.set_mode(mode)
    M._state.mode = { mode = mode, blocking = false }
end

-- Helper to get notifications
function M.get_notifications()
    return M._state.notifications
end

-- Helper to set password input response
function M.set_input_response(response)
    table.insert(M._state.input_responses, response)
end

-- Helper to set inputlist response
function M.set_inputlist_response(choice)
    M._state.inputlist_response = choice
end

-- Build the vim mock namespace
local vim_mock = {}

-- vim.g (global variables)
vim_mock.g = setmetatable({}, {
    __index = function(_, key)
        return M._state.global_vars[key]
    end,
    __newindex = function(_, key, value)
        M._state.global_vars[key] = value
    end
})

-- vim.fn (vimscript functions)
vim_mock.fn = {
    stdpath = function(what)
        if what == "data" then
            return M._state.stdpath_data
        end
        return "/tmp"
    end,

    inputsecret = function(prompt)
        if #M._state.input_responses > 0 then
            return table.remove(M._state.input_responses, 1)
        end
        return "test_password"
    end,

    input = function(prompt)
        if #M._state.input_responses > 0 then
            return table.remove(M._state.input_responses, 1)
        end
        return ""
    end,

    inputlist = function(choices)
        return M._state.inputlist_response
    end,

    getpos = function(mark)
        if mark == "." then
            return { 0, 1, 1, 0 }  -- cursor position
        elseif mark == "v" then
            return { 0, 1, 1, 0 }  -- other end of visual selection
        elseif mark == "'<" then
            return M._state.visual_marks["<"]
        elseif mark == "'>" then
            return M._state.visual_marks[">"]
        end
        return { 0, 0, 0, 0 }
    end,
}

-- vim.api (Neovim API functions)
vim_mock.api = {
    nvim_get_current_buf = function()
        return M._state.current_buffer
    end,

    nvim_buf_get_lines = function(buf, start_idx, end_idx, strict)
        local buffer = M._state.buffers[buf]
        if not buffer then return {} end

        local lines = buffer.lines
        if end_idx == -1 then end_idx = #lines end

        local result = {}
        for i = start_idx + 1, end_idx do
            table.insert(result, lines[i] or "")
        end
        return result
    end,

    nvim_buf_set_lines = function(buf, start_idx, end_idx, strict, replacement)
        M._state.buffers[buf] = M._state.buffers[buf] or { lines = {}, modified = false }
        local lines = M._state.buffers[buf].lines

        if end_idx == -1 then end_idx = #lines end

        -- Remove old lines and insert new ones
        local new_lines = {}
        for i = 1, start_idx do
            new_lines[i] = lines[i]
        end
        for i, line in ipairs(replacement) do
            new_lines[start_idx + i] = line
        end
        for i = end_idx + 1, #lines do
            new_lines[#new_lines + 1] = lines[i]
        end

        M._state.buffers[buf].lines = new_lines
    end,

    nvim_buf_set_option = function(buf, option, value)
        if option == "modified" then
            M._state.buffers[buf] = M._state.buffers[buf] or { lines = {}, modified = false }
            M._state.buffers[buf].modified = value
        end
    end,

    nvim_get_mode = function()
        return M._state.mode
    end,

    nvim_create_user_command = function(name, callback, opts)
        -- Store command for verification
        M._state.commands = M._state.commands or {}
        M._state.commands[name] = { callback = callback, opts = opts }
    end,

    nvim_feedkeys = function(keys, mode, escape_ks)
        -- No-op for testing
    end,

    nvim_replace_termcodes = function(str, from_part, do_lt, special)
        return str
    end,
}

-- vim.notify
vim_mock.notify = function(msg, level)
    table.insert(M._state.notifications, { msg = msg, level = level })
end

-- vim.log.levels
vim_mock.log = {
    levels = {
        DEBUG = 0,
        INFO = 1,
        WARN = 2,
        ERROR = 3,
    }
}

-- vim.split
vim_mock.split = function(str, sep, opts)
    opts = opts or {}
    local result = {}
    local pattern = sep
    if opts.plain then
        pattern = sep:gsub("([^%w])", "%%%1")
    end

    local pos = 1
    while true do
        local start_pos, end_pos = str:find(pattern, pos, opts.plain)
        if not start_pos then
            table.insert(result, str:sub(pos))
            break
        end
        table.insert(result, str:sub(pos, start_pos - 1))
        pos = end_pos + 1
    end

    return result
end

-- vim.tbl_deep_extend
vim_mock.tbl_deep_extend = function(behavior, ...)
    local result = {}
    local tables = {...}

    for _, tbl in ipairs(tables) do
        for k, v in pairs(tbl) do
            if type(v) == "table" and type(result[k]) == "table" then
                result[k] = vim_mock.tbl_deep_extend(behavior, result[k], v)
            else
                result[k] = v
            end
        end
    end

    return result
end

-- vim.keymap.set
vim_mock.keymap = {
    set = function(mode, lhs, rhs, opts)
        M._state.keymaps = M._state.keymaps or {}
        M._state.keymaps[mode .. ":" .. lhs] = { rhs = rhs, opts = opts }
    end
}

-- Assign to module and return
M.vim = vim_mock

return M
