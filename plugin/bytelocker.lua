-- Bytelocker plugin entry point
-- This file is automatically loaded by Neovim

if vim.g.loaded_bytelocker then
    return
end
vim.g.loaded_bytelocker = 1

-- Auto-setup with default options if not already configured
if not vim.g.bytelocker_setup_done then
    require('bytelocker').setup()
    vim.g.bytelocker_setup_done = true
end 