# Bytelocker

A Neovim plugin for encrypting and decrypting files using a simple shift cipher. The plugin automatically detects whether a file is encrypted or not and provides a symmetric toggle function.

## Features

- **Automatic detection**: Detects if a file is encrypted or plain text
- **Toggle functionality**: Single command to encrypt plain text files or decrypt encrypted files
- **Separate encrypt/decrypt**: Individual commands for explicit encryption or decryption
- **Password protection**: Uses password-based encryption with shift cipher
- **User-friendly**: Integrates seamlessly with Neovim workflow

## Installation

### Using [packer.nvim](https://github.com/wbthomason/packer.nvim)

```lua
use 'your-username/bytelocker'
```

### Using [lazy.nvim](https://github.com/folke/lazy.nvim)

```lua
{
    'your-username/bytelocker',
    config = function()
        require('bytelocker').setup({
            setup_keymaps = true  -- Optional: set up default keymaps
        })
    end
}
```

### Using [vim-plug](https://github.com/junegunn/vim-plug)

```vim
Plug 'your-username/bytelocker'
```

## Usage

### Commands

- `:BytelockerToggle` - Automatically encrypt plain text files or decrypt encrypted files
- `:BytelockerEncrypt` - Explicitly encrypt the current file
- `:BytelockerDecrypt` - Explicitly decrypt the current file

### Default Keymaps (optional)

If you enable `setup_keymaps = true` in the setup configuration:

- `<leader>bt` - Toggle encryption/decryption
- `<leader>be` - Encrypt file
- `<leader>bd` - Decrypt file

### Configuration

```lua
require('bytelocker').setup({
    setup_keymaps = true,  -- Set to true to enable default keymaps
})
```

## How it works

1. **Detection**: The plugin checks the first byte of a file to determine if it's encrypted
   - If the first byte is a printable ASCII character (32-126), the file is considered plain text
   - If the first byte is null (0), the file is considered encrypted

2. **Encryption**: 
   - Adds a null byte at the beginning to mark the file as encrypted
   - Processes the content in 16-byte blocks
   - Uses a shift cipher based on the provided password

3. **Decryption**:
   - Removes the null byte marker
   - Processes encrypted blocks back to plain text
   - Removes padding null characters

## Security Note

⚠️ **Warning**: This plugin uses a simple shift cipher which provides only basic obfuscation, not cryptographic security. It should not be used for protecting sensitive data. For real security, use proper encryption tools like GPG.

## License

MIT License
