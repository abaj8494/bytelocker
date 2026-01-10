# bytelocker.nvim

## Demo

![useage](./demo.gif)

## Intro

A Neovim plugin for encrypting and decrypting files using multiple cipher methods. The plugin automatically detects whether a file is encrypted or not and provides a symmetric toggle function.

## Features

- **Multiple cipher methods**: Choose from Shift, XOR, or Caesar ciphers
- **Automatic detection**: Detects if a file is encrypted or plain text
- **Toggle functionality**: Single command to encrypt plain text files or decrypt encrypted files
- **Separate encrypt/decrypt**: Individual commands for explicit encryption or decryption
- **Password protection**: Uses password-based encryption with your chosen cipher
- **Data integrity**: Improved algorithm prevents data loss during encryption/decryption cycles
- **Visual selection support**: Encrypt/decrypt selected text within a buffer
- **User-friendly**: Integrates seamlessly with Neovim workflow

## Installation

### Using [packer.nvim](https://github.com/wbthomason/packer.nvim)

```lua
use 'abaj8494/bytelocker.nvim'
```

### Using [lazy.nvim](https://github.com/folke/lazy.nvim)

```lua
{
    'abaj8494/bytelocker.nvim',
    config = function()
        require('bytelocker').setup({
            setup_keymaps = true,  -- Optional: set up default keymaps
            cipher = "shift"       -- Optional: pre-select cipher ("shift", "xor", "caesar")
                                  -- If not specified, you'll be prompted when first using the plugin
        })
    end
}
```

### Using [vim-plug](https://github.com/junegunn/vim-plug)

```vim
Plug 'abaj8494/bytelocker.nvim'
```

## Usage

### Commands

- `:BytelockerToggle` - Automatically encrypt plain text files or decrypt encrypted files
- `:BytelockerEncrypt` - Explicitly encrypt the current file
- `:BytelockerDecrypt` - Explicitly decrypt the current file
- `:BytelockerChangeCipher` - Change the encryption cipher method
- `:BytelockerClearPassword` - Clear stored password from memory and disk
- `:BytelockerClearCipher` - Reset cipher choice to default

### Default Keymaps (optional)

If you enable `setup_keymaps = true` in the setup configuration:

- `E` - Toggle encryption/decryption
- `<leader>E` - Change cipher method

### Configuration

```lua
require('bytelocker').setup({
    setup_keymaps = true,  -- Set to true to enable default keymaps
    cipher = "shift"       -- Choose cipher: "shift", "xor", or "caesar"
                          -- If not specified, you'll be prompted to select one
})
```

### Available Ciphers

- **Shift Cipher** (default): Bitwise rotation cipher - fast and reversible
- **XOR Cipher**: XOR-based encryption with rotation - secure against password leakage
- **Caesar Cipher**: Character shifting cipher with XOR preprocessing

## How it works

1. **Detection**: The plugin uses magic headers to determine if content is encrypted
   - File encryption uses `---BYTELOCKER-ENCRYPTED-FILE---` markers with base64 encoding
   - Text encryption uses a `BYTELOCKR` magic header

2. **Encryption**:
   - Stores original content length for perfect reconstruction
   - Processes content in 16-byte blocks using your chosen cipher
   - Encodes output as base64 for safe file storage

3. **Decryption**:
   - Validates magic headers and decodes base64
   - Processes encrypted blocks back to plain text
   - Restores exact original content length

## Security Notes

- Passwords are stored with basic obfuscation (not secure storage - for convenience only)
- The XOR cipher includes protection against password leakage on null input
- These ciphers are for casual privacy, not cryptographic security

## Testing

Run the test suite with:

```bash
make test
```

The project includes 298 tests covering all cipher implementations, edge cases, and integration scenarios.

## Data Integrity

- **Length preservation**: Original content length is stored in the encrypted header
- **Perfect reversibility**: All cipher implementations ensure encrypt/decrypt cycles preserve data exactly
- **Binary data support**: Handles all byte values (0-255) correctly
- **Unicode support**: Full support for UTF-8 and multi-byte characters
