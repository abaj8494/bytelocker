# Bytelocker

A Neovim plugin for encrypting and decrypting files using a simple shift cipher. The plugin automatically detects whether a file is encrypted or not and provides a symmetric toggle function.

## Features

- **Multiple cipher methods**: Choose from Shift, XOR, or Caesar ciphers
- **Automatic detection**: Detects if a file is encrypted or plain text
- **Toggle functionality**: Single command to encrypt plain text files or decrypt encrypted files
- **Separate encrypt/decrypt**: Individual commands for explicit encryption or decryption
- **Password protection**: Uses password-based encryption with your chosen cipher
- **Data integrity**: Improved algorithm prevents data loss during encryption/decryption cycles
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
            setup_keymaps = true,  -- Optional: set up default keymaps
            cipher = "shift"       -- Optional: pre-select cipher ("shift", "xor", "caesar")
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
- `:BytelockerChangeCipher` - Change the encryption cipher method

### Default Keymaps (optional)

If you enable `setup_keymaps = true` in the setup configuration:

- `<leader>Et` - Toggle encryption/decryption
- `<leader>Ee` - Encrypt file
- `<leader>Ed` - Decrypt file
- `<leader>Ec` - Change cipher method

### Configuration

```lua
require('bytelocker').setup({
    setup_keymaps = true,  -- Set to true to enable default keymaps
    cipher = "shift"       -- Choose cipher: "shift", "xor", or "caesar"
                          -- If not specified, you'll be prompted to select one
})
```

### Available Ciphers

- **Shift Cipher** (default): Bitwise rotation cipher - same as original C implementation
- **XOR Cipher**: XOR-based encryption - simple but effective
- **Caesar Cipher**: Character shifting cipher - classic substitution method

## How it works

1. **Detection**: The plugin checks the first byte of a file to determine if it's encrypted
   - If the first byte is a printable ASCII character (32-126), the file is considered plain text  
   - If the first byte is null (0), the file is considered encrypted

2. **Encryption**: 
   - Adds a null byte marker followed by the original file length (4 bytes)
   - Processes the content in 16-byte blocks using your chosen cipher
   - Pads incomplete blocks with null characters

3. **Decryption**:
   - Reads the null byte marker and original file length
   - Processes encrypted blocks back to plain text using the same cipher
   - Restores the exact original file length to prevent data loss

## Data Integrity Improvements

This version fixes potential data loss issues from the original C implementation:

- **Length preservation**: Original file length is stored in the encrypted file header
- **Perfect reversibility**: All cipher implementations ensure encrypt→decrypt cycles preserve data
- **Trailing data protection**: Files with trailing null bytes or binary data are handled correctly
- **Overflow protection**: Bit operations are properly bounded to prevent data corruption

## Security Note

⚠️ **Warning**: This plugin uses a simple shift cipher which provides only basic obfuscation, not cryptographic security. It should not be used for protecting sensitive data. For real security, use proper encryption tools like GPG.

## License

MIT License
