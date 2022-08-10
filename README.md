# Welcome to the bytelocker!

This is a small program written in C to help me consolidate by understanding of `FILE` streams, *bitwise operations* and *memory representations* of data. 

## What does bytelocker do?

Bytelocker takes in 2 arguments, a file and a password. It then encrypts this file in place with an ECB cipher.

## Why is this useful?

Whilst you can use this binary from the command line to encrypt a standalone file, as is the case with many `C` programs, you will find this integrates nicely within larger workflows. See below.

### My usecase.

I spend my day in vim and vimwiki. And sometimes I need to document slightly sensitive information which I don't feel comfortable leaving in plaintext. As such, I have added a binding to my vimrc calling the bytelocker utility.

The code snippet looks like:
`nnoremap E :silent ! '/Users/aayushbajaj/Google Drive/2. - code/202. - c/202.6 - bytelocker/bytelocker' '%' '$bl_pass'<CR>:set noro<CR>`

here pressing capital E in normal mode will encrypt the file.
- `silent` suppresses output
- `!` is the execution of a shell command, which then runs the bytelocker executable from my google drive
- `%` is a vim macro for the current file
- and the password is retrieved from an environmental variable defined in `.zprofile`.
	- the definition looks like `export bl_pass="passwordpassword"`
	- **NOTE: the password must be 16 characters!!**
	- **NOTE: if you choose to define the password in another file, make sure your viwrc sources the file**
		- the line in .vimrc would look something like `so "~/.config/zsh/.zprofile"
		

### Demo
![](img/demo.gif)

