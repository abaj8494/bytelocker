# Welcome to the bytelocker!

This is a small program written in C to help me consolidate by understanding of `FILE` streams, bitwise operations and memory representation. 

## What does it do??

Bytelocker takes in a file and a password as an argument and encrypts the file with an ECB cipher.

## Why is this useful?

You can of course use this binary from the command line to encrypt a standalone file, but as with most `C` programs, you will find this integrates nicely within larger workflows.

### My usecase.

I write in vim all day and rotate between writing code and building my wiki. As such sometimes I need to document slightly sensitive information which I don't want to leave in plaintext files. So I have added a binding to my vimrc calling this bytelocker utility with a password defined in my `.zprofile` as an environmental variable.

The code snippet looks like:
`nnoremap E :silent ! '/Users/aayushbajaj/Google Drive/2. - code/202. - c/202.6 - bytelocker/bytelocker' '%' '$bl_pass'<CR>:set noro<CR>`

where pressing capital E in normal mode will encrypt the file.
- silent suppresses output
- the exclamation is the execution of a shell command, which then runs the bytelocker executable from my google drive
- the percent sign is a vim macro for the current file
- and the password is retrieved from an environmental variable defined in `.zprofile`.
	- the definition looks like `export bl_pass="passwordpassword"`
	- **NOTE: the password must be 16 characters!!**
	- **NOTE: if you choose to define the password in another file, make sure your viwrc sources the file**
		- the line in .vimrc would look something like `so "~/.config/zsh/.zprofile"
		


