-- Unit tests for encryption format detection
-- Tests is_encrypted, is_text_encrypted, is_file_encrypted

local vim_mock = require("spec.mocks.vim_mock")
_G.vim = vim_mock.vim

local bl = require("spec.bytelocker_testable")

describe("Format Detection", function()
    before_each(function()
        vim_mock.reset()
        bl.reset()
    end)

    describe("is_encrypted (legacy null-byte detection)", function()
        it("should return false for empty content", function()
            assert.is_false(bl.is_encrypted(""))
        end)

        it("should return true for content starting with null byte", function()
            local content = string.char(0) .. "remaining content"
            assert.is_true(bl.is_encrypted(content))
        end)

        it("should return false for content not starting with null byte", function()
            local content = "normal text content"
            assert.is_false(bl.is_encrypted(content))
        end)

        it("should return false for single non-null byte", function()
            assert.is_false(bl.is_encrypted("x"))
        end)

        it("should return true for single null byte", function()
            assert.is_true(bl.is_encrypted(string.char(0)))
        end)

        it("should only check first byte", function()
            -- Content with null byte not at start
            local content = "hello" .. string.char(0) .. "world"
            assert.is_false(bl.is_encrypted(content))
        end)
    end)

    describe("is_text_encrypted (magic header detection)", function()
        it("should return false for empty content", function()
            assert.is_false(bl.is_text_encrypted(""))
        end)

        it("should return false for content shorter than magic header", function()
            assert.is_false(bl.is_text_encrypted("BYTELOC"))  -- 7 chars, header is 9
        end)

        it("should return true for content with exact magic header", function()
            local content = bl.MAGIC_HEADER
            assert.is_true(bl.is_text_encrypted(content))
        end)

        it("should return true for content starting with magic header", function()
            local content = bl.MAGIC_HEADER .. "some encrypted data follows"
            assert.is_true(bl.is_text_encrypted(content))
        end)

        it("should return false for similar but incorrect header", function()
            assert.is_false(bl.is_text_encrypted("BYTELOCK"))  -- missing R
            assert.is_false(bl.is_text_encrypted("bytelockr"))  -- lowercase
            assert.is_false(bl.is_text_encrypted("BYTELOCKE"))  -- wrong char
        end)

        it("should return false for header in middle of content", function()
            local content = "prefix" .. bl.MAGIC_HEADER .. "suffix"
            assert.is_false(bl.is_text_encrypted(content))
        end)

        it("should return false for plain text", function()
            assert.is_false(bl.is_text_encrypted("Hello, World!"))
            assert.is_false(bl.is_text_encrypted("This is a test file."))
        end)
    end)

    describe("is_file_encrypted (file wrapper detection)", function()
        it("should return false for empty content", function()
            assert.is_false(bl.is_file_encrypted(""))
        end)

        it("should return true for content with file header", function()
            local content = "---BYTELOCKER-ENCRYPTED-FILE---\nbase64content\n---END-BYTELOCKER-ENCRYPTED-FILE---"
            assert.is_true(bl.is_file_encrypted(content))
        end)

        it("should return true even with just header (incomplete file)", function()
            local content = "---BYTELOCKER-ENCRYPTED-FILE---"
            assert.is_true(bl.is_file_encrypted(content))
        end)

        it("should return false for similar but incorrect header", function()
            assert.is_false(bl.is_file_encrypted("--BYTELOCKER-ENCRYPTED-FILE---"))
            assert.is_false(bl.is_file_encrypted("---BYTELOCKER-ENCRYPTED-FILE--"))
            assert.is_false(bl.is_file_encrypted("---bytelocker-encrypted-file---"))
        end)

        it("should return false for header in middle of content", function()
            local content = "some prefix---BYTELOCKER-ENCRYPTED-FILE---"
            assert.is_false(bl.is_file_encrypted(content))
        end)

        it("should return false for plain text", function()
            assert.is_false(bl.is_file_encrypted("Hello, World!"))
            assert.is_false(bl.is_file_encrypted("This is a regular file."))
        end)

        it("should return false for magic header only (wrong format)", function()
            local content = bl.MAGIC_HEADER .. "data"
            assert.is_false(bl.is_file_encrypted(content))
        end)
    end)

    describe("detection with actual encrypted content", function()
        local password = "test_password"

        before_each(function()
            bl.set_cipher("shift")
        end)

        it("should detect text-encrypted content", function()
            local plaintext = "Hello, secret world!"
            local encrypted = bl.encrypt_text_only(plaintext, password)

            assert.is_true(bl.is_text_encrypted(encrypted))
            assert.is_false(bl.is_file_encrypted(encrypted))
        end)

        it("should detect file-encrypted content", function()
            local plaintext = "Hello, secret world!"
            local encrypted = bl.encrypt_for_file(plaintext, password)

            assert.is_true(bl.is_file_encrypted(encrypted))
            -- Note: is_text_encrypted checks for magic header at start,
            -- but file format starts with "---BYTELOCKER..."
            assert.is_false(bl.is_text_encrypted(encrypted))
        end)

        it("should not detect plain text as encrypted", function()
            local plaintext = "This is not encrypted content."

            assert.is_false(bl.is_text_encrypted(plaintext))
            assert.is_false(bl.is_file_encrypted(plaintext))
        end)

        it("should work with all cipher types", function()
            local plaintext = "Test with different ciphers"

            for cipher, _ in pairs(bl.CIPHERS) do
                bl.set_cipher(cipher)

                local text_enc = bl.encrypt_text_only(plaintext, password)
                local file_enc = bl.encrypt_for_file(plaintext, password)

                assert.is_true(bl.is_text_encrypted(text_enc),
                    string.format("text detection failed for %s", cipher))
                assert.is_true(bl.is_file_encrypted(file_enc),
                    string.format("file detection failed for %s", cipher))
            end
        end)
    end)

    describe("edge cases", function()
        it("should handle content that looks almost like header", function()
            -- Content very close to but not matching headers
            local almost_magic = "BYTELOCKX" .. string.rep("x", 100)
            local almost_file = "---BYTELOCKER-ENCRYPTED-FILE--" .. string.rep("x", 100)

            assert.is_false(bl.is_text_encrypted(almost_magic))
            assert.is_false(bl.is_file_encrypted(almost_file))
        end)

        it("should handle binary content", function()
            -- Random binary data (shouldn't match headers)
            local binary = ""
            for i = 0, 255 do
                binary = binary .. string.char(i)
            end

            assert.is_false(bl.is_text_encrypted(binary))
            assert.is_false(bl.is_file_encrypted(binary))
        end)

        it("should handle content with newlines at start", function()
            local content = "\n---BYTELOCKER-ENCRYPTED-FILE---"
            assert.is_false(bl.is_file_encrypted(content))
        end)

        it("should handle content with spaces at start", function()
            local content = " ---BYTELOCKER-ENCRYPTED-FILE---"
            assert.is_false(bl.is_file_encrypted(content))
        end)
    end)
end)
