-- Unit tests for Base64 encoding/decoding
-- Tests the custom implementation for ASCII-safe file storage

local core = require("bytelocker.core")

describe("Base64 Encoding", function()
    describe("standard test vectors", function()
        -- RFC 4648 test vectors
        it("should encode empty string", function()
            assert.are.equal("", core.base64_encode(""))
        end)

        it("should encode 'f' correctly", function()
            assert.are.equal("Zg==", core.base64_encode("f"))
        end)

        it("should encode 'fo' correctly", function()
            assert.are.equal("Zm8=", core.base64_encode("fo"))
        end)

        it("should encode 'foo' correctly", function()
            assert.are.equal("Zm9v", core.base64_encode("foo"))
        end)

        it("should encode 'foob' correctly", function()
            assert.are.equal("Zm9vYg==", core.base64_encode("foob"))
        end)

        it("should encode 'fooba' correctly", function()
            assert.are.equal("Zm9vYmE=", core.base64_encode("fooba"))
        end)

        it("should encode 'foobar' correctly", function()
            assert.are.equal("Zm9vYmFy", core.base64_encode("foobar"))
        end)
    end)

    describe("padding", function()
        it("should add two padding chars when length % 3 == 1", function()
            local encoded = core.base64_encode("x")
            assert.are.equal(4, #encoded)
            assert.are.equal("==", encoded:sub(-2))
        end)

        it("should add one padding char when length % 3 == 2", function()
            local encoded = core.base64_encode("xx")
            assert.are.equal(4, #encoded)
            assert.are.equal("=", encoded:sub(-1))
        end)

        it("should add no padding when length % 3 == 0", function()
            local encoded = core.base64_encode("xxx")
            assert.are.equal(4, #encoded)
            assert.is_not.equal("=", encoded:sub(-1))
        end)
    end)

    describe("ASCII safety", function()
        it("should only produce ASCII characters", function()
            -- Test with binary data containing all byte values
            local binary = ""
            for i = 0, 255 do
                binary = binary .. string.char(i)
            end

            local encoded = core.base64_encode(binary)

            for i = 1, #encoded do
                local byte = string.byte(encoded, i)
                assert.is_true(byte >= 32 and byte < 127,
                    string.format("Non-ASCII character at position %d: %d", i, byte))
            end
        end)

        it("should only use valid base64 characters", function()
            local valid_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
            local binary = string.rep(string.char(0xFF), 100) .. string.rep(string.char(0), 100)

            local encoded = core.base64_encode(binary)

            for i = 1, #encoded do
                local char = encoded:sub(i, i)
                assert.is_not_nil(valid_chars:find(char, 1, true),
                    string.format("Invalid base64 character: '%s'", char))
            end
        end)
    end)

    describe("special cases", function()
        it("should handle null bytes", function()
            local with_nulls = "hello\x00world\x00"
            local encoded = core.base64_encode(with_nulls)
            assert.is_true(#encoded > 0)
        end)

        it("should handle all 0xFF bytes", function()
            local all_ff = string.rep(string.char(0xFF), 16)
            local encoded = core.base64_encode(all_ff)
            assert.is_true(#encoded > 0)
        end)

        it("should handle alternating bytes", function()
            local alternating = ""
            for i = 1, 16 do
                alternating = alternating .. string.char(i % 2 == 0 and 0xFF or 0x00)
            end
            local encoded = core.base64_encode(alternating)
            assert.is_true(#encoded > 0)
        end)
    end)
end)

describe("Base64 Decoding", function()
    describe("standard test vectors", function()
        it("should decode empty string", function()
            assert.are.equal("", core.base64_decode(""))
        end)

        it("should decode 'Zg==' to 'f'", function()
            assert.are.equal("f", core.base64_decode("Zg=="))
        end)

        it("should decode 'Zm8=' to 'fo'", function()
            assert.are.equal("fo", core.base64_decode("Zm8="))
        end)

        it("should decode 'Zm9v' to 'foo'", function()
            assert.are.equal("foo", core.base64_decode("Zm9v"))
        end)

        it("should decode 'Zm9vYg==' to 'foob'", function()
            assert.are.equal("foob", core.base64_decode("Zm9vYg=="))
        end)

        it("should decode 'Zm9vYmE=' to 'fooba'", function()
            assert.are.equal("fooba", core.base64_decode("Zm9vYmE="))
        end)

        it("should decode 'Zm9vYmFy' to 'foobar'", function()
            assert.are.equal("foobar", core.base64_decode("Zm9vYmFy"))
        end)
    end)

    describe("padding handling", function()
        it("should handle missing padding", function()
            -- Decode should work without padding
            assert.are.equal("f", core.base64_decode("Zg"))
            assert.are.equal("fo", core.base64_decode("Zm8"))
        end)

        it("should handle single padding", function()
            assert.are.equal("fo", core.base64_decode("Zm8="))
        end)

        it("should handle double padding", function()
            assert.are.equal("f", core.base64_decode("Zg=="))
        end)
    end)

    describe("whitespace handling", function()
        it("should ignore spaces", function()
            assert.are.equal("foobar", core.base64_decode("Zm9v YmFy"))
        end)

        it("should ignore newlines", function()
            assert.are.equal("foobar", core.base64_decode("Zm9v\nYmFy"))
        end)

        it("should ignore tabs", function()
            assert.are.equal("foobar", core.base64_decode("Zm9v\tYmFy"))
        end)

        it("should ignore carriage returns", function()
            assert.are.equal("foobar", core.base64_decode("Zm9v\rYmFy"))
        end)

        it("should handle multiple whitespace types", function()
            assert.are.equal("foobar", core.base64_decode("Zm9v \n\t\r YmFy"))
        end)
    end)
end)

describe("Base64 Roundtrip", function()
    describe("text content", function()
        it("should roundtrip simple ASCII text", function()
            local original = "Hello, World!"
            local encoded = core.base64_encode(original)
            local decoded = core.base64_decode(encoded)
            assert.are.equal(original, decoded)
        end)

        it("should roundtrip empty string", function()
            local original = ""
            local encoded = core.base64_encode(original)
            local decoded = core.base64_decode(encoded)
            assert.are.equal(original, decoded)
        end)

        it("should roundtrip single character", function()
            for code = 32, 126 do
                local original = string.char(code)
                local encoded = core.base64_encode(original)
                local decoded = core.base64_decode(encoded)
                assert.are.equal(original, decoded,
                    string.format("Failed for char code %d", code))
            end
        end)

        it("should roundtrip various lengths", function()
            for length = 1, 100 do
                local original = string.rep("x", length)
                local encoded = core.base64_encode(original)
                local decoded = core.base64_decode(encoded)
                assert.are.equal(original, decoded,
                    string.format("Failed for length %d", length))
            end
        end)
    end)

    describe("binary content", function()
        it("should roundtrip all byte values", function()
            local original = ""
            for i = 0, 255 do
                original = original .. string.char(i)
            end

            local encoded = core.base64_encode(original)
            local decoded = core.base64_decode(encoded)
            assert.are.equal(original, decoded)
        end)

        it("should roundtrip null bytes", function()
            local original = string.rep(string.char(0), 16)
            local encoded = core.base64_encode(original)
            local decoded = core.base64_decode(encoded)
            assert.are.equal(original, decoded)
        end)

        it("should roundtrip 0xFF bytes", function()
            local original = string.rep(string.char(0xFF), 16)
            local encoded = core.base64_encode(original)
            local decoded = core.base64_decode(encoded)
            assert.are.equal(original, decoded)
        end)

        it("should roundtrip random-like patterns", function()
            for seed = 1, 10 do
                local original = ""
                for i = 1, 100 do
                    original = original .. string.char((seed * i + 17) % 256)
                end

                local encoded = core.base64_encode(original)
                local decoded = core.base64_decode(encoded)
                assert.are.equal(original, decoded,
                    string.format("Failed for seed %d", seed))
            end
        end)
    end)

    describe("length properties", function()
        it("should produce output length = ceil(input_length / 3) * 4", function()
            for length = 0, 50 do
                local original = string.rep("x", length)
                local encoded = core.base64_encode(original)
                local expected_len = math.ceil(length / 3) * 4
                assert.are.equal(expected_len, #encoded,
                    string.format("Wrong length for input length %d", length))
            end
        end)

        it("should restore exact original length after decode", function()
            for length = 0, 50 do
                local original = string.rep("x", length)
                local encoded = core.base64_encode(original)
                local decoded = core.base64_decode(encoded)
                assert.are.equal(length, #decoded,
                    string.format("Wrong restored length for input length %d", length))
            end
        end)
    end)
end)

describe("Base64 Edge Cases", function()
    describe("large data", function()
        it("should handle 1KB of data", function()
            local original = string.rep("x", 1024)
            local encoded = core.base64_encode(original)
            local decoded = core.base64_decode(encoded)
            assert.are.equal(original, decoded)
        end)

        it("should handle 10KB of random-like data", function()
            local original = ""
            for i = 1, 10240 do
                original = original .. string.char(i % 256)
            end

            local encoded = core.base64_encode(original)
            local decoded = core.base64_decode(encoded)
            assert.are.equal(original, decoded)
        end)
    end)

    describe("boundary conditions", function()
        it("should handle length 1 (needs 2 padding)", function()
            local original = "x"
            local encoded = core.base64_encode(original)
            local decoded = core.base64_decode(encoded)
            assert.are.equal(original, decoded)
        end)

        it("should handle length 2 (needs 1 padding)", function()
            local original = "xx"
            local encoded = core.base64_encode(original)
            local decoded = core.base64_decode(encoded)
            assert.are.equal(original, decoded)
        end)

        it("should handle length 3 (no padding)", function()
            local original = "xxx"
            local encoded = core.base64_encode(original)
            local decoded = core.base64_decode(encoded)
            assert.are.equal(original, decoded)
        end)
    end)

    describe("encrypted data roundtrip", function()
        it("should correctly handle typical encrypted content", function()
            -- Simulate encrypted content (magic header + binary data)
            local binary_data = core.MAGIC_HEADER
            for i = 1, 100 do
                binary_data = binary_data .. string.char(i % 256)
            end

            local encoded = core.base64_encode(binary_data)
            local decoded = core.base64_decode(encoded)
            assert.are.equal(binary_data, decoded)
        end)
    end)
end)
