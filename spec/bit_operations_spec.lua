-- Unit tests for bit rotation operations (rol8, ror8)
-- These are fundamental building blocks for the shift cipher

local core = require("bytelocker.core")

describe("Bit Operations", function()
    describe("rol8 (rotate left 8-bit)", function()
        it("should rotate 0x01 left by 1 bit to 0x02", function()
            assert.are.equal(0x02, core.rol8(0x01, 1))
        end)

        it("should rotate 0x01 left by 4 bits to 0x10", function()
            assert.are.equal(0x10, core.rol8(0x01, 4))
        end)

        it("should rotate 0x80 left by 1 bit to 0x01 (wrap around)", function()
            assert.are.equal(0x01, core.rol8(0x80, 1))
        end)

        it("should rotate 0xFF left by any amount to 0xFF", function()
            assert.are.equal(0xFF, core.rol8(0xFF, 1))
            assert.are.equal(0xFF, core.rol8(0xFF, 4))
            assert.are.equal(0xFF, core.rol8(0xFF, 7))
        end)

        it("should handle 0x00 correctly (always 0)", function()
            assert.are.equal(0x00, core.rol8(0x00, 1))
            assert.are.equal(0x00, core.rol8(0x00, 7))
        end)

        it("should handle rotation by 0 (identity)", function()
            assert.are.equal(0x42, core.rol8(0x42, 0))
            assert.are.equal(0xAB, core.rol8(0xAB, 0))
        end)

        it("should handle rotation by 8 (full cycle = identity)", function()
            assert.are.equal(0x42, core.rol8(0x42, 8))
            assert.are.equal(0xCD, core.rol8(0xCD, 8))
        end)

        it("should handle rotation by more than 8 (modulo)", function()
            -- 9 % 8 = 1, so rol8(x, 9) == rol8(x, 1)
            assert.are.equal(core.rol8(0x55, 1), core.rol8(0x55, 9))
            assert.are.equal(core.rol8(0xAA, 3), core.rol8(0xAA, 11))
        end)

        it("should rotate 0xAA (10101010) left by 1 to 0x55 (01010101)", function()
            assert.are.equal(0x55, core.rol8(0xAA, 1))
        end)

        it("should mask values > 255 to 8-bit", function()
            -- Input of 0x1FF should be masked to 0xFF
            assert.are.equal(core.rol8(0xFF, 1), core.rol8(0x1FF, 1))
        end)

        -- Property test: rol8 followed by ror8 with same amount = original
        it("should be reversible with ror8", function()
            for value = 0, 255, 17 do  -- Sample some values
                for bits = 0, 7 do
                    local rotated = core.rol8(value, bits)
                    local restored = core.ror8(rotated, bits)
                    assert.are.equal(value, restored,
                        string.format("Failed for value=%d, bits=%d", value, bits))
                end
            end
        end)
    end)

    describe("ror8 (rotate right 8-bit)", function()
        it("should rotate 0x02 right by 1 bit to 0x01", function()
            assert.are.equal(0x01, core.ror8(0x02, 1))
        end)

        it("should rotate 0x10 right by 4 bits to 0x01", function()
            assert.are.equal(0x01, core.ror8(0x10, 4))
        end)

        it("should rotate 0x01 right by 1 bit to 0x80 (wrap around)", function()
            assert.are.equal(0x80, core.ror8(0x01, 1))
        end)

        it("should rotate 0xFF right by any amount to 0xFF", function()
            assert.are.equal(0xFF, core.ror8(0xFF, 1))
            assert.are.equal(0xFF, core.ror8(0xFF, 4))
            assert.are.equal(0xFF, core.ror8(0xFF, 7))
        end)

        it("should handle 0x00 correctly (always 0)", function()
            assert.are.equal(0x00, core.ror8(0x00, 1))
            assert.are.equal(0x00, core.ror8(0x00, 7))
        end)

        it("should handle rotation by 0 (identity)", function()
            assert.are.equal(0x42, core.ror8(0x42, 0))
            assert.are.equal(0xAB, core.ror8(0xAB, 0))
        end)

        it("should handle rotation by 8 (full cycle = identity)", function()
            assert.are.equal(0x42, core.ror8(0x42, 8))
            assert.are.equal(0xCD, core.ror8(0xCD, 8))
        end)

        it("should rotate 0x55 (01010101) right by 1 to 0xAA (10101010)", function()
            assert.are.equal(0xAA, core.ror8(0x55, 1))
        end)

        -- Property test: ror8 followed by rol8 with same amount = original
        it("should be reversible with rol8", function()
            for value = 0, 255, 17 do
                for bits = 0, 7 do
                    local rotated = core.ror8(value, bits)
                    local restored = core.rol8(rotated, bits)
                    assert.are.equal(value, restored,
                        string.format("Failed for value=%d, bits=%d", value, bits))
                end
            end
        end)
    end)

    describe("combined rotation properties", function()
        it("rol8 by n equals ror8 by (8-n)", function()
            for value = 0, 255, 31 do
                for bits = 0, 7 do
                    local left_rotated = core.rol8(value, bits)
                    local right_rotated = core.ror8(value, 8 - bits)
                    assert.are.equal(left_rotated, right_rotated,
                        string.format("Failed for value=%d, bits=%d", value, bits))
                end
            end
        end)

        it("rotating 8 times by 1 equals original", function()
            for value = 0, 255, 31 do
                local rotated = value
                for _ = 1, 8 do
                    rotated = core.rol8(rotated, 1)
                end
                assert.are.equal(value, rotated)
            end
        end)
    end)
end)
