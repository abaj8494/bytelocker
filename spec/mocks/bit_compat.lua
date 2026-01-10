-- Bit operation compatibility layer
-- Works with both LuaJIT's 'bit' module and Lua 5.3+/5.4's native bitwise operators

local M = {}

-- Try to use LuaJIT's bit module first, fall back to native operators
local ok, bit = pcall(require, "bit")

if ok then
    -- LuaJIT's bit module is available
    M.band = bit.band
    M.bor = bit.bor
    M.bxor = bit.bxor
    M.bnot = bit.bnot
    M.lshift = bit.lshift
    M.rshift = bit.rshift
    M.arshift = bit.arshift
    M.rol = bit.rol
    M.ror = bit.ror
    M.tobit = bit.tobit
    M.tohex = bit.tohex
else
    -- Lua 5.3+ native bitwise operators
    -- These are implemented as functions wrapping the operators

    M.band = function(a, b)
        return a & b
    end

    M.bor = function(a, b)
        return a | b
    end

    M.bxor = function(a, b)
        return a ~ b
    end

    M.bnot = function(a)
        return ~a
    end

    M.lshift = function(a, n)
        return (a << n) & 0xFFFFFFFF
    end

    M.rshift = function(a, n)
        return (a & 0xFFFFFFFF) >> n
    end

    M.arshift = function(a, n)
        -- Arithmetic right shift (preserves sign)
        if a >= 0x80000000 then
            return ((a >> n) | (~((1 << (32 - n)) - 1))) & 0xFFFFFFFF
        else
            return a >> n
        end
    end

    -- 32-bit rotate left
    M.rol = function(a, n)
        n = n % 32
        a = a & 0xFFFFFFFF
        return ((a << n) | (a >> (32 - n))) & 0xFFFFFFFF
    end

    -- 32-bit rotate right
    M.ror = function(a, n)
        n = n % 32
        a = a & 0xFFFFFFFF
        return ((a >> n) | (a << (32 - n))) & 0xFFFFFFFF
    end

    M.tobit = function(a)
        return a & 0xFFFFFFFF
    end

    M.tohex = function(a, n)
        n = n or 8
        return string.format("%0" .. n .. "x", a & 0xFFFFFFFF)
    end
end

return M
