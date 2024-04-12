local base64_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

return function(data)
    local result = {}
    local length = #data
    local padding = length % 3
    for i = 1, length - 2, 3 do
        local triplet = string.byte(data, i) * 65536 + string.byte(data, i + 1) * 256 + string.byte(data, i + 2)
        for j = 1, 4 do
            local char_index = math.floor(triplet / (2 ^ (6 * (4 - j)))) % 64 + 1
            result[#result + 1] = base64_chars:sub(char_index, char_index)
        end
    end
    if padding == 1 then
        local value = string.byte(data, length)
        result[#result + 1] = base64_chars:sub(math.floor(value / 4) + 1, math.floor(value / 4) + 1)
        result[#result + 1] = base64_chars:sub(((value % 4) * 16) + 1, ((value % 4) * 16) + 1)
        result[#result + 1] = '=='
    elseif padding == 2 then
        local value1 = string.byte(data, length - 1)
        local value2 = string.byte(data, length)
        result[#result + 1] = base64_chars:sub(math.floor(value1 / 4) + 1, math.floor(value1 / 4) + 1)
        result[#result + 1] = base64_chars:sub((((value1 % 4) * 16) + math.floor(value2 / 16)) + 1, (((value1 % 4) * 16) + math.floor(value2 / 16)) + 1)
        result[#result + 1] = base64_chars:sub(((value2 % 16) * 4) + 1, ((value2 % 16) * 4) + 1)
        result[#result + 1] = '='
    end
    return table.concat(result)
end

