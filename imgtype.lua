local sniff_len = 512
local sniff_signatures = {
    [string.char(0) .. string.char(0) .. string.char(1) .. string.char(0)] = 'image/x-icon',
    [string.char(0) .. string.char(0) .. string.char(2) .. string.char(0)] = 'image/x-icon',
    ['BM'] = 'image/bmp',
    ['GIF87a'] = 'image/gif',
    ['GIF89a'] = 'image/gif',
    [string.char(137) .. 'PNG' .. string.char(13) .. string.char(10) .. string.char(26) .. string.char(10)] = 'image/png',
    [string.char(255) .. string.char(216) .. string.char(255)] = 'image/jpeg'
}
local image_type = {
    ['image/x-icon'] = 'x-icon',
    ['image/bmp'] = 'bmp',
    ['image/gif'] = 'gif',
    ['image/png'] = 'png',
    ['image/jpeg'] = 'jpeg'
}

local function is_WS(b)
    -- if b == '\t' or b == '\n' or b == '\x0c' or b == '\r' or b == ' ' then
    if b == 9 or b == 10 or b == 12 or b == 13 or b == 32 then
        return true
    end
    return false
end

local function startswith(text, prefix)
    return text:find(prefix, 1, true) == 1
end

local function match(sig, data, first_non_WS)
    if startswith(data, sig) then
        return sniff_signatures[sig]
    end
    return ''
end

local function detect_content_type(data)
    if #data > sniff_len then
        data = data:sub(1, sniff_len)
    end

    local first_non_WS = 0
    repeat
        first_non_WS = first_non_WS + 1
    until first_non_WS > #data or is_WS(data:byte(first_non_WS))

    for sig, ct in pairs(sniff_signatures) do
        ct = match(sig, data, first_non_WS)
        if ct ~= '' then
            return ct
        end
    end
    return 'application/octet-stream' -- fallback
end
local _M = {}

function _M.get_type_by_path(p)
    local file = io.open(p, 'rb')
    if not file then
        error("Can not open file")
    end
    local data = file:read('*a')
    file:close()
    return _M.get_type(data)
end

function _M.get_type(file_stream)
    local mime_type = detect_content_type(file_stream)
    local type = image_type[mime_type]
    if type then
        return type
    end
    return 'unknown'
end
return _M
