local response = require "resty.kafka.response"
local request = require "resty.kafka.request"
local bxor = bit.bxor

local to_int32 = response.to_int32
local pid = ngx.worker.pid

local _M = {}
local mt = { __index = _M }

local MECHANISM_PLAINTEXT = "PLAIN"
local MECHANISM_SCRAMSHA256 = "SCRAM-SHA-256"
local SEP = string.char(0)


local function _encode_plaintext(authz_id, user, pwd)
    local msg = ""
    if authz_id then
        msg = msg ..authz_id
    end

    return (authz_id or "") .. SEP .. user .. SEP .. pwd
end

local function _encode(mechanism,authz_id, user, pwd)
    if mechanism == MECHANISM_PLAINTEXT then
        return _encode_plaintext(authz_id, user, pwd)
    end

    return ""
end

-- TODO: Duplicate function in broker.lua
local function _sock_send_receive(sock, request)
    local bytes, err = sock:send(request:package())
    if not bytes then
        return nil, err, true
    end

    -- Reading a 4 byte `message_size`
    local len, err = sock:receive(4)

    if not len then
        if err == "timeout" then
            sock:close()
            return nil, err
        end
        return nil, err, true
    end

    local data, err = sock:receive(to_int32(len))
    if not data then
        if err == "timeout" then
            sock:close()
            return nil, err, true
        end
    end

    return response:new(data, request.api_version), nil, true
end

local function _sasl_handshake_decode(resp)
    -- TODO: contains mechanisms supported by the local server
    -- read this like I did with the supported api versions thing
    local err_code =  resp:int16()
    local mechanisms =  resp:string()
    if err_code ~= 0 then
        return err_code, mechanisms
    end
    return 0, nil
end


local function _sock_send_recieve(sock, request)
    local bytes, err = sock:send(request:package())
    if not bytes then
        return nil, err, true
    end

    local len, err = sock:receive(4)
    if not len then
        if err == "timeout" then
            -- ngx_log(ERR, "socket timeout.")
            sock:close()
            return nil, err
        end
        return nil, err, true
    end

    local data, err = sock:receive(to_int32(len))
    if not data then
        if err == "timeout" then
            -- ngx_log(ERR, "socket timeout..")
            sock:close()
            return nil, err
        end
        return nil, err, true
    end

    return response:new(data, request.api_version), nil, true
end


local function _sasl_auth(self, sock)
    local cli_id = "worker" .. pid()
    local req = request:new(request.SaslAuthenticateRequest, 0, cli_id,
                            request.API_VERSION_V1)

    local msg = _encode(self.config.mechanism, nil, self.config.user,
    self.config.password)

    req:bytes(msg)

    local resp, err = _sock_send_recieve(sock, req)
    if not resp  then
        return nil, err
    end

    local err_code = resp:int16()
    local error_msg = resp:string()
    local auth_bytes = resp:bytes()

    if err_code ~= 0 then
        return nil, error_msg
    end

    return 0, nil 
end


local function _sasl_handshake(self, sock)
    local cli_id = "worker" .. pid()
    local api_version = request.API_VERSION_V1

    local req = request:new(request.SaslHandshakeRequest, 0, cli_id, api_version)
    local mechanism = self.config.mechanism
    req:string(mechanism)
    local resp, err = _sock_send_receive(sock, req)
    if not resp  then
        return nil, err
    end
    local rc, mechanism = _sasl_handshake_decode(resp)
    -- the presence of mechanisms indicate that the mechanism used isn't enabled on the Kafka server.
    if mechanism then
        return nil, mechanism
    end
    return rc, nil
end


function _M.new(opts)
    local self = {
        config = opts
    }

    return setmetatable(self, mt)
end

function _M:authenticate(sock)
    local ok, err = _sasl_handshake(self, sock)
    if not ok then
        if err then
            return nil, err
        end
        return nil, "Unkown Error"
    end

    local ok, err = _sasl_auth(self, sock)
    if not ok then
        return nil, err
    end
    return 0, nil
end

return _M
