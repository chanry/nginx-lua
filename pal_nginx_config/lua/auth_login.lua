local auth_module = require("auth_adapter");
local Logger = require("Logger");
local Redis = require("Redis");
local cjson = require("cjson.safe");
local cookie_value_pre = 'MOD_AMP_';
local redis_client;


------------- 校验登陆 --------------
-- @return  has_login, login_user
local function verify_login()
    local has_login = false;
    local login_user;
    local cookie_user_token = ngx.var.cookie_MOD_AMP_AUTH;
    if cookie_user_token ~= nil then
        Logger.debug("cookie_user_token: " .. cookie_user_token);
        login_user = Redis.get(redis_client, cookie_user_token);

        if login_user == ngx.null or login_user == nil then
            login_user = nil;
            has_login = false;
        else
            has_login = true;
        end
    else
        has_login = false;
    end
    return has_login, login_user;
end

------------- 设置登陆用户至请求头header中 --------------
-- @args    user_id, user_cname, logout_url
local function set_user_to_header(user_id, user_cname, logout_url)
    if user_id then
        ngx.req.set_header("CAS_USER", user_id);
    end
    if user_cname then
        ngx.req.set_header("CAS_USER_CN", user_cname);
    end
    if logout_url then
        ngx.req.set_header("ATTR_CAS_LOGOUT_URL", logout_url);
    end
end


-------------- process ---------------
--  step 1: check user_token_cookie, if exists step 2
--  step 2: start auth_module.auth(), if login return userInfo
--  step 3: set_user_to_header
local function verify()
    redis_client = Redis.get_client();
    Redis.connect(redis_client);

    --	logoutSessionKey
    -- 	单点退出特殊处理
    if ngx.var.arg_logoutSessionKey ~= nil then
        local cookie_value = cookie_value_pre .. ngx.var.arg_logoutSessionKey;
        Logger.debug("==================== find logoutSessionKey, single logout ====================");
        Logger.debug("logoutSessionKey: " .. cookie_value);
        local user_info = Redis.get(redis_client, cookie_value);
        if(user_info ~= nil) then
            Redis.remove(redis_client, cookie_value);
        end
    end

    local user_id, user_name, logout_url;

    Logger.debug("verify login...");
    local has_login, login_user = verify_login();
    if has_login then
        local user_table = cjson.decode(login_user);
        user_id = user_table["user_id"];
        user_name = user_table["user_name"];
    else
        Logger.debug("no login, exec auth_adapter.auth ...");
        auth_module.auth();
    end

    Redis.close(redis_client);
    set_user_to_header(user_id, user_name, logout_url);
end


return {
    verify = verify
}