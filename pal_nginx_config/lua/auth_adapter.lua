local Common = require("Common");
local Config = require("Config");
local Logger = require("Logger");
local Redis = require("Redis");
local cjson = require("cjson");
local redis_client;
local source_url, redirect_url;
local cookie_value_pre = 'MOD_AMP_';
local authserver_login_url;
local authserver_logout_url;
local validate_url_prefix;
local proxy_validate_url;

----------------- function init -------------------
-- 主要任务：构造两种不同的URL 一个是authserver_login_url 用于跳转到 login 登陆界面
-- 如http://authserver.wisedu.com/authserver/login?service=http%3A%2F%2Fdemo.wisedu.com%2Famp-deploy-local%2Flogin%3Fservice%3Dhttp%3A%2F%2Fdemo.wisedu.com%2Famp-deploy-local%2Findex.html
-- 另一个是 validate_url 专用于校验ticket的时候使用
local function init()
    Logger.debug("init cas config");
    local auth_server_url_prefix = Config.get("ids_domain_schema") .. '://' .. Config.get("ids_domain");
    local validate_url_prefix;

    validate_url_prefix = Config.get("ids_domain_schema") .. '/' .. Config.get("ids_domain");

    if (Config.get("ids_domain_port") == nil or Config.get("ids_domain_port") == '80') then
        validate_url_prefix = '/proxy/' .. validate_url_prefix;
    else
        auth_server_url_prefix = auth_server_url_prefix .. ':' .. Config.get("ids_domain_port");
        validate_url_prefix = '/proxywithport/' .. validate_url_prefix .. '/' .. Config.get("ids_domain_port");
    end

    if (Config.get("ids_domain_context") ~= nil) then
        auth_server_url_prefix = auth_server_url_prefix .. '/' .. Config.get("ids_domain_context");
        validate_url_prefix = validate_url_prefix .. '/' .. Config.get("ids_domain_context");
    end

    authserver_login_url = auth_server_url_prefix .. '/login?service=';
    authserver_logout_url = auth_server_url_prefix .. '/logout?service=';
    validate_url = validate_url_prefix .. '/serviceValidate';
    proxy_validate_url = validate_url_prefix .. '/proxyValidate';
end

-------------------------------------------------------
local function redirect_login(url)
    Common.remove_session_cookie();
    Logger.debug("==================== redirect_login ====================");
    local r_url = authserver_login_url .. ngx.escape_uri(url);
    Logger.info('the redirect url is:' .. r_url);
    Common.redirect(r_url, 302, redis_client);
end

----------------- function start -----------------
function get_source_and_redirect_url()
    local source_url;
    local redirect_url;
    local url_port = ngx.var.server_port;

    if url_port == '80' then
        source_url = ngx.var.scheme .. "://" .. ngx.var.host .. ngx.var.request_uri;
        redirect_url = ngx.var.scheme .. "://" .. ngx.var.host .. ngx.var.uri;
    else
        source_url = ngx.var.scheme .. "://" .. ngx.var.host .. ":" .. ngx.var.server_port .. ngx.var.request_uri;
        redirect_url = ngx.var.scheme .. "://" .. ngx.var.host .. ":" .. ngx.var.server_port .. ngx.var.uri;
    end
    if ngx.req.get_uri_args() ~= nil then
        redirect_url = redirect_url .. "?";
        for index, str in pairs(ngx.req.get_uri_args()) do
            if type(str) == "string" and index ~= "ticket" then
                redirect_url = redirect_url .. index .. "=" .. str .. "&";
            end
        end
        redirect_url = string.sub(redirect_url, 0, string.len(redirect_url) - 1);
    end

    return source_url, redirect_url;
end

----------------------- function handle_json_response ------------------
local function handle_json_response(response_body)
    Logger.info("==================== get response from authserver: " .. response_body .. "====================");

    -- 校验是否为失败
    local i, j = string.find(response_body, 'authenticationFailure', 1);
    if (i ~= nil) then
        Logger.error("authenticationFailure，go to login page " .. response_body);
        redirect_login(redirect_url);
    end

    local resp_data = cjson.decode(response_body);
    if resp_data == nil then
        Logger.error("response error " .. response_body);
        redirect_login(source_url);
    end

    local table_data = {};
    Common.table_handle(resp_data, table_data);
    local user_id_key = Config.get("user_id_key");
    local user_name_key = Config.get("user_name_key");

    table_data['remoteAddr'] = ngx.var.remote_addr;
    table_data['sourceUrl'] = ngx.escape_uri(source_url);
    table_data['user_id'] = table_data[user_id_key];
    table_data['user_name'] = table_data[user_name_key];

    --create cookie,store in redis
    local cookie_value = cookie_value_pre .. ngx.var.arg_ticket;
    local session_value = cjson.encode(table_data);

    Redis.set(redis_client, cookie_value, session_value, 3600);
    Common.set_session_cookie(cookie_value);
end


local function verify_ticket()
    if ngx.var.arg_ticket then
        Logger.debug("==================== find ticket: " .. ngx.var.arg_ticket .. "====================");
        Common.remove_session();
        local verify_ticket_url = validate_url .. '?RETURN_TYPE=JSON&ticket=' .. ngx.var.arg_ticket .. '&service=' .. ngx.escape_uri(redirect_url);
        Logger.debug("verify ticket through url: " .. verify_ticket_url);
        local response = ngx.location.capture(verify_ticket_url);
        if response.status == 200 then
            handle_json_response(response.body);
            Logger.debug("redirect_url: " .. redirect_url);
            Common.redirect(redirect_url, 302, redis_client);
        else
            Logger.error("validate ticket error: code=" .. response.status .. ", response=" .. response.body);
            Common.response_content("validate ticket error: code=" .. response.status .. ", response=" .. response.body);
        end
    else
        Logger.info("no ticket found, redirect login page ");
        redirect_login(source_url);
    end
end

--- step1：初始化authserver的登入、登出、ticket校验地址
--- step2：初始化请求地址
--- step3：校验ticket，有ticket则 goto step4， 无 goto step5
--- step4：根据ticket到authserver去校验并获取用户信息存储到redis中，再次重定向到最初的请求地址
--- step5：重定向到authserver去登录
local function auth()
    redis_client = Redis.get_client();
    Redis.connect(redis_client);
    init();
    source_url, redirect_url = get_source_and_redirect_url();
    Logger.debug("==================== verify ticket ====================");
    verify_ticket();
    Redis.close(redis_client);
end


return {
    auth = auth
}