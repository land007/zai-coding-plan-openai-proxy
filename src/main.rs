use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Verifier;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const GLOBAL_BASE_URL: &str = "https://api.z.ai/api/coding/paas/v4";
const CN_BASE_URL: &str = "https://open.bigmodel.cn/api/coding/paas/v4";
const JSON_CONTENT_TYPE: &str = "application/json; charset=utf-8";
const LICENSE_TOKEN_HEADER: &str = "x-webclaw-license-token";
const USAGE_MODE_HEADER: &str = "x-webclaw-usage-mode";
const LICENSE_TOKEN_ISSUER: &str = "webclaw-platform";
const DEFAULT_FREE_LOGIN_TOTAL_TOKENS: u64 = 200_000;
const DEFAULT_USAGE_STORE_PATH: &str = "./data/free-usage.jsonl";
const DEFAULT_PAID_USAGE_STORE_PATH: &str = "./data/paid-usage.jsonl";
const DEFAULT_PAID_BALANCE_STORE_PATH: &str = "./data/paid-balances.json";
const DEFAULT_PAID_GRANT_STORE_PATH: &str = "./data/paid-grants.jsonl";
const DEFAULT_USER_EMAILS_STORE_PATH: &str = "./data/user-emails.json";
const AUTH_CALLBACK_PUBLIC_KEY_PEM: &str = include_str!("../auth-callback-public.pem");

#[derive(Clone)]
struct AppConfig {
    host: String,
    port: u16,
    proxy_api_key: Option<String>,
    zai_api_key: String,
    upstream_base_url: String,
    allowed_models: Vec<ModelAlias>,
    allow_anonymous: bool,
    free_login_total_tokens: u64,
    usage_store_path: PathBuf,
    paid_usage_store_path: PathBuf,
    paid_balance_store_path: PathBuf,
    paid_grant_store_path: PathBuf,
    user_emails_store_path: PathBuf,
    internal_api_key: Option<String>,
}

#[derive(Clone)]
struct ModelAlias {
    public_id: &'static str,
    upstream_id: &'static str,
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

struct CurlResponse {
    status_code: u16,
    content_type: Option<String>,
    body: Vec<u8>,
    usage: Option<RequestUsage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UsageRecord {
    ts: u64,
    user_id: u64,
    email: String,
    total_tokens: u64,
    input_tokens: u64,
    output_tokens: u64,
    model: String,
    stream: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PaidGrantRecord {
    ts: u64,
    user_id: u64,
    email: String,
    order_no: String,
    product_type: String,
    granted_tokens: u64,
    balance_after: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct GrantTokensRequest {
    user_id: u64,
    email: String,
    order_no: String,
    product_type: String,
    tokens: u64,
}

#[derive(Debug, Clone)]
struct RequestUsage {
    total_tokens: u64,
    input_tokens: u64,
    output_tokens: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UsageMode {
    FreeTrial,
    PaidBalance,
}

#[derive(Debug, Clone)]
enum AuthContext {
    Anonymous,
    ProxyKey,
    ApiToken(u64),
    Login(LoginTokenClaims),
}

#[derive(Debug, Clone, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct LoginTokenClaims {
    #[serde(rename = "userId")]
    user_id: u64,
    email: String,
    #[serde(rename = "proStatus")]
    pro_status: bool,
    exp: u64,
    #[serde(default)]
    iat: Option<u64>,
    #[serde(default)]
    iss: Option<String>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("fatal: {err}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let cfg = Arc::new(load_config()?);
    let listener = TcpListener::bind(format!("{}:{}", cfg.host, cfg.port))?;
    eprintln!(
        "zai-coding-plan-openai-proxy listening on http://{}:{}",
        cfg.host, cfg.port
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let cfg = Arc::clone(&cfg);
                thread::spawn(move || {
                    if let Err(err) = handle_client(stream, cfg) {
                        eprintln!("request error: {err}");
                    }
                });
            }
            Err(err) => eprintln!("accept error: {err}"),
        }
    }

    Ok(())
}

fn load_config() -> io::Result<AppConfig> {
    let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = env::var("PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(8787);
    let proxy_api_key = env::var("PROXY_API_KEY")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let zai_api_key = env::var("ZAI_API_KEY")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "ZAI_API_KEY is required"))?;
    let endpoint = env::var("ZAI_CODING_PLAN_ENDPOINT").unwrap_or_else(|_| "global".to_string());
    let upstream_base_url = match endpoint.trim().to_ascii_lowercase().as_str() {
        "global" => GLOBAL_BASE_URL.to_string(),
        "cn" => CN_BASE_URL.to_string(),
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported ZAI_CODING_PLAN_ENDPOINT: {other}"),
            ));
        }
    };
    let allow_anonymous = env_bool("ALLOW_ANONYMOUS", false);
    let free_login_total_tokens = env::var("FREE_LOGIN_TOTAL_TOKENS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_FREE_LOGIN_TOTAL_TOKENS);
    let usage_store_path = env::var("FREE_USAGE_STORE_PATH")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_USAGE_STORE_PATH));
    let paid_usage_store_path = env::var("PAID_USAGE_STORE_PATH")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PAID_USAGE_STORE_PATH));
    let paid_balance_store_path = env::var("PAID_BALANCE_STORE_PATH")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PAID_BALANCE_STORE_PATH));
    let paid_grant_store_path = env::var("PAID_GRANT_STORE_PATH")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PAID_GRANT_STORE_PATH));
    let user_emails_store_path = env::var("USER_EMAILS_STORE_PATH")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_USER_EMAILS_STORE_PATH));
    let internal_api_key = env::var("INTERNAL_API_KEY")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());

    Ok(AppConfig {
        host,
        port,
        proxy_api_key,
        zai_api_key,
        upstream_base_url,
        allowed_models: allowed_models(),
        allow_anonymous,
        free_login_total_tokens,
        usage_store_path,
        paid_usage_store_path,
        paid_balance_store_path,
        paid_grant_store_path,
        user_emails_store_path,
        internal_api_key,
    })
}

fn allowed_models() -> Vec<ModelAlias> {
    vec![
        ModelAlias {
            public_id: "zai/glm-4.7",
            upstream_id: "glm-4.7",
        },
        ModelAlias {
            public_id: "zai/glm-4.7-flash",
            upstream_id: "glm-4.7-flash",
        },
        ModelAlias {
            public_id: "zai/glm-4.7-flashx",
            upstream_id: "glm-4.7-flashx",
        },
        ModelAlias {
            public_id: "zai/glm-5",
            upstream_id: "glm-5",
        },
        ModelAlias {
            public_id: "zai/glm-5-turbo",
            upstream_id: "glm-5-turbo",
        },
        ModelAlias {
            public_id: "zai-coding-plan/glm-5",
            upstream_id: "glm-5",
        },
        ModelAlias {
            public_id: "zai-coding-plan/glm-5-turbo",
            upstream_id: "glm-5-turbo",
        },
        ModelAlias {
            public_id: "zai-coding-plan/glm-4.7",
            upstream_id: "glm-4.7",
        },
        ModelAlias {
            public_id: "zai-coding-plan/glm-4.7-flash",
            upstream_id: "glm-4.7-flash",
        },
        ModelAlias {
            public_id: "zai-coding-plan/glm-4.7-flashx",
            upstream_id: "glm-4.7-flashx",
        },
    ]
}

fn handle_client(mut stream: TcpStream, cfg: Arc<AppConfig>) -> io::Result<()> {
    let peer = stream
        .peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let request = match read_request(&stream) {
        Ok(request) => request,
        Err(err) => {
            eprintln!("request parse error from {peer}: {err}");
            write_json_response(
                &mut stream,
                400,
                &json_error("invalid_request", &err.to_string()),
            )?;
            return Ok(());
        }
    };

    let path_only = request
        .path
        .split('?')
        .next()
        .unwrap_or(request.path.as_str());

    if matches!(
        (request.method.as_str(), path_only),
        ("GET", "/health")
            | ("OPTIONS", _)
            | ("GET", "/internal/user-usage")
            | ("POST", "/internal/grant-tokens")
            | ("POST", "/internal/sync-user")
    ) {
        let route_result: io::Result<()> = match (request.method.as_str(), path_only) {
            ("GET", "/health") => write_json_response(
                &mut stream,
                200,
                "{\"ok\":true,\"provider\":\"zai-coding-plan-openai-proxy\"}",
            ),
            ("GET", "/internal/user-usage") => handle_internal_user_usage(&mut stream, &cfg, &request),
            ("POST", "/internal/grant-tokens") => handle_internal_grant_tokens(&mut stream, &cfg, &request),
            ("POST", "/internal/sync-user") => handle_internal_sync_user(&mut stream, &cfg, &request),
            ("OPTIONS", _) => write_empty_response(&mut stream, 204),
            _ => Ok(()),
        };

        if let Err(err) = route_result {
            log_route_error(&peer, &err);
            let _ = write_route_error_response(&mut stream, &err);
        }

        return Ok(());
    }

    let auth = match authorize(&request, &cfg) {
        Ok(auth) => auth,
        Err(err) => {
            eprintln!("request unauthorized from {peer}: path={} error={err}", request.path);
            write_json_response(&mut stream, 401, &json_error("unauthorized", &err))?;
            return Ok(());
        }
    };

    eprintln!(
        "request from {peer}: method={} path={} auth={} content-length={}",
        request.method,
        request.path,
        auth_label(&auth),
        request.body.len()
    );

    let route_result: io::Result<()> = match (request.method.as_str(), path_only) {
        ("GET", "/v1/models") => write_json_response(&mut stream, 200, &build_models_payload(&cfg)),
        ("GET", "/v1/usage") => handle_get_usage(&mut stream, &cfg, &auth, &request),
        ("GET", path) if path.starts_with("/v1/models/") => {
            handle_get_model(&mut stream, &cfg, path.trim_start_matches("/v1/models/"))
        }
        ("POST", "/v1/chat/completions") => {
            handle_chat_completions(&mut stream, &cfg, &request, &auth)
        }
        ("POST", "/api/anthropic/v1/messages") => {
            handle_anthropic_messages(&mut stream, &cfg, &request, &auth)
        }
        _ => write_json_response(
            &mut stream,
            404,
            &json_error("not_found", "route not found"),
        ),
    };

    if let Err(err) = route_result {
        log_route_error(&peer, &err);
        let _ = write_route_error_response(&mut stream, &err);
    }

    Ok(())
}

fn handle_internal_user_usage(
    stream: &mut TcpStream,
    cfg: &AppConfig,
    request: &HttpRequest,
) -> io::Result<()> {
    if let Err(err) = authorize_internal(request, cfg) {
        let status = if err.kind() == io::ErrorKind::PermissionDenied { 403 } else { 500 };
        return write_json_response(stream, status, &json_error("internal_auth_failed", &err.to_string()));
    }
    let Some(user_id) = request_query_param(&request.path, "user_id")
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|value| *value > 0) else {
        return write_json_response(stream, 400, &json_error("invalid_user_id", "user_id is required"));
    };
    let free_used_tokens = load_user_consumed_tokens(&cfg.usage_store_path, user_id)?;
    let (free_last_24h_tokens, free_last_24h_requests) =
        load_user_consumed_tokens_last_24h(&cfg.usage_store_path, user_id)?;
    let paid_tokens_purchased = load_user_purchased_tokens(&cfg.paid_balance_store_path, user_id)?;
    let paid_tokens_used = load_user_consumed_tokens(&cfg.paid_usage_store_path, user_id)?;
    let (paid_last_24h_tokens, paid_last_24h_requests) =
        load_user_consumed_tokens_last_24h(&cfg.paid_usage_store_path, user_id)?;
    let paid_tokens_remaining = paid_tokens_purchased.saturating_sub(paid_tokens_used);
    let payload = serde_json::json!({
        "user_id": user_id,
        "free_login_total_tokens": cfg.free_login_total_tokens,
        "free_tokens_used": free_used_tokens,
        "free_tokens_remaining": cfg.free_login_total_tokens.saturating_sub(free_used_tokens),
        "free_last_24h_tokens": free_last_24h_tokens,
        "free_last_24h_requests": free_last_24h_requests,
        "paid_tokens_purchased": paid_tokens_purchased,
        "paid_tokens_used": paid_tokens_used,
        "paid_tokens_remaining": paid_tokens_remaining,
        "paid_last_24h_tokens": paid_last_24h_tokens,
        "paid_last_24h_requests": paid_last_24h_requests,
    });
    write_json_response(stream, 200, &payload.to_string())
}

fn handle_internal_grant_tokens(
    stream: &mut TcpStream,
    cfg: &AppConfig,
    request: &HttpRequest,
) -> io::Result<()> {
    if let Err(err) = authorize_internal(request, cfg) {
        let status = if err.kind() == io::ErrorKind::PermissionDenied { 403 } else { 500 };
        return write_json_response(stream, status, &json_error("internal_auth_failed", &err.to_string()));
    }
    let body = String::from_utf8(request.body.clone())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "request body must be utf-8 json"))?;
    let payload = serde_json::from_str::<GrantTokensRequest>(&body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid json body: {e}")))?;
    if payload.user_id == 0 {
        return write_json_response(stream, 400, &json_error("invalid_user_id", "user_id must be greater than 0"));
    }
    if payload.tokens == 0 {
        return write_json_response(stream, 400, &json_error("invalid_tokens", "tokens must be greater than 0"));
    }
    if payload.order_no.trim().is_empty() {
        return write_json_response(stream, 400, &json_error("invalid_order_no", "order_no is required"));
    }
    if payload.email.trim().is_empty() {
        return write_json_response(stream, 400, &json_error("invalid_email", "email is required"));
    }

    if let Some(existing) = find_grant_record_by_order_no(&cfg.paid_grant_store_path, payload.order_no.trim())? {
        let response = serde_json::json!({
            "ok": true,
            "already_granted": true,
            "user_id": existing.user_id,
            "order_no": existing.order_no,
            "granted_tokens": existing.granted_tokens,
            "balance_after": existing.balance_after,
        });
        return write_json_response(stream, 200, &response.to_string());
    }

    let balance_after = add_paid_tokens(
        &cfg.paid_balance_store_path,
        payload.user_id,
        payload.tokens,
    )?;
    let record = PaidGrantRecord {
        ts: now_ms(),
        user_id: payload.user_id,
        email: payload.email.trim().to_string(),
        order_no: payload.order_no.trim().to_string(),
        product_type: payload.product_type.trim().to_string(),
        granted_tokens: payload.tokens,
        balance_after,
    };
    append_paid_grant_record(&cfg.paid_grant_store_path, &record)?;
    let response = serde_json::json!({
        "ok": true,
        "already_granted": false,
        "user_id": record.user_id,
        "order_no": record.order_no,
        "granted_tokens": record.granted_tokens,
        "balance_after": record.balance_after,
    });
    write_json_response(stream, 200, &response.to_string())
}

#[derive(Debug, Clone, Deserialize)]
struct SyncUserRequest {
    user_id: u64,
    email: String,
}

fn handle_internal_sync_user(
    stream: &mut TcpStream,
    cfg: &AppConfig,
    request: &HttpRequest,
) -> io::Result<()> {
    if let Err(err) = authorize_internal(request, cfg) {
        let status = if err.kind() == io::ErrorKind::PermissionDenied { 403 } else { 500 };
        return write_json_response(stream, status, &json_error("internal_auth_failed", &err.to_string()));
    }
    let body = String::from_utf8(request.body.clone())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "request body must be utf-8 json"))?;
    let payload = serde_json::from_str::<SyncUserRequest>(&body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid json body: {e}")))?;
    if payload.user_id == 0 {
        return write_json_response(stream, 400, &json_error("invalid_user_id", "user_id must be greater than 0"));
    }
    if payload.email.trim().is_empty() {
        return write_json_response(stream, 400, &json_error("invalid_email", "email is required"));
    }

    sync_user_email(&cfg.user_emails_store_path, payload.user_id, &payload.email.trim())?;

    let response = serde_json::json!({
        "ok": true,
        "user_id": payload.user_id,
        "email": payload.email.trim(),
    });
    write_json_response(stream, 200, &response.to_string())
}

fn read_request(stream: &TcpStream) -> io::Result<HttpRequest> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    if request_line.trim().is_empty() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "empty request"));
    }

    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing path"))?
        .to_string();

    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let content_length = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let body = if headers
        .get("transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        read_chunked_body(&mut reader)?
    } else {
        let mut body = vec![0_u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut body)?;
        }
        body
    };

    Ok(HttpRequest {
        method,
        path,
        headers,
        body,
    })
}

fn authorize(request: &HttpRequest, cfg: &AppConfig) -> Result<AuthContext, String> {
    if let Some(header) = request.headers.get("authorization") {
        if let Some(token) = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
        {
            // 检查是否是 WebClaw API Key
            if let Some(user_id) = extract_user_id_from_api_key(token.trim()) {
                return Ok(AuthContext::ApiToken(user_id));
            }

            // 检查 PROXY_API_KEY
            if let Some(expected) = cfg.proxy_api_key.as_ref() {
                if token.trim() == expected {
                    return Ok(AuthContext::ProxyKey);
                }
            }
        }
    }

    if let Some(token) = request.headers.get(LICENSE_TOKEN_HEADER) {
        let claims = verify_login_token(token.trim())?;
        return Ok(AuthContext::Login(claims));
    }

    if cfg.allow_anonymous {
        return Ok(AuthContext::Anonymous);
    }

    Err("missing api key, proxy key, or valid login token".to_string())
}

fn extract_user_id_from_api_key(key: &str) -> Option<u64> {
    let key = key.trim();
    if !key.starts_with("sk-webclaw-") {
        return None;
    }

    // 解析：sk-webclaw-{userId}-{xxx}
    let parts: Vec<&str> = key.split('-').collect();
    if parts.len() < 3 {
        return None;
    }

    // 提取 userId（第3部分）
    parts.get(2)?.parse::<u64>().ok()
}

fn auth_label(auth: &AuthContext) -> &'static str {
    match auth {
        AuthContext::Anonymous => "anonymous",
        AuthContext::ProxyKey => "proxy-key",
        AuthContext::ApiToken(_) => "api-token",
        AuthContext::Login(_) => "login-token",
    }
}

fn authorize_internal(request: &HttpRequest, cfg: &AppConfig) -> io::Result<()> {
    let Some(expected) = cfg.internal_api_key.as_ref() else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "INTERNAL_API_KEY is not configured",
        ));
    };
    let Some(header) = request.headers.get("authorization") else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "missing authorization header",
        ));
    };
    let provided = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))
        .map(str::trim)
        .unwrap_or("");
    if provided != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid internal api key",
        ));
    }
    Ok(())
}

fn handle_get_model(stream: &mut TcpStream, cfg: &AppConfig, encoded_id: &str) -> io::Result<()> {
    let model_id = percent_decode(encoded_id);
    let Some(model) = cfg.allowed_models.iter().find(|entry| entry.public_id == model_id) else {
        return write_json_response(
            stream,
            404,
            &json_error("model_not_found", "model not found"),
        );
    };
    let payload = format!(
        "{{\"id\":\"{}\",\"object\":\"model\",\"created\":0,\"owned_by\":\"zai-coding-plan-proxy\"}}",
        escape_json(model.public_id)
    );
    write_json_response(stream, 200, &payload)
}

fn handle_get_usage(
    stream: &mut TcpStream,
    cfg: &AppConfig,
    auth: &AuthContext,
    request: &HttpRequest,
) -> io::Result<()> {
    let requested_mode = requested_usage_mode_from_headers(&request.headers).unwrap_or(UsageMode::FreeTrial);
    let payload = match auth {
        AuthContext::ProxyKey => serde_json::json!({
            "auth_mode": "proxy_key",
            "current_source": "proxy_key",
            "is_paid": true,
            "is_unlimited": true,
            "usage_mode_requested": usage_mode_label(requested_mode),
            "free_login_total_tokens": cfg.free_login_total_tokens,
            "free_tokens_used": 0u64,
            "free_tokens_remaining": serde_json::Value::Null,
            "paid_tokens_purchased": serde_json::Value::Null,
            "paid_tokens_used": 0u64,
            "paid_tokens_remaining": serde_json::Value::Null,
            "used_tokens": 0u64,
            "remaining_tokens": serde_json::Value::Null,
            "message": "proxy api key is not quota-limited by free login allowance"
        }),
        AuthContext::Anonymous => serde_json::json!({
            "auth_mode": "anonymous",
            "current_source": "anonymous",
            "is_paid": false,
            "is_unlimited": cfg.allow_anonymous,
            "usage_mode_requested": usage_mode_label(requested_mode),
            "free_login_total_tokens": cfg.free_login_total_tokens,
            "free_tokens_used": 0u64,
            "free_tokens_remaining": serde_json::Value::Null,
            "paid_tokens_purchased": serde_json::Value::Null,
            "paid_tokens_used": 0u64,
            "paid_tokens_remaining": serde_json::Value::Null,
            "used_tokens": 0u64,
            "remaining_tokens": serde_json::Value::Null,
            "message": "anonymous access is enabled"
        }),
        AuthContext::Login(claims) => {
            let free_used_tokens = load_user_consumed_tokens(&cfg.usage_store_path, claims.user_id)?;
            let (free_last_24h_tokens, free_last_24h_requests) =
                load_user_consumed_tokens_last_24h(&cfg.usage_store_path, claims.user_id)?;
            let free_remaining_tokens = Some(cfg.free_login_total_tokens.saturating_sub(free_used_tokens));
            let paid_tokens_purchased = load_user_purchased_tokens(&cfg.paid_balance_store_path, claims.user_id)?;
            let paid_tokens_used = load_user_consumed_tokens(&cfg.paid_usage_store_path, claims.user_id)?;
            let (paid_last_24h_tokens, paid_last_24h_requests) =
                load_user_consumed_tokens_last_24h(&cfg.paid_usage_store_path, claims.user_id)?;
            let paid_tokens_remaining = Some(paid_tokens_purchased.saturating_sub(paid_tokens_used));
            let current_source = match requested_mode {
                UsageMode::PaidBalance => "paid_balance",
                UsageMode::FreeTrial => "free_trial",
            };
            let remaining_tokens = match requested_mode {
                UsageMode::PaidBalance => paid_tokens_remaining,
                UsageMode::FreeTrial => free_remaining_tokens,
            };
            let last_24h_tokens = match requested_mode {
                UsageMode::PaidBalance => paid_last_24h_tokens,
                UsageMode::FreeTrial => free_last_24h_tokens,
            };
            let last_24h_requests = match requested_mode {
                UsageMode::PaidBalance => paid_last_24h_requests,
                UsageMode::FreeTrial => free_last_24h_requests,
            };
            serde_json::json!({
                "auth_mode": "login_token",
                "user_id": claims.user_id,
                "email": claims.email,
                "is_paid": claims.pro_status || paid_tokens_purchased > 0,
                "is_unlimited": false,
                "usage_mode_requested": usage_mode_label(requested_mode),
                "current_source": current_source,
                "free_login_total_tokens": cfg.free_login_total_tokens,
                "free_tokens_used": free_used_tokens,
                "free_tokens_remaining": free_remaining_tokens,
                "free_last_24h_tokens": free_last_24h_tokens,
                "free_last_24h_requests": free_last_24h_requests,
                "paid_tokens_purchased": paid_tokens_purchased,
                "paid_tokens_used": paid_tokens_used,
                "paid_tokens_remaining": paid_tokens_remaining,
                "paid_last_24h_tokens": paid_last_24h_tokens,
                "paid_last_24h_requests": paid_last_24h_requests,
                "used_tokens": match requested_mode {
                    UsageMode::PaidBalance => paid_tokens_used,
                    UsageMode::FreeTrial => free_used_tokens,
                },
                "remaining_tokens": remaining_tokens,
                "last_24h_tokens": last_24h_tokens,
                "last_24h_requests": last_24h_requests,
                "message": match requested_mode {
                    UsageMode::PaidBalance => "paid balance mode uses purchased tokens",
                    UsageMode::FreeTrial => "free trial mode uses gifted tokens",
                }
            })
        }
        AuthContext::ApiToken(user_id) => {
            let email = get_user_email(&cfg.user_emails_store_path, *user_id)?;
            let free_used_tokens = load_user_consumed_tokens(&cfg.usage_store_path, *user_id)?;
            let (free_last_24h_tokens, free_last_24h_requests) =
                load_user_consumed_tokens_last_24h(&cfg.usage_store_path, *user_id)?;
            let free_remaining_tokens = Some(cfg.free_login_total_tokens.saturating_sub(free_used_tokens));
            let paid_tokens_purchased = load_user_purchased_tokens(&cfg.paid_balance_store_path, *user_id)?;
            let paid_tokens_used = load_user_consumed_tokens(&cfg.paid_usage_store_path, *user_id)?;
            let (paid_last_24h_tokens, paid_last_24h_requests) =
                load_user_consumed_tokens_last_24h(&cfg.paid_usage_store_path, *user_id)?;
            let paid_tokens_remaining = Some(paid_tokens_purchased.saturating_sub(paid_tokens_used));
            let current_source = match requested_mode {
                UsageMode::PaidBalance => "paid_balance",
                UsageMode::FreeTrial => "free_trial",
            };
            let remaining_tokens = match requested_mode {
                UsageMode::PaidBalance => paid_tokens_remaining,
                UsageMode::FreeTrial => free_remaining_tokens,
            };
            let last_24h_tokens = match requested_mode {
                UsageMode::PaidBalance => paid_last_24h_tokens,
                UsageMode::FreeTrial => free_last_24h_tokens,
            };
            let last_24h_requests = match requested_mode {
                UsageMode::PaidBalance => paid_last_24h_requests,
                UsageMode::FreeTrial => free_last_24h_requests,
            };
            serde_json::json!({
                "auth_mode": "api_token",
                "user_id": user_id,
                "email": email,
                "is_paid": paid_tokens_purchased > 0,
                "is_unlimited": false,
                "usage_mode_requested": usage_mode_label(requested_mode),
                "current_source": current_source,
                "free_login_total_tokens": cfg.free_login_total_tokens,
                "free_tokens_used": free_used_tokens,
                "free_tokens_remaining": free_remaining_tokens,
                "free_last_24h_tokens": free_last_24h_tokens,
                "free_last_24h_requests": free_last_24h_requests,
                "paid_tokens_purchased": paid_tokens_purchased,
                "paid_tokens_used": paid_tokens_used,
                "paid_tokens_remaining": paid_tokens_remaining,
                "paid_last_24h_tokens": paid_last_24h_tokens,
                "paid_last_24h_requests": paid_last_24h_requests,
                "used_tokens": match requested_mode {
                    UsageMode::PaidBalance => paid_tokens_used,
                    UsageMode::FreeTrial => free_used_tokens,
                },
                "remaining_tokens": remaining_tokens,
                "last_24h_tokens": last_24h_tokens,
                "last_24h_requests": last_24h_requests,
                "message": match requested_mode {
                    UsageMode::PaidBalance => "paid balance mode uses purchased tokens",
                    UsageMode::FreeTrial => "free trial mode uses gifted tokens",
                }
            })
        }
    };
    write_json_response(stream, 200, &payload.to_string())
}

fn handle_chat_completions(
    stream: &mut TcpStream,
    cfg: &AppConfig,
    request: &HttpRequest,
    auth: &AuthContext,
) -> io::Result<()> {
    let usage_mode = match requested_usage_mode_from_headers(&request.headers) {
        Some(mode) => mode,
        None => auto_resolve_usage_mode(cfg, auth)?,
    };
    if let Some(error_body) = check_login_quota(cfg, auth, usage_mode)? {
        return write_json_response(stream, 429, &error_body);
    }

    let body_text = String::from_utf8(request.body.clone()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "request body must be utf-8 json")
    })?;
    let model = extract_json_string_field(&body_text, "model")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "request json missing model"))?;
    let Some(mapped) = cfg.allowed_models.iter().find(|entry| entry.public_id == model) else {
        eprintln!("blocked unsupported model: {model}");
        write_json_response(
            stream,
            400,
            &format!(
                "{{\"error\":{{\"message\":\"unsupported model: {}\",\"type\":\"invalid_request_error\",\"code\":\"model_not_allowed\"}}}}",
                escape_json(&model)
            ),
        )?;
        return Ok(());
    };

    let replaced_body = replace_json_string_field(&body_text, "model", mapped.upstream_id)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "failed to rewrite model field"))?;
    let is_stream = extract_json_bool_field(&body_text, "stream").unwrap_or(false);
    eprintln!(
        "chat completion model={} mapped_model={} stream={}",
        model, mapped.upstream_id, is_stream
    );

    if is_stream {
        let usage = proxy_streaming_response(stream, cfg, &replaced_body)?;
        persist_usage_if_needed(cfg, auth, usage, &model, true, usage_mode)?;
        Ok(())
    } else {
        let response = proxy_buffered_response(cfg, &replaced_body)?;
        persist_usage_if_needed(cfg, auth, response.usage.clone(), &model, false, usage_mode)?;
        write_upstream_response(stream, response)
    }
}

// Anthropic Messages API entrypoint. Translates inbound Anthropic JSON to
// OpenAI chat-completions, calls the upstream non-streaming, and emits an
// Anthropic-shaped response (or a synthesized SSE stream when requested).
// Pure conversion helpers below are ported from
// webclaw-launcher-tauri/src-tauri/src/services/launcher_claude_service.rs.
fn handle_anthropic_messages(
    stream: &mut TcpStream,
    cfg: &AppConfig,
    request: &HttpRequest,
    auth: &AuthContext,
) -> io::Result<()> {
    let usage_mode = match requested_usage_mode_from_headers(&request.headers) {
        Some(mode) => mode,
        None => auto_resolve_usage_mode(cfg, auth)?,
    };
    if let Some(error_body) = check_login_quota(cfg, auth, usage_mode)? {
        let message = serde_json::from_str::<Value>(&error_body)
            .ok()
            .and_then(|v| {
                v.get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or(error_body);
        return write_anthropic_error(stream, 429, "rate_limit_error", &message);
    }

    let body_text = String::from_utf8(request.body.clone()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "request body must be utf-8 json")
    })?;
    let mut anthropic_payload: Value = serde_json::from_str(&body_text).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid anthropic json: {e}"))
    })?;

    let requested_model = anthropic_payload
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let client_wants_stream = anthropic_payload
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let Some(mapped) = cfg
        .allowed_models
        .iter()
        .find(|entry| entry.public_id == requested_model)
    else {
        eprintln!("blocked unsupported anthropic model: {requested_model}");
        return write_anthropic_error(
            stream,
            400,
            "invalid_request_error",
            &format!("unsupported model: {}", requested_model),
        );
    };

    let openai_payload =
        match convert_anthropic_request_to_openai(&mut anthropic_payload, mapped.upstream_id) {
            Ok(value) => value,
            Err(msg) => {
                return write_anthropic_error(stream, 400, "invalid_request_error", &msg);
            }
        };
    let openai_body = openai_payload.to_string();

    eprintln!(
        "anthropic messages model={} mapped_model={} stream={}",
        requested_model, mapped.upstream_id, client_wants_stream
    );

    let response = proxy_buffered_response(cfg, &openai_body)?;
    persist_usage_if_needed(
        cfg,
        auth,
        response.usage.clone(),
        &requested_model,
        client_wants_stream,
        usage_mode,
    )?;

    if response.status_code >= 400 {
        eprintln!(
            "anthropic upstream error status={} body-bytes={}",
            response.status_code,
            response.body.len()
        );
        let message = serde_json::from_slice::<Value>(&response.body)
            .ok()
            .and_then(|v| {
                v.get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_else(|| String::from_utf8_lossy(&response.body).into_owned());
        return write_anthropic_error(stream, response.status_code, "api_error", &message);
    }

    let openai_response: Value = serde_json::from_slice(&response.body).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid upstream chat response json: {e}"),
        )
    })?;
    let anthropic_response =
        convert_openai_response_to_anthropic(&openai_response, &requested_model);

    if client_wants_stream {
        let sse_body = synthesize_anthropic_sse(&anthropic_response);
        write_anthropic_sse(stream, &sse_body)
    } else {
        write_json_response(stream, 200, &anthropic_response.to_string())
    }
}

fn write_anthropic_error(
    stream: &mut TcpStream,
    status: u16,
    error_type: &str,
    message: &str,
) -> io::Result<()> {
    let body = format!(
        "{{\"type\":\"error\",\"error\":{{\"type\":\"{}\",\"message\":\"{}\"}}}}",
        error_type,
        escape_json(message),
    );
    write_json_response(stream, status, &body)
}

fn write_anthropic_sse(stream: &mut TcpStream, body: &str) -> io::Result<()> {
    write_status_line(stream, 200)?;
    write_common_headers(
        stream,
        Some("text/event-stream; charset=utf-8".to_string()),
        Some(body.len()),
    )?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

fn anthropic_unique_id(prefix: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}_{:x}{:x}", prefix, now_ms(), counter)
}

fn convert_anthropic_request_to_openai(
    payload: &mut Value,
    upstream_model: &str,
) -> Result<Value, String> {
    let object = payload
        .as_object_mut()
        .ok_or_else(|| "anthropic payload must be an object".to_string())?;

    let mut messages = Vec::<Value>::new();
    let system_text = extract_anthropic_system_text(object.remove("system"));
    if !system_text.trim().is_empty() {
        messages.push(serde_json::json!({
            "role": "system",
            "content": system_text,
        }));
    }

    for message in object
        .get("messages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let role = message
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("user");
        convert_anthropic_message(role, message.get("content"), &mut messages);
    }

    let mut openai = serde_json::Map::new();
    openai.insert(
        "model".to_string(),
        Value::String(upstream_model.to_string()),
    );
    openai.insert("messages".to_string(), Value::Array(messages));
    openai.insert("stream".to_string(), Value::Bool(false));

    if let Some(max_tokens) = object.get("max_tokens").and_then(Value::as_u64) {
        openai.insert("max_tokens".to_string(), serde_json::json!(max_tokens));
    }
    if let Some(temperature) = object.get("temperature").and_then(Value::as_f64) {
        openai.insert("temperature".to_string(), serde_json::json!(temperature));
    }
    if let Some(top_p) = object.get("top_p").and_then(Value::as_f64) {
        openai.insert("top_p".to_string(), serde_json::json!(top_p));
    }
    if let Some(tools) = convert_anthropic_tools(object.get("tools")) {
        openai.insert("tools".to_string(), tools);
    }
    if let Some(tool_choice) = convert_anthropic_tool_choice(object.get("tool_choice")) {
        openai.insert("tool_choice".to_string(), tool_choice);
    }

    Ok(Value::Object(openai))
}

fn convert_anthropic_message(role: &str, content: Option<&Value>, messages: &mut Vec<Value>) {
    match role {
        "assistant" => convert_anthropic_assistant_message(content, messages),
        _ => convert_anthropic_user_message(content, messages),
    }
}

fn convert_anthropic_user_message(content: Option<&Value>, messages: &mut Vec<Value>) {
    if let Some(text) = inline_anthropic_content_to_text(content) {
        if !text.trim().is_empty() {
            messages.push(serde_json::json!({
                "role": "user",
                "content": text,
            }));
        }
    }

    for block in content.and_then(Value::as_array).cloned().unwrap_or_default() {
        if block.get("type").and_then(Value::as_str) != Some("tool_result") {
            continue;
        }
        let tool_use_id = block
            .get("tool_use_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if tool_use_id.is_empty() {
            continue;
        }
        let mut tool_text = block_anthropic_content_to_text(block.get("content"));
        if block.get("is_error").and_then(Value::as_bool).unwrap_or(false) {
            tool_text = format!("Tool execution failed.\n{}", tool_text);
        }
        messages.push(serde_json::json!({
            "role": "tool",
            "tool_call_id": tool_use_id,
            "content": tool_text,
        }));
    }
}

fn convert_anthropic_assistant_message(content: Option<&Value>, messages: &mut Vec<Value>) {
    let text = inline_anthropic_content_to_text(content).unwrap_or_default();
    let mut tool_calls = Vec::<Value>::new();
    for block in content.and_then(Value::as_array).cloned().unwrap_or_default() {
        if block.get("type").and_then(Value::as_str) != Some("tool_use") {
            continue;
        }
        let id = block
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| anthropic_unique_id("toolu"));
        let name = block
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("tool")
            .to_string();
        let input = block
            .get("input")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        tool_calls.push(serde_json::json!({
            "id": id,
            "type": "function",
            "function": {
                "name": name,
                "arguments": input.to_string(),
            }
        }));
    }

    let mut message = serde_json::Map::new();
    message.insert("role".to_string(), Value::String("assistant".to_string()));
    message.insert("content".to_string(), Value::String(text));
    if !tool_calls.is_empty() {
        message.insert("tool_calls".to_string(), Value::Array(tool_calls));
    }
    messages.push(Value::Object(message));
}

fn extract_anthropic_system_text(system: Option<Value>) -> String {
    match system {
        Some(Value::String(text)) => text,
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n\n"),
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

fn inline_anthropic_content_to_text(content: Option<&Value>) -> Option<String> {
    match content {
        Some(Value::String(text)) => Some(text.to_string()),
        Some(Value::Array(blocks)) => {
            let text = blocks
                .iter()
                .filter(|block| block.get("type").and_then(Value::as_str) == Some("text"))
                .filter_map(|block| block.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n\n");
            Some(text)
        }
        Some(other) => Some(other.to_string()),
        None => None,
    }
}

fn block_anthropic_content_to_text(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(text)) => text.to_string(),
        Some(Value::Array(blocks)) => blocks
            .iter()
            .map(|block| match block.get("type").and_then(Value::as_str) {
                Some("text") => block
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                _ => block.to_string(),
            })
            .collect::<Vec<_>>()
            .join("\n\n"),
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

fn convert_anthropic_tools(value: Option<&Value>) -> Option<Value> {
    let tools = value?.as_array()?;
    Some(Value::Array(
        tools
            .iter()
            .map(|tool| {
                serde_json::json!({
                    "type": "function",
                    "function": {
                        "name": tool.get("name").and_then(Value::as_str).unwrap_or("tool"),
                        "description": tool.get("description").and_then(Value::as_str).unwrap_or_default(),
                        "parameters": tool.get("input_schema").cloned().unwrap_or_else(|| serde_json::json!({
                            "type": "object",
                            "properties": {}
                        })),
                    }
                })
            })
            .collect(),
    ))
}

fn convert_anthropic_tool_choice(value: Option<&Value>) -> Option<Value> {
    let tool_choice = value?;
    if let Some(choice_type) = tool_choice.get("type").and_then(Value::as_str) {
        return match choice_type {
            "auto" => Some(Value::String("auto".to_string())),
            "any" => Some(Value::String("required".to_string())),
            "tool" => tool_choice.get("name").and_then(Value::as_str).map(|name| {
                serde_json::json!({
                    "type": "function",
                    "function": {
                        "name": name,
                    }
                })
            }),
            _ => None,
        };
    }
    None
}

fn convert_openai_response_to_anthropic(openai: &Value, requested_model: &str) -> Value {
    let message = openai
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let finish_reason = openai
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("finish_reason"))
        .and_then(Value::as_str)
        .unwrap_or("stop");

    let text = message
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let mut content = Vec::<Value>::new();
    if !text.is_empty() {
        content.push(serde_json::json!({
            "type": "text",
            "text": text,
        }));
    }
    for tool_call in message
        .get("tool_calls")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let input = tool_call
            .get("function")
            .and_then(|function| function.get("arguments"))
            .and_then(Value::as_str)
            .and_then(|value| serde_json::from_str::<Value>(value).ok())
            .unwrap_or_else(|| serde_json::json!({}));
        content.push(serde_json::json!({
            "type": "tool_use",
            "id": tool_call.get("id").and_then(Value::as_str).unwrap_or_default(),
            "name": tool_call
                .get("function")
                .and_then(|function| function.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("tool"),
            "input": input,
        }));
    }

    serde_json::json!({
        "id": openai
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| anthropic_unique_id("msg")),
        "type": "message",
        "role": "assistant",
        "model": if requested_model.trim().is_empty() { "glm" } else { requested_model },
        "content": content,
        "stop_reason": map_anthropic_stop_reason(finish_reason),
        "stop_sequence": Value::Null,
        "usage": {
            "input_tokens": openai
                .get("usage")
                .and_then(|usage| usage.get("prompt_tokens"))
                .and_then(Value::as_u64)
                .unwrap_or(0),
            "output_tokens": openai
                .get("usage")
                .and_then(|usage| usage.get("completion_tokens"))
                .and_then(Value::as_u64)
                .unwrap_or(0),
        }
    })
}

fn map_anthropic_stop_reason(finish_reason: &str) -> &'static str {
    match finish_reason {
        "tool_calls" => "tool_use",
        "length" => "max_tokens",
        _ => "end_turn",
    }
}

fn synthesize_anthropic_sse(message: &Value) -> String {
    let mut body = String::new();
    let input_tokens = message
        .get("usage")
        .and_then(|usage| usage.get("input_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let output_tokens = message
        .get("usage")
        .and_then(|usage| usage.get("output_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let empty_message = serde_json::json!({
        "id": message.get("id").cloned().unwrap_or_else(|| Value::String(anthropic_unique_id("msg"))),
        "type": "message",
        "role": "assistant",
        "model": message.get("model").cloned().unwrap_or_else(|| serde_json::json!("glm")),
        "content": [],
        "stop_reason": Value::Null,
        "stop_sequence": Value::Null,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": 0,
        }
    });
    push_anthropic_sse_event(
        &mut body,
        "message_start",
        &serde_json::json!({
            "type": "message_start",
            "message": empty_message,
        }),
    );

    for (index, block) in message
        .get("content")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .enumerate()
    {
        match block.get("type").and_then(Value::as_str).unwrap_or_default() {
            "tool_use" => {
                push_anthropic_sse_event(
                    &mut body,
                    "content_block_start",
                    &serde_json::json!({
                        "type": "content_block_start",
                        "index": index,
                        "content_block": {
                            "type": "tool_use",
                            "id": block.get("id").cloned().unwrap_or_else(|| Value::String(anthropic_unique_id("toolu"))),
                            "name": block.get("name").cloned().unwrap_or_else(|| serde_json::json!("tool")),
                            "input": {},
                        }
                    }),
                );
                push_anthropic_sse_event(
                    &mut body,
                    "content_block_delta",
                    &serde_json::json!({
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {
                            "type": "input_json_delta",
                            "partial_json": block.get("input").cloned().unwrap_or_else(|| serde_json::json!({})).to_string(),
                        }
                    }),
                );
                push_anthropic_sse_event(
                    &mut body,
                    "content_block_stop",
                    &serde_json::json!({
                        "type": "content_block_stop",
                        "index": index,
                    }),
                );
            }
            _ => {
                push_anthropic_sse_event(
                    &mut body,
                    "content_block_start",
                    &serde_json::json!({
                        "type": "content_block_start",
                        "index": index,
                        "content_block": {
                            "type": "text",
                            "text": "",
                        }
                    }),
                );
                push_anthropic_sse_event(
                    &mut body,
                    "content_block_delta",
                    &serde_json::json!({
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {
                            "type": "text_delta",
                            "text": block.get("text").and_then(Value::as_str).unwrap_or_default(),
                        }
                    }),
                );
                push_anthropic_sse_event(
                    &mut body,
                    "content_block_stop",
                    &serde_json::json!({
                        "type": "content_block_stop",
                        "index": index,
                    }),
                );
            }
        }
    }

    push_anthropic_sse_event(
        &mut body,
        "message_delta",
        &serde_json::json!({
            "type": "message_delta",
            "delta": {
                "stop_reason": message.get("stop_reason").cloned().unwrap_or(Value::Null),
                "stop_sequence": Value::Null,
            },
            "usage": {
                "output_tokens": output_tokens,
            }
        }),
    );
    push_anthropic_sse_event(
        &mut body,
        "message_stop",
        &serde_json::json!({
            "type": "message_stop",
        }),
    );
    body.push_str("data: [DONE]\n\n");
    body
}

fn push_anthropic_sse_event(body: &mut String, event: &str, payload: &Value) {
    body.push_str("event: ");
    body.push_str(event);
    body.push('\n');
    body.push_str("data: ");
    body.push_str(&payload.to_string());
    body.push_str("\n\n");
}

fn check_login_quota(cfg: &AppConfig, auth: &AuthContext, usage_mode: UsageMode) -> io::Result<Option<String>> {
    let user_id = match auth {
        AuthContext::Login(claims) => claims.user_id,
        AuthContext::ApiToken(user_id) => *user_id,
        _ => return Ok(None),
    };

    match usage_mode {
        UsageMode::FreeTrial => {
            let used = load_user_consumed_tokens(&cfg.usage_store_path, user_id)?;
            if used < cfg.free_login_total_tokens {
                return Ok(None);
            }
            let body = format!(
                "{{\"error\":{{\"message\":\"free quota exhausted. used {} of {} tokens\",\"type\":\"insufficient_quota\",\"code\":\"free_quota_exhausted\"}}}}",
                used,
                cfg.free_login_total_tokens
            );
            Ok(Some(body))
        }
        UsageMode::PaidBalance => {
            let purchased = load_user_purchased_tokens(&cfg.paid_balance_store_path, user_id)?;
            let used = load_user_consumed_tokens(&cfg.paid_usage_store_path, user_id)?;
            if used < purchased {
                return Ok(None);
            }
            let body = format!(
                "{{\"error\":{{\"message\":\"paid balance exhausted. used {} of {} tokens\",\"type\":\"insufficient_quota\",\"code\":\"paid_balance_exhausted\"}}}}",
                used,
                purchased
            );
            Ok(Some(body))
        }
    }
}

fn persist_usage_if_needed(
    cfg: &AppConfig,
    auth: &AuthContext,
    usage: Option<RequestUsage>,
    model: &str,
    stream: bool,
    usage_mode: UsageMode,
) -> io::Result<()> {
    let (user_id, email) = match auth {
        AuthContext::Login(claims) => (claims.user_id, claims.email.clone()),
        AuthContext::ApiToken(user_id) => {
            let email = get_user_email(&cfg.user_emails_store_path, *user_id)?;
            (*user_id, email)
        }
        _ => return Ok(()),
    };

    let Some(usage) = usage else {
        return Ok(());
    };

    let record = UsageRecord {
        ts: now_ms(),
        user_id,
        email,
        total_tokens: usage.total_tokens,
        input_tokens: usage.input_tokens,
        output_tokens: usage.output_tokens,
        model: model.to_string(),
        stream,
    };
    let target_path = match usage_mode {
        UsageMode::FreeTrial => &cfg.usage_store_path,
        UsageMode::PaidBalance => &cfg.paid_usage_store_path,
    };
    append_usage_record(target_path, &record)
}

fn proxy_buffered_response(cfg: &AppConfig, body: &str) -> io::Result<CurlResponse> {
    let header_path = unique_tmp_path("headers");
    let body_path = unique_tmp_path("body");

    let mut child = Command::new("curl")
        .args([
            "-sS",
            "--http1.1",
            "-X",
            "POST",
            "-H",
            &format!("Authorization: Bearer {}", cfg.zai_api_key),
            "-H",
            "Content-Type: application/json",
            "-H",
            "Accept: application/json",
            "-D",
            header_path.to_string_lossy().as_ref(),
            "-o",
            body_path.to_string_lossy().as_ref(),
            &format!("{}/chat/completions", cfg.upstream_base_url),
            "--data-binary",
            "@-",
        ])
        .stdin(Stdio::piped())
        .spawn()?;

    write_curl_stdin(&mut child, body)?;
    let status = child.wait()?;

    if !status.success() {
        cleanup_tmp(&header_path);
        cleanup_tmp(&body_path);
        eprintln!("upstream curl failed before response: exit_status={status}");
        return Err(io::Error::other("curl upstream request failed"));
    }

    let headers_raw = fs::read_to_string(&header_path)?;
    let body_bytes = fs::read(&body_path)?;
    cleanup_tmp(&header_path);
    cleanup_tmp(&body_path);
    let (status_code, content_type) = parse_header_block(&headers_raw);
    let usage = extract_usage_from_json_bytes(&body_bytes);

    eprintln!(
        "upstream buffered response: status={} content-type={} body-bytes={}",
        status_code,
        content_type.as_deref().unwrap_or("-"),
        body_bytes.len()
    );

    Ok(CurlResponse {
        status_code,
        content_type,
        body: body_bytes,
        usage,
    })
}

fn proxy_streaming_response(
    stream: &mut TcpStream,
    cfg: &AppConfig,
    body: &str,
) -> io::Result<Option<RequestUsage>> {
    let mut last_err = None;
    for attempt in 1..=2 {
        match proxy_streaming_response_once(stream, cfg, body) {
            Ok(usage) => return Ok(usage),
            Err(err) if should_retry_stream_setup(&err) && attempt < 2 => {
                eprintln!("upstream stream setup failed on attempt {attempt}, retrying once: {err}");
                last_err = Some(err);
                thread::sleep(Duration::from_millis(200));
            }
            Err(err) => return Err(err),
        }
    }

    Err(last_err.unwrap_or_else(|| io::Error::other("streaming proxy failed without a captured error")))
}

fn proxy_streaming_response_once(
    stream: &mut TcpStream,
    cfg: &AppConfig,
    body: &str,
) -> io::Result<Option<RequestUsage>> {
    let mut child = Command::new("curl")
        .args([
            "-sS",
            "-N",
            "--http1.1",
            "-X",
            "POST",
            "-H",
            &format!("Authorization: Bearer {}", cfg.zai_api_key),
            "-H",
            "Content-Type: application/json",
            "-H",
            "Accept: text/event-stream",
            "-D",
            "-",
            &format!("{}/chat/completions", cfg.upstream_base_url),
            "--data-binary",
            "@-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    write_curl_stdin(&mut child, body)?;

    let mut stdout = BufReader::new(
        child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("missing curl stdout"))?,
    );
    let mut header_bytes = Vec::new();
    if let Err(err) = read_http_headers(&mut stdout, &mut header_bytes) {
        let output = child.wait_with_output()?;
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let detail = if stderr.is_empty() {
            err.to_string()
        } else {
            format!("{}; curl stderr: {}", err, stderr)
        };
        return Err(io::Error::new(err.kind(), detail));
    }
    let header_text = String::from_utf8_lossy(&header_bytes);
    let (status_code, content_type) = parse_header_block(&header_text);
    eprintln!(
        "upstream streaming response headers: status={} content-type={}",
        status_code,
        content_type.as_deref().unwrap_or("text/event-stream")
    );

    write_status_line(stream, status_code)?;
    write_common_headers(
        stream,
        Some(content_type.unwrap_or_else(|| "text/event-stream".to_string())),
        None,
    )?;
    stream.flush()?;

    let mut usage = None;
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = stdout.read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        stream.write_all(&line)?;
        if let Some(found) = extract_usage_from_sse_line(&line) {
            usage = Some(found);
        }
    }
    stream.flush()?;

    let output = child.wait_with_output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("curl stream error: {stderr}");
    }

    Ok(usage)
}

fn should_retry_stream_setup(err: &io::Error) -> bool {
    let message = err.to_string();
    err.kind() == io::ErrorKind::UnexpectedEof
        || message.contains("upstream closed before sending headers")
        || message.contains("Empty reply from server")
}

fn write_curl_stdin(child: &mut std::process::Child, body: &str) -> io::Result<()> {
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("missing curl stdin"))?;
    stdin.write_all(body.as_bytes())?;
    stdin.flush()?;
    drop(stdin);
    Ok(())
}

fn read_http_headers<R: Read>(reader: &mut R, output: &mut Vec<u8>) -> io::Result<()> {
    let mut buf = [0_u8; 1];
    let mut trailer = Vec::new();
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "upstream closed before sending headers",
            ));
        }
        output.push(buf[0]);
        trailer.push(buf[0]);
        if trailer.len() > 4 {
            trailer.remove(0);
        }
        if trailer == b"\r\n\r\n" || trailer == b"\n\n" {
            break;
        }
    }
    Ok(())
}

fn read_chunked_body<R: BufRead>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let mut size_line = String::new();
        reader.read_line(&mut size_line)?;
        let trimmed = size_line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let size_hex = trimmed.split(';').next().unwrap_or(trimmed);
        let size = usize::from_str_radix(size_hex, 16).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid chunk size: {size_hex}"),
            )
        })?;
        if size == 0 {
            let mut trailer = String::new();
            loop {
                trailer.clear();
                reader.read_line(&mut trailer)?;
                if trailer.trim().is_empty() {
                    break;
                }
            }
            break;
        }

        let mut chunk = vec![0_u8; size];
        reader.read_exact(&mut chunk)?;
        body.extend_from_slice(&chunk);

        let mut crlf = [0_u8; 2];
        reader.read_exact(&mut crlf)?;
    }
    Ok(body)
}

fn parse_header_block(headers_raw: &str) -> (u16, Option<String>) {
    let mut status_code = 200;
    let mut content_type = None;
    for line in headers_raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("HTTP/") {
            let mut parts = trimmed.split_whitespace();
            let _ = parts.next();
            status_code = parts
                .next()
                .and_then(|code| code.parse::<u16>().ok())
                .unwrap_or(200);
        } else if let Some((name, value)) = trimmed.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-type") {
                content_type = Some(value.trim().to_string());
            }
        }
    }
    (status_code, content_type)
}

fn write_upstream_response(stream: &mut TcpStream, response: CurlResponse) -> io::Result<()> {
    write_status_line(stream, response.status_code)?;
    write_common_headers(
        stream,
        Some(
            response
                .content_type
                .unwrap_or_else(|| JSON_CONTENT_TYPE.to_string()),
        ),
        Some(response.body.len()),
    )?;
    stream.write_all(&response.body)?;
    stream.flush()
}

fn write_json_response(stream: &mut TcpStream, status: u16, body: &str) -> io::Result<()> {
    write_status_line(stream, status)?;
    write_common_headers(
        stream,
        Some(JSON_CONTENT_TYPE.to_string()),
        Some(body.len()),
    )?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

fn log_route_error(peer: &str, err: &io::Error) {
    if is_client_disconnect(err) {
        eprintln!("request client disconnected from {peer}: {err}");
        return;
    }
    eprintln!("request handling error from {peer}: {err}");
}

fn write_route_error_response(stream: &mut TcpStream, err: &io::Error) -> io::Result<()> {
    if is_client_disconnect(err) {
        return Ok(());
    }

    let message = err.to_string();
    let (status, code, client_message) = classify_route_error(err, &message);
    write_json_response(stream, status, &json_error(code, client_message))
}

fn classify_route_error(err: &io::Error, message: &str) -> (u16, &'static str, &'static str) {
    if err.kind() == io::ErrorKind::InvalidData || err.kind() == io::ErrorKind::InvalidInput {
        return (400, "invalid_request", "request body is invalid");
    }
    if message.contains("status=429") {
        return (429, "rate_limit", "upstream rate limit reached, please retry later");
    }
    if message.contains("upstream closed before sending headers") {
        return (
            503,
            "upstream_unavailable",
            "upstream closed before sending headers, please retry",
        );
    }
    if message.contains("curl upstream request failed") {
        return (502, "upstream_request_failed", "upstream request failed");
    }
    (502, "upstream_error", "proxy request failed")
}

fn is_client_disconnect(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof
    ) && !err.to_string().contains("upstream closed before sending headers")
}

fn write_empty_response(stream: &mut TcpStream, status: u16) -> io::Result<()> {
    write_status_line(stream, status)?;
    write_common_headers(stream, None, Some(0))?;
    stream.flush()
}

fn write_status_line(stream: &mut TcpStream, status: u16) -> io::Result<()> {
    let reason = reason_phrase(status);
    write!(stream, "HTTP/1.1 {} {}\r\n", status, reason)
}

fn write_common_headers(
    stream: &mut TcpStream,
    content_type: Option<String>,
    content_length: Option<usize>,
) -> io::Result<()> {
    write!(stream, "Connection: close\r\n")?;
    write!(stream, "Access-Control-Allow-Origin: *\r\n")?;
    write!(
        stream,
        "Access-Control-Allow-Headers: Authorization, Content-Type, X-WebClaw-License-Token, X-WebClaw-Usage-Mode\r\n"
    )?;
    write!(stream, "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n")?;
    if let Some(content_type) = content_type {
        write!(stream, "Content-Type: {}\r\n", content_type)?;
    }
    if let Some(content_length) = content_length {
        write!(stream, "Content-Length: {}\r\n", content_length)?;
    }
    write!(stream, "\r\n")
}

fn build_models_payload(cfg: &AppConfig) -> String {
    let data = cfg
        .allowed_models
        .iter()
        .map(|model| {
            format!(
                "{{\"id\":\"{}\",\"object\":\"model\",\"created\":0,\"owned_by\":\"zai-coding-plan-proxy\"}}",
                escape_json(model.public_id)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"object\":\"list\",\"data\":[{}]}}", data)
}

fn json_error(code: &str, message: &str) -> String {
    format!(
        "{{\"error\":{{\"message\":\"{}\",\"type\":\"invalid_request_error\",\"code\":\"{}\"}}}}",
        escape_json(message),
        escape_json(code)
    )
}

fn extract_json_string_field(body: &str, field: &str) -> Option<String> {
    let pattern = format!("\"{}\"", field);
    let start = body.find(&pattern)?;
    let after_key = &body[start + pattern.len()..];
    let colon_index = after_key.find(':')?;
    let after_colon = after_key[colon_index + 1..].trim_start();
    if !after_colon.starts_with('"') {
        return None;
    }
    let value = parse_json_string(after_colon)?;
    Some(value.0)
}

fn extract_json_bool_field(body: &str, field: &str) -> Option<bool> {
    let pattern = format!("\"{}\"", field);
    let start = body.find(&pattern)?;
    let after_key = &body[start + pattern.len()..];
    let colon_index = after_key.find(':')?;
    let after_colon = after_key[colon_index + 1..].trim_start();
    if after_colon.starts_with("true") {
        Some(true)
    } else if after_colon.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn replace_json_string_field(body: &str, field: &str, replacement: &str) -> Option<String> {
    let pattern = format!("\"{}\"", field);
    let key_index = body.find(&pattern)?;
    let mut cursor = key_index + pattern.len();
    let bytes = body.as_bytes();

    while cursor < body.len() && matches!(bytes[cursor], b' ' | b'\n' | b'\r' | b'\t') {
        cursor += 1;
    }
    if cursor >= body.len() || bytes[cursor] != b':' {
        return None;
    }
    cursor += 1;
    while cursor < body.len() && matches!(bytes[cursor], b' ' | b'\n' | b'\r' | b'\t') {
        cursor += 1;
    }
    if cursor >= body.len() || bytes[cursor] != b'"' {
        return None;
    }
    let value_start = cursor;
    let (_, consumed) = parse_json_string(&body[value_start..])?;
    let value_end = value_start + consumed;

    let mut rewritten = String::new();
    rewritten.push_str(&body[..value_start]);
    rewritten.push('"');
    rewritten.push_str(&escape_json(replacement));
    rewritten.push('"');
    rewritten.push_str(&body[value_end..]);
    Some(rewritten)
}

fn parse_json_string(input: &str) -> Option<(String, usize)> {
    let mut chars = input.char_indices();
    let (_, first) = chars.next()?;
    if first != '"' {
        return None;
    }

    let mut escaped = false;
    let mut output = String::new();

    for (index, ch) in input.char_indices().skip(1) {
        if escaped {
            let actual = match ch {
                '"' => '"',
                '\\' => '\\',
                '/' => '/',
                'b' => '\u{0008}',
                'f' => '\u{000C}',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                'u' => return None,
                other => other,
            };
            output.push(actual);
            escaped = false;
            continue;
        }

        match ch {
            '\\' => escaped = true,
            '"' => return Some((output, index + 1)),
            other => output.push(other),
        }
    }

    None
}

fn verify_login_token(token: &str) -> Result<LoginTokenClaims, String> {
    let segments: Vec<&str> = token.split('.').collect();
    if segments.len() != 3 {
        return Err("invalid login token format".to_string());
    }

    let header: JwtHeader = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(segments[0].as_bytes())
            .map_err(|e| format!("decode token header failed: {e}"))?,
    )
    .map_err(|e| format!("parse token header failed: {e}"))?;
    if header.alg != "RS256" {
        return Err("unsupported login token algorithm".to_string());
    }
    if let Some(token_type) = header.typ.as_deref() {
        if !token_type.eq_ignore_ascii_case("JWT") {
            return Err("invalid login token type".to_string());
        }
    }

    let signing_input = format!("{}.{}", segments[0], segments[1]);
    let public_key = PKey::public_key_from_pem(AUTH_CALLBACK_PUBLIC_KEY_PEM.as_bytes())
        .map_err(|e| format!("load public key failed: {e}"))?;
    let signature = URL_SAFE_NO_PAD
        .decode(segments[2].as_bytes())
        .map_err(|e| format!("decode token signature failed: {e}"))?;
    let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key)
        .map_err(|e| format!("init verifier failed: {e}"))?;
    verifier
        .update(signing_input.as_bytes())
        .map_err(|e| format!("feed verifier failed: {e}"))?;
    let verified = verifier
        .verify(&signature)
        .map_err(|e| format!("verify token signature failed: {e}"))?;
    if !verified {
        return Err("invalid login token signature".to_string());
    }

    let claims: LoginTokenClaims = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(segments[1].as_bytes())
            .map_err(|e| format!("decode token payload failed: {e}"))?,
    )
    .map_err(|e| format!("parse token payload failed: {e}"))?;

    if claims.iss.as_deref() != Some(LICENSE_TOKEN_ISSUER) {
        return Err("invalid login token issuer".to_string());
    }
    if claims.user_id == 0 || claims.email.trim().is_empty() {
        return Err("login token missing user identity".to_string());
    }
    if claims.exp <= now_secs() {
        return Err("login token expired".to_string());
    }
    if let Some(iat) = claims.iat {
        if iat > now_secs().saturating_add(60) {
            return Err("login token issued-at time is invalid".to_string());
        }
    }

    Ok(claims)
}

fn requested_usage_mode_from_headers(headers: &HashMap<String, String>) -> Option<UsageMode> {
    match headers.get(USAGE_MODE_HEADER).map(|value| value.trim()) {
        Some("paid_balance") => Some(UsageMode::PaidBalance),
        Some("free_trial") => Some(UsageMode::FreeTrial),
        _ => None,
    }
}

fn auto_resolve_usage_mode(cfg: &AppConfig, auth: &AuthContext) -> io::Result<UsageMode> {
    let user_id = match auth {
        AuthContext::Login(claims) => claims.user_id,
        AuthContext::ApiToken(user_id) => *user_id,
        _ => return Ok(UsageMode::FreeTrial),
    };
    let purchased = load_user_purchased_tokens(&cfg.paid_balance_store_path, user_id)?;
    let used = load_user_consumed_tokens(&cfg.paid_usage_store_path, user_id)?;
    if purchased > used {
        Ok(UsageMode::PaidBalance)
    } else {
        Ok(UsageMode::FreeTrial)
    }
}

fn usage_mode_label(mode: UsageMode) -> &'static str {
    match mode {
        UsageMode::FreeTrial => "free_trial",
        UsageMode::PaidBalance => "paid_balance",
    }
}

fn load_user_consumed_tokens(path: &Path, user_id: u64) -> io::Result<u64> {
    if !path.exists() {
        return Ok(0);
    }
    let _guard = FileLockGuard::acquire(path)?;
    let content = fs::read_to_string(path)?;
    let mut total = 0_u64;
    for line in content.lines() {
        let Ok(record) = serde_json::from_str::<UsageRecord>(line) else {
            continue;
        };
        if record.user_id == user_id {
            total = total.saturating_add(record.total_tokens);
        }
    }
    Ok(total)
}

fn load_user_consumed_tokens_last_24h(path: &Path, user_id: u64) -> io::Result<(u64, u64)> {
    if !path.exists() {
        return Ok((0, 0));
    }
    let _guard = FileLockGuard::acquire(path)?;
    let content = fs::read_to_string(path)?;
    let cutoff = now_ms().saturating_sub(24 * 60 * 60 * 1000);
    let mut total_tokens = 0_u64;
    let mut requests = 0_u64;
    for line in content.lines() {
        let Ok(record) = serde_json::from_str::<UsageRecord>(line) else {
            continue;
        };
        if record.user_id == user_id && record.ts >= cutoff {
            total_tokens = total_tokens.saturating_add(record.total_tokens);
            requests = requests.saturating_add(1);
        }
    }
    Ok((total_tokens, requests))
}

fn load_user_purchased_tokens(path: &Path, user_id: u64) -> io::Result<u64> {
    if !path.exists() {
        return Ok(0);
    }
    let _guard = FileLockGuard::acquire(path)?;
    let content = fs::read_to_string(path)?;
    let value = serde_json::from_str::<Value>(&content)
        .map_err(|e| io::Error::other(format!("parse paid balance store failed: {e}")))?;
    let user_key = user_id.to_string();
    Ok(value
        .get(&user_key)
        .and_then(Value::as_u64)
        .unwrap_or(0))
}

fn add_paid_tokens(path: &Path, user_id: u64, granted_tokens: u64) -> io::Result<u64> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let _guard = FileLockGuard::acquire(path)?;
    let mut balances = if path.exists() {
        serde_json::from_str::<Value>(&fs::read_to_string(path)?)
            .unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };
    let user_key = user_id.to_string();
    let current = balances
        .get(&user_key)
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let next = current.saturating_add(granted_tokens);
    balances[&user_key] = Value::from(next);
    let bytes = serde_json::to_vec_pretty(&balances)
        .map_err(|e| io::Error::other(format!("serialize paid balances failed: {e}")))?;
    atomic_write_bytes(path, &bytes)?;
    Ok(next)
}

fn append_paid_grant_record(path: &Path, record: &PaidGrantRecord) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let _guard = FileLockGuard::acquire(path)?;
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(
        file,
        "{}",
        serde_json::to_string(record)
            .map_err(|e| io::Error::other(format!("serialize paid grant record failed: {e}")))?
    )?;
    Ok(())
}

fn find_grant_record_by_order_no(path: &Path, order_no: &str) -> io::Result<Option<PaidGrantRecord>> {
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(path)?;
    for line in content.lines() {
        let Ok(record) = serde_json::from_str::<PaidGrantRecord>(line) else {
            continue;
        };
        if record.order_no == order_no {
            return Ok(Some(record));
        }
    }
    Ok(None)
}

fn sync_user_email(path: &Path, user_id: u64, email: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let _guard = FileLockGuard::acquire(path)?;
    let mut emails = if path.exists() {
        serde_json::from_str::<Value>(&fs::read_to_string(path)?)
            .unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };
    let user_key = user_id.to_string();
    emails[&user_key] = Value::from(email.trim());
    let bytes = serde_json::to_vec_pretty(&emails)
        .map_err(|e| io::Error::other(format!("serialize user emails failed: {e}")))?;
    atomic_write_bytes(path, &bytes)?;
    Ok(())
}

fn get_user_email(path: &Path, user_id: u64) -> io::Result<String> {
    if !path.exists() {
        return Ok(format!("user-{}@example.com", user_id));
    }
    let _guard = FileLockGuard::acquire(path)?;
    let content = fs::read_to_string(path)?;
    let value = serde_json::from_str::<Value>(&content)
        .map_err(|e| io::Error::other(format!("parse user emails failed: {e}")))?;
    let user_key = user_id.to_string();
    Ok(value
        .get(&user_key)
        .and_then(Value::as_str)
        .unwrap_or(&format!("user-{}@example.com", user_key))
        .to_string())
}

fn request_query_param(path: &str, key: &str) -> Option<String> {
    let query = path.split_once('?')?.1;
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if name == key {
            return Some(percent_decode(value));
        }
    }
    None
}

fn append_usage_record(path: &Path, record: &UsageRecord) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let _guard = FileLockGuard::acquire(path)?;
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(
        file,
        "{}",
        serde_json::to_string(record)
            .map_err(|e| io::Error::other(format!("serialize usage record failed: {e}")))?
    )?;
    Ok(())
}

fn extract_usage_from_json_bytes(body: &[u8]) -> Option<RequestUsage> {
    let value = serde_json::from_slice::<Value>(body).ok()?;
    extract_usage_from_value(&value)
}

fn extract_usage_from_sse_line(line: &[u8]) -> Option<RequestUsage> {
    let text = String::from_utf8_lossy(line);
    let trimmed = text.trim();
    let payload = trimmed.strip_prefix("data:")?.trim();
    if payload.is_empty() || payload == "[DONE]" {
        return None;
    }
    let value = serde_json::from_str::<Value>(payload).ok()?;
    extract_usage_from_value(&value)
}

fn extract_usage_from_value(value: &Value) -> Option<RequestUsage> {
    let usage = value.get("usage")?;
    let input_tokens = usage
        .get("prompt_tokens")
        .or_else(|| usage.get("input_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let output_tokens = usage
        .get("completion_tokens")
        .or_else(|| usage.get("output_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let total_tokens = usage
        .get("total_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(input_tokens.saturating_add(output_tokens));
    Some(RequestUsage {
        total_tokens,
        input_tokens,
        output_tokens,
    })
}

fn percent_decode(input: &str) -> String {
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &input[i + 1..i + 3];
            if let Ok(value) = u8::from_str_radix(hex, 16) {
                out.push(value);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn escape_json(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

fn unique_tmp_path(kind: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    env::temp_dir().join(format!(
        "zai-coding-plan-openai-proxy-{}-{}-{}.tmp",
        std::process::id(),
        kind,
        nanos
    ))
}

fn atomic_write_bytes(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp_path = atomic_tmp_path(path);
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp_path, path)?;
    Ok(())
}

fn atomic_tmp_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state");
    path.with_file_name(format!(
        ".{}.{}.tmp",
        file_name,
        now_ms()
    ))
}

struct FileLockGuard {
    path: PathBuf,
}

impl FileLockGuard {
    fn acquire(target: &Path) -> io::Result<Self> {
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let lock_path = lock_path_for(target);
        for _ in 0..200 {
            match OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&lock_path)
            {
                Ok(mut file) => {
                    let _ = writeln!(file, "pid={} ts={}", std::process::id(), now_ms());
                    return Ok(Self { path: lock_path });
                }
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => return Err(err),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("timed out waiting for lock: {}", lock_path.display()),
        ))
    }
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn lock_path_for(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state");
    path.with_file_name(format!(".{}.lock", file_name))
}

fn cleanup_tmp(path: &PathBuf) {
    let _ = fs::remove_file(path);
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis() as u64
}

fn env_bool(name: &str, default: bool) -> bool {
    env::var(name)
        .ok()
        .map(|value| matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(default)
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "OK",
    }
}
