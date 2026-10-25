//! KH Debug MCP: a small MCP server for Windows or Linux Docker.
//! Expose on host loopback only. Use a trusted Secure MCP Tunnel
//! rather than publishing this arbitrary-command tool on the Internet.
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{env, net::SocketAddr, sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use tokio::process::Command;
mod image_store;
use image_store::ImageStore;
mod image_tools;
use tokio::time::timeout;

const DEFAULT_ADDRESS: &str = "127.0.0.1:41370";
struct AppState {
    images: ImageStore,
    allowed_hosts: Vec<String>,
    pair_gate: Option<PairGate>,
    relay: Option<McpRelay>,
}
struct McpRelay {
    secret: String,
    a_half_file: std::path::PathBuf,
    auth_url: String,
    client: reqwest::Client,
}
impl McpRelay {
    fn allowed(&self, headers: &HeaderMap) -> bool {
        let Some(token) = headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
        else {
            return false;
        };
        token.len() == self.secret.len()
            && bool::from(token.as_bytes().ct_eq(self.secret.as_bytes()))
    }
    async fn command(
        &self,
        script: &str,
        seconds: u64,
        target: Option<&str>,
        shell: &str,
    ) -> Value {
        let reply = self
            .client
            .post(&self.auth_url)
            .bearer_auth(&self.secret)
            .json(&json!({"command":script,"timeout_seconds":seconds,"target_user":target,"shell":shell}))
            .send()
            .await;
        let Ok(reply) = reply else {
            return tool_result("AuthGate unavailable: remote command blocked".into(), true);
        };
        if !reply.status().is_success() {
            return tool_result(
                format!("AuthGate blocked remote command ({})", reply.status()),
                true,
            );
        }
        match reply.json::<Value>().await {
            Ok(body) if body.get("result").is_some() => body["result"].clone(),
            _ => tool_result(
                "Invalid AuthGate response; remote command blocked".into(),
                true,
            ),
        }
    }
}
struct PairGate {
    url: String,
    b_png_base64: String,
    user: Option<String>,
    password: Option<String>,
    client: reqwest::Client,
}
impl PairGate {
    async fn authorized(&self) -> bool {
        let req = self
            .client
            .post(&self.url)
            .json(&json!({"b_png_base64": self.b_png_base64,"expected_user":self.user,"password":self.password}))
            .send()
            .await;
        let Ok(reply) = req else {
            return false;
        };
        if !reply.status().is_success() {
            return false;
        }
        reply
            .json::<Value>()
            .await
            .is_ok_and(|body| body["authorized"] == true)
    }
}
const MAX_COMMAND_LENGTH: usize = 8192;
const MAX_OUTPUT_BYTES: usize = 64 * 1024;

fn rpc_ok(id: Value, result: Value) -> Response {
    Json(json!({"jsonrpc":"2.0","id":id,"result":result})).into_response()
}
fn rpc_error(id: Value, code: i32, message: &str) -> Response {
    Json(json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})).into_response()
}
fn tool_result(text: String, is_error: bool) -> Value {
    json!({"content":[{"type":"text","text":text}],"isError":is_error})
}

fn remote_tool(shell_mode: &str) -> Value {
    let (name, description) = if shell_mode == "sh" {
        (
            "run_remote_shell",
            "Execute a /bin/sh script inside an authenticated Linux user-agent container, routed exclusively through AuthGate.",
        )
    } else {
        (
            "run_remote_powershell",
            "Execute PowerShell in an authenticated Windows diagnostic EXE, routed exclusively through AuthGate.",
        )
    };
    json!({"name":name,
        "description":description,
        "inputSchema":{"type":"object","properties":{
            "command":{"type":"string"},"target_user":{"type":"string"},
            "timeout_seconds":{"type":"integer","minimum":1,"maximum":120}
        },"required":["command"],"additionalProperties":false},
        "annotations":{"readOnlyHint":false,"destructiveHint":true}})
}
fn tool_definition() -> Value {
    json!({
        "name": "run_powershell",
        "title": "Run PowerShell in the MCP runtime",
        "description": "Run PowerShell inside this MCP process environment (inside the container when using Docker, not on the Docker host). This can change system state. Obtain user approval for modifications.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type":"string","description":"PowerShell command or script to run"},
                "timeout_seconds": {"type":"integer","minimum":1,"maximum":120,"default":30}
            },
            "required": ["command"],
            "additionalProperties": false
        },
        "annotations":{"readOnlyHint":false,"destructiveHint":true,"openWorldHint":false}
    })
}

async fn run_powershell(args: &Value) -> Value {
    let Some(script) = args.get("command").and_then(Value::as_str) else {
        return tool_result("Missing string argument: command".into(), true);
    };
    if script.is_empty() || script.len() > MAX_COMMAND_LENGTH {
        return tool_result(
            format!("Command must contain 1–{MAX_COMMAND_LENGTH} bytes"),
            true,
        );
    }
    let seconds = args
        .get("timeout_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(30);
    if !(1..=120).contains(&seconds) {
        return tool_result("timeout_seconds must be 1–120".into(), true);
    }
    {
        let shell = if cfg!(windows) {
            "powershell.exe"
        } else {
            "pwsh"
        };
        let mut process = Command::new(shell);
        process.args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ]);
        process.kill_on_drop(true);
        process.stdout(std::process::Stdio::piped());
        process.stderr(std::process::Stdio::piped());
        let child = match process.spawn() {
            Ok(child) => child,
            Err(e) => return tool_result(format!("Failed to launch PowerShell: {e}"), true),
        };
        match timeout(Duration::from_secs(seconds), child.wait_with_output()).await {
            Err(_) => tool_result(
                format!("PowerShell exceeded {seconds}s; process terminated"),
                true,
            ),
            Ok(Err(e)) => tool_result(format!("PowerShell process failed: {e}"), true),
            Ok(Ok(output)) => {
                let success = output.status.success();
                let mut out = format!(
                    "exit_code: {}\nstdout:\n{}\nstderr:\n{}",
                    output
                        .status
                        .code()
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "terminated".into()),
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                if out.len() > MAX_OUTPUT_BYTES {
                    let mut boundary = MAX_OUTPUT_BYTES;
                    while !out.is_char_boundary(boundary) {
                        boundary -= 1;
                    }
                    out.truncate(boundary);
                    out.push_str("\n[output truncated]");
                }
                tool_result(out, !success)
            }
        }
    }
}

/// No browser access, even from a malicious tab on the same computer.
async fn mcp(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Response {
    if headers.contains_key("origin") {
        return StatusCode::FORBIDDEN.into_response();
    }
    let host = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if !state.allowed_hosts.iter().any(|h| h == host) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return rpc_error(
            request.get("id").cloned().unwrap_or(Value::Null),
            -32600,
            "Invalid Request",
        );
    };
    // MCP notifications (e.g. notifications/initialized) get HTTP 202, no JSON body.
    let Some(id) = request.get("id").cloned() else {
        return StatusCode::ACCEPTED.into_response();
    };
    match method {
        "initialize" => rpc_ok(
            id,
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities":{"tools":{"listChanged":false}},
                "serverInfo":{"name":"kh-debug-mcp","version":env!("CARGO_PKG_VERSION")}
            }),
        ),
        "ping" => rpc_ok(id, json!({})),
        "tools/list" => {
            let mut tools = vec![
                tool_definition(),
                image_tools::list_tool(),
                image_tools::save_tool(),
                image_tools::delete_tool(),
            ];
            if state.relay.is_some() {
                tools.push(remote_tool("powershell"));
                tools.push(remote_tool("sh"));
            }
            rpc_ok(id, json!({"tools":tools}))
        }
        "tools/call" => {
            if let Some(gate) = &state.pair_gate {
                if !gate.authorized().await {
                    return rpc_error(id, -32001, "A/B image pairing not authorized");
                }
            }
            let Some(params) = request.get("params") else {
                return rpc_error(id, -32602, "Missing params");
            };
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            rpc_ok(
                id,
                call_tool(
                    &state,
                    params.get("name").and_then(Value::as_str).unwrap_or(""),
                    &args,
                )
                .await,
            )
        }
        _ => rpc_error(id, -32601, "Method not found"),
    }
}

async fn call_tool(state: &AppState, name: &str, args: &Value) -> Value {
    match name {
        "run_powershell" => run_powershell(args).await,
        "run_remote_powershell" | "run_remote_shell" => {
            let Some(relay) = &state.relay else {
                return tool_result("AuthGate not configured".into(), true);
            };
            let command = args["command"].as_str().unwrap_or("");
            let seconds = args["timeout_seconds"].as_u64().unwrap_or(30);
            if command.is_empty()
                || command.len() > MAX_COMMAND_LENGTH
                || !(1..=120).contains(&seconds)
            {
                return tool_result("Invalid remote command".into(), true);
            }
            relay
                .command(
                    command,
                    seconds,
                    args["target_user"].as_str(),
                    if name == "run_remote_shell" {
                        "sh"
                    } else {
                        "powershell"
                    },
                )
                .await
        }
        "list_images" => match state.images.list().await {
            Ok(items) => tool_result(json!({"images":items,"max_images":96}).to_string(), false),
            Err(e) => tool_result(e.to_string(), true),
        },
        "save_image" => {
            let name = args.get("name").and_then(Value::as_str).unwrap_or("");
            let png = args.get("png_base64").and_then(Value::as_str).unwrap_or("");
            match state.images.save(name, png).await {
                Ok(record) => tool_result(record.to_string(), false),
                Err(e) => tool_result(e, true),
            }
        }
        "delete_image" => {
            let name = args.get("name").and_then(Value::as_str).unwrap_or("");
            match state.images.delete(name).await {
                Ok(()) => tool_result("Image deleted".into(), false),
                Err(e) => tool_result(e, true),
            }
        }
        _ => tool_result("Unknown tool".into(), true),
    }
}

async fn master_digest(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let Some(relay) = &state.relay else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({})));
    };
    if !relay.allowed(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({})));
    }
    let Ok(value) = tokio::fs::read_to_string(&relay.a_half_file).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({})));
    };
    let part = value.trim();
    if part.len() != 32 || !part.bytes().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({})));
    }
    (StatusCode::OK, Json(json!({"a_half":part.to_ascii_lowercase()})))
}

async fn health() -> Json<Value> {
    Json(json!({"ok":true,"mcp_endpoint":"/mcp","platform":std::env::consts::OS}))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = env::var("KH_DEBUG_BIND").unwrap_or_else(|_| DEFAULT_ADDRESS.into());
    let addr: SocketAddr = bind.parse()?;
    let allowed = env::var("KH_DEBUG_ALLOWED_HOSTS")
        .unwrap_or_else(|_| "localhost:41370,127.0.0.1:41370".into());
    let allowed_hosts = allowed.split(',').map(|s| s.trim().to_string()).collect();
    let images = ImageStore::new(
        env::var("KH_DEBUG_IMAGE_DIR")
            .unwrap_or_else(|_| "./screenshots".into())
            .into(),
    )
    .await?;
    let pair_gate = match (
        env::var("KH_DEBUG_AUTH_URL").ok(),
        env::var("KH_DEBUG_PAIR_B").ok(),
    ) {
        (None, None) => None, // Legacy native Windows mode, no pairing configured.
        (Some(url), Some(path)) => {
            if !url.starts_with("http://auth:41371/") && !url.starts_with("http://127.0.0.1:") {
                return Err("Auth URL must refer to private Auth Server".into());
            }
            let png = tokio::fs::read(path).await?;
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()?;
            let user = env::var("KH_DEBUG_PAIR_USER").ok();
            let password = match env::var("KH_DEBUG_PAIR_PASSWORD_FILE") {
                Ok(file) => Some(
                    tokio::fs::read_to_string(file)
                        .await?
                        .trim_end_matches(['\r', '\n'])
                        .to_owned(),
                ),
                Err(env::VarError::NotPresent) => None,
                Err(_) => return Err("Invalid pairing password path".into()),
            };
            if user.is_some() != password.is_some() {
                return Err("User and password file must both be set".into());
            }
            Some(PairGate {
                url,
                b_png_base64: STANDARD.encode(png),
                user,
                password,
                client,
            })
        }
        _ => return Err("Both KH_DEBUG_AUTH_URL and KH_DEBUG_PAIR_B are required".into()),
    };
    if let Some(gate) = &pair_gate {
        if !gate.authorized().await {
            return Err("A/B image pairing failed: MCP will not listen".into());
        }
    }
    let relay=match (env::var("KH_DEBUG_A_HALF_FILE").ok(),env::var("KH_DEBUG_AUTH_RELAY_URL").ok(),
        env::var("KH_DEBUG_SERVICE_TOKEN_FILE").ok()){
        (None,None,None)=>None,
        (Some(master),Some(url),Some(secret_file))=>{
            if !url.starts_with("http://127.0.0.1:") && !url.starts_with("http://auth:41371/") {
                return Err("AuthGate relay URL must be private".into());
            }
            let a_half_file=std::path::PathBuf::from(master);
            if !a_half_file.is_absolute()||!a_half_file.is_file(){return Err("MCP A-half file unavailable".into())}
            let secret=tokio::fs::read_to_string(secret_file).await?.trim().to_owned();
            if secret.len()<32{return Err("MCP/Auth service token unavailable".into())}
            let client=reqwest::Client::builder().timeout(Duration::from_secs(10)).build()?;
            Some(McpRelay{secret,a_half_file,auth_url:url,client})
        }
        _=>return Err("Set KH_DEBUG_A_HALF_FILE, KH_DEBUG_AUTH_RELAY_URL and KH_DEBUG_SERVICE_TOKEN_FILE together".into())
    };
    let state = Arc::new(AppState {
        images,
        allowed_hosts,
        pair_gate,
        relay,
    });
    let app = Router::new()
        .route("/health", get(health))
        .route("/mcp", post(mcp))
        .route("/internal/a-half", get(master_digest))
        .layer(DefaultBodyLimit::max(14 * 1024 * 1024))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("KH Debug MCP listening at http://{bind}/mcp");
    println!("For ChatGPT, connect using a trusted Secure MCP Tunnel.");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tool_schema_is_valid() {
        assert_eq!(tool_definition()["name"], "run_powershell");
        assert_eq!(tool_definition()["inputSchema"]["required"][0], "command");
    }
    #[tokio::test]
    async fn missing_command_is_denied() {
        assert_eq!(run_powershell(&json!({})).await["isError"], true);
    }
    #[tokio::test]
    async fn oversized_timeout_is_denied() {
        assert_eq!(
            run_powershell(&json!({"command":"pwd","timeout_seconds":200})).await["isError"],
            true
        );
    }
    #[cfg(windows)]
    #[tokio::test]
    async fn actual_powershell_executes() {
        let result = run_powershell(&json!({"command":"Write-Output 'KH_MCP_RUST_OK'"})).await;
        assert_eq!(result["isError"], false, "{result:?}");
        assert!(
            result["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("KH_MCP_RUST_OK")
        );
    }
}
