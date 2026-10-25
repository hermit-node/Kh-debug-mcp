//! KH Debug MCP: a small, stateless MCP server running locally on Windows.
//! Accept connections on loopback only. Use a trusted Secure MCP Tunnel
//! rather than publishing this arbitrary-command tool on the Internet.
use axum::{
    Json, Router,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};
#[cfg(windows)]
use tokio::process::Command;
use tokio::time::timeout;

const ADDRESS: &str = "127.0.0.1:41370";
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

fn tool_definition() -> Value {
    json!({
        "name": "run_powershell",
        "title": "Run PowerShell on this Windows computer",
        "description": "Run a PowerShell command locally as the Windows account hosting this MCP server. This can change system state. Request user approval before commands that modify files, services, configuration or software.",
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
    #[cfg(not(windows))]
    {
        let _ = (script, seconds);
        return tool_result(
            "PowerShell execution is supported only on Windows hosts".into(),
            true,
        );
    }
    #[cfg(windows)]
    {
        let mut process = Command::new("powershell.exe");
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
async fn mcp(headers: HeaderMap, Json(request): Json<Value>) -> Response {
    if headers.contains_key("origin") {
        return StatusCode::FORBIDDEN.into_response();
    }
    let host = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if !matches!(host, "127.0.0.1:41370" | "localhost:41370") {
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
        "tools/list" => rpc_ok(id, json!({"tools":[tool_definition()]})),
        "tools/call" => {
            let Some(params) = request.get("params") else {
                return rpc_error(id, -32602, "Missing params");
            };
            if params.get("name").and_then(Value::as_str) != Some("run_powershell") {
                return rpc_error(id, -32602, "Unknown tool");
            }
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            rpc_ok(id, run_powershell(&args).await)
        }
        _ => rpc_error(id, -32601, "Method not found"),
    }
}

async fn health() -> Json<Value> {
    Json(json!({"ok":true,"mcp_endpoint":"/mcp","platform":std::env::consts::OS}))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = ADDRESS.parse()?;
    let app = Router::new()
        .route("/health", get(health))
        .route("/mcp", post(mcp));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("KH Debug MCP listening at http://{ADDRESS}/mcp (loopback only)");
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