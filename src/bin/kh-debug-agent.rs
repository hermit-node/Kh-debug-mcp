//! User-side ephemeral diagnostic agent: holds only B and makes outbound HTTP.
//! Runs local PowerShell only after MCP forwards a job from an Auth-approved session.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{env, process::Stdio, time::Duration};
use tokio::{process::Command, time::timeout};

async fn execute(command: &str, seconds: u64) -> Value {
    if command.is_empty() || command.len() > 8192 || !(1..=120).contains(&seconds) {
        return json!({"content":[{"type":"text","text":"invalid remote command"}],"isError":true});
    }
    let exe = if cfg!(windows) {
        "powershell.exe"
    } else {
        "pwsh"
    };
    let mut cmd = Command::new(exe);
    cmd.args([
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        command,
    ])
    .env("KH_AGENT_ROLE", "USER_SIDE_AGENT")
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true);
    match cmd.spawn() {
        Err(e) => {
            json!({"content":[{"type":"text","text":format!("PowerShell spawn failed: {e}")}],"isError":true})
        }
        Ok(process) => {
            match timeout(Duration::from_secs(seconds), process.wait_with_output()).await {
                Err(_) => {
                    json!({"content":[{"type":"text","text":"Remote command timeout"}],"isError":true})
                }
                Ok(Err(e)) => {
                    json!({"content":[{"type":"text","text":format!("Remote command failed: {e}")}],"isError":true})
                }
                Ok(Ok(output)) => {
                    let mut text = format!(
                        "exit_code: {:?}\nstdout:\n{}\nstderr:\n{}",
                        output.status.code(),
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                    if text.len() > 64 * 1024 {
                        let mut pos = 64 * 1024;
                        while !text.is_char_boundary(pos) {
                            pos -= 1
                        }
                        text.truncate(pos);
                        text.push_str("\n[truncated]");
                    }
                    json!({"content":[{"type":"text","text":text}],"isError":!output.status.success()})
                }
            }
        }
    }
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = env::var("KH_AGENT_AUTH_URL")?;
    if !endpoint.starts_with("http://127.0.0.1:")
        && !endpoint.starts_with("http://localhost:")
        && !endpoint.starts_with("http://auth:41371")
        && !endpoint.starts_with("https://")
    {
        return Err("Development agent requires local AuthGate or a secure local forwarding endpoint; never use unprotected remote HTTP".into());
    }
    let user = env::var("KH_AGENT_USER")?;
    let b = tokio::fs::read(env::var("KH_AGENT_B")?).await?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()?;
    let response = client
        .post(format!("{endpoint}/agent/login"))
        .json(&json!({"user_id":user,"b_png_base64":STANDARD.encode(b)}))
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(format!("Auth rejected connection ({})", response.status()).into());
    }
    let login: Value = response.json().await?;
    let token = login["session_token"].as_str().ok_or("No session token")?;
    println!("AUTH_APPROVED: user={user}, outbound agent tunnel established");
    loop {
        let response = client
            .post(format!("{endpoint}/agent/next"))
            .bearer_auth(token)
            .send()
            .await?;
        if !response.status().is_success() {
            println!("TUNNEL_CLOSED: session rejected, revoked or expired");
            break;
        }
        let job: Value = response.json().await?;
        let Some(id) = job["job_id"].as_u64() else {
            continue;
        };
        let result = execute(
            job["command"].as_str().unwrap_or(""),
            job["timeout_seconds"].as_u64().unwrap_or(30),
        )
        .await;
        let result_response = client
            .post(format!("{endpoint}/agent/result"))
            .bearer_auth(token)
            .json(&json!({"job_id":id,"output":result}))
            .send()
            .await?;
        if !result_response.status().is_success() {
            println!("TUNNEL_CLOSED: result rejected after revocation or expiry");
            break;
        }
        println!("REMOTE_COMMAND_COMPLETED: {id}");
    }
    Ok(())
}
