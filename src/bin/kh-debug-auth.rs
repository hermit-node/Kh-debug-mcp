//! Independent StegoSplit verification gateway.
//! Only delegates decisions to a separately supplied, trusted verifier.
//! Does not implement or replace the existing StegoSplit A/B algorithm.
#[path = "kh-debug-auth/relay.rs"]
mod relay;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use kh_debug_mcp::pairing;
use serde_json::{Value, json};
use std::{env, path::PathBuf, process::Stdio, sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use tokio::{io::AsyncWriteExt, process::Command, time::timeout};

const MAX_IMAGE_BYTES: usize = 10 * 1024 * 1024;
const PNG_HEADER: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];

struct PythonBridge {
    python_exe: PathBuf,
    script: PathBuf,
    cover: PathBuf,
}

struct Settings {
    api_token: String,
    verifier: Option<PathBuf>,
    state_dir: PathBuf,
    pair_a: Option<PathBuf>,
    python: Option<PythonBridge>,
    relay: Option<Arc<relay::Relay>>,
}

fn authorized(headers: &HeaderMap, secret: &str) -> bool {
    let Some(value) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(provided) = value.strip_prefix("Bearer ") else {
        return false;
    };
    provided.len() == secret.len() && bool::from(provided.as_bytes().ct_eq(secret.as_bytes()))
}

fn acceptable_image(encoded: &str) -> bool {
    if encoded.len() > MAX_IMAGE_BYTES * 4 / 3 + 16 {
        return false;
    }
    match STANDARD.decode(encoded) {
        Ok(data) => {
            !data.is_empty() && data.len() <= MAX_IMAGE_BYTES && data.starts_with(&PNG_HEADER)
        }
        Err(_) => false,
    }
}

async fn health(State(settings): State<Arc<Settings>>) -> Json<Value> {
    let configured = settings.verifier.as_ref().is_some_and(|v| v.is_file());
    Json(
        json!({"online":true,"stegosplit_verifier_ready":configured,"pairing_a_ready":settings.pair_a.as_ref().is_some_and(|p|p.is_file())}),
    )
}

async fn verify(
    State(settings): State<Arc<Settings>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if !authorized(&headers, &settings.api_token) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"authorized":false})));
    }
    let Some(verifier) = settings.verifier.as_ref().filter(|path| path.is_file()) else {
        // Missing verifier MUST NOT result in access.
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"authorized":false,"reason":"StegoSplit verifier not installed"})),
        );
    };
    let user = body
        .get("expected_user")
        .and_then(Value::as_str)
        .unwrap_or("");
    let password = body.get("password").and_then(Value::as_str).unwrap_or("");
    let png = body
        .get("client_png_base64")
        .and_then(Value::as_str)
        .unwrap_or("");
    if user.is_empty() || user.len() > 128 || password.is_empty() || !acceptable_image(png) {
        return (StatusCode::BAD_REQUEST, Json(json!({"authorized":false})));
    }
    // Inherit the configured, trusted verifier path from the server environment,
    // never from the user request. Never include passwords in command arguments.
    let mut proc = Command::new(verifier);
    proc.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    proc.env("KH_AUTH_STATE_DIR", &settings.state_dir)
        .kill_on_drop(true);
    let Ok(mut child) = proc.spawn() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"authorized":false})),
        );
    };
    let payload = json!({
        "expected_user":user, "password":password, "client_png_base64":png,
    })
    .to_string();
    let Some(mut stdin) = child.stdin.take() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"authorized":false})),
        );
    };
    if !matches!(
        timeout(Duration::from_secs(15), stdin.write_all(payload.as_bytes())).await,
        Ok(Ok(()))
    ) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"authorized":false})),
        );
    }
    drop(stdin);
    match timeout(Duration::from_secs(15), child.wait_with_output()).await {
        Ok(Ok(output)) if output.status.success() && output.stdout.len() <= 4096 => {
            let Ok(result) = serde_json::from_slice::<Value>(&output.stdout) else {
                return (StatusCode::BAD_GATEWAY, Json(json!({"authorized":false})));
            };
            let approved = result.get("authorized") == Some(&Value::Bool(true))
                && result.get("user_id").and_then(Value::as_str) == Some(user);
            (StatusCode::OK, Json(json!({"authorized":approved})))
        }
        _ => (StatusCode::BAD_GATEWAY, Json(json!({"authorized":false}))),
    }
}

/// The Rust gate owns HTTP; the reference Python process owns StegoSplit operations.
/// Both source A and supplied B are passed over a local child-process stdin pipe.
async fn reference_call(settings: &Settings, request: Value) -> Result<Value, StatusCode> {
    let Some(bridge) = &settings.python else {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    };
    let mut child = Command::new(&bridge.python_exe);
    child
        .arg(&bridge.script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env("KH_AUTH_STATE_DIR", &settings.state_dir)
        .kill_on_drop(true);
    let mut process = child.spawn().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let message = request.to_string();
    let Some(mut input) = process.stdin.take() else {
        return Err(StatusCode::BAD_GATEWAY);
    };
    if !matches!(
        timeout(Duration::from_secs(30), input.write_all(message.as_bytes())).await,
        Ok(Ok(()))
    ) {
        return Err(StatusCode::GATEWAY_TIMEOUT);
    }
    drop(input);
    let output = timeout(Duration::from_secs(60), process.wait_with_output())
        .await
        .map_err(|_| StatusCode::GATEWAY_TIMEOUT)?
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    if !output.status.success() || output.stdout.len() > 14 * 1024 * 1024 {
        return Err(StatusCode::BAD_GATEWAY);
    }
    serde_json::from_slice(&output.stdout).map_err(|_| StatusCode::BAD_GATEWAY)
}

async fn reference_admin(
    State(settings): State<Arc<Settings>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if !authorized(&headers, &settings.api_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        );
    }
    let Some(bridge) = &settings.python else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"Python reference backend disabled"})),
        );
    };
    let op = body
        .get("operation")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    if !matches!(op.as_str(), "bootstrap" | "issue" | "revoke" | "list") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"unsupported operation"})),
        );
    }
    let mut request = body;
    if op == "bootstrap" {
        let Ok(cover) = tokio::fs::read(&bridge.cover).await else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"configured source PNG unavailable"})),
            );
        };
        if cover.len() > MAX_IMAGE_BYTES {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"source PNG too large"})),
            );
        }
        request["cover_png_base64"] = json!(STANDARD.encode(cover));
    }
    match reference_call(&settings, request).await {
        Ok(result) => (StatusCode::OK, Json(result)),
        Err(status) => (status, Json(json!({"error":"reference operation failed"}))),
    }
}

/// MCP supplies master A, user-side agent supplies B. Auth decides using
/// the existing StegoSplit v0.6 registry. Never accepts a client-selected A.
async fn verify_images(
    State(settings): State<Arc<Settings>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if settings.python.is_none() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"authorized":false})),
        );
    }
    let a = body["a_png_base64"].as_str().unwrap_or("");
    let b = body["b_png_base64"].as_str().unwrap_or("");
    let user = body["expected_user"].as_str().unwrap_or("");
    let password = body["password"].as_str().unwrap_or("");
    if !acceptable_image(a)
        || !acceptable_image(b)
        || user.is_empty()
        || user.len() > 128
        || password.is_empty()
        || password.len() > 256
    {
        return (StatusCode::BAD_REQUEST, Json(json!({"authorized":false})));
    }
    match reference_call(
        &settings,
        json!({"operation":"verify",
        "a_png_base64":a,"b_png_base64":b,"expected_user":user,"password":password}),
    )
    .await
    {
        Ok(reply) if reply["authorized"] == true => (StatusCode::OK, Json(reply)),
        Ok(_) => (StatusCode::UNAUTHORIZED, Json(json!({"authorized":false}))),
        Err(status) => (status, Json(json!({"authorized":false}))),
    }
}

async fn verify_pair(
    State(settings): State<Arc<Settings>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if settings.python.is_some() {
        // Server-held A and client-presented B are both handed to the original
        // Python StegoSplit verifier. Credential registry, expiry, revocation
        // and password handling remain entirely in the reference backend.
        let image = body
            .get("b_png_base64")
            .and_then(Value::as_str)
            .unwrap_or("");
        let user = body
            .get("expected_user")
            .and_then(Value::as_str)
            .unwrap_or("");
        let password = body.get("password").and_then(Value::as_str).unwrap_or("");
        if !acceptable_image(image) || user.is_empty() || password.is_empty() {
            return (StatusCode::BAD_REQUEST, Json(json!({"authorized":false})));
        }
        let a = settings.state_dir.join("verifier").join("master.png");
        let Ok(master) = tokio::fs::read(a).await else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"authorized":false})),
            );
        };
        let request = json!({
            "operation":"verify",
            "a_png_base64": STANDARD.encode(master),
            "b_png_base64": image,
            "expected_user": user,
            "password": password
        });
        return match reference_call(&settings, request).await {
            Ok(result) if result["authorized"] == true => (StatusCode::OK, Json(result)),
            Ok(_) => (StatusCode::UNAUTHORIZED, Json(json!({"authorized":false}))),
            Err(status) => (status, Json(json!({"authorized":false}))),
        };
    }
    let Some(a) = settings.pair_a.as_ref().filter(|p| p.is_file()) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"authorized":false})),
        );
    };
    let Some(encoded) = body.get("b_png_base64").and_then(Value::as_str) else {
        return (StatusCode::BAD_REQUEST, Json(json!({"authorized":false})));
    };
    if !acceptable_image(encoded) {
        return (StatusCode::BAD_REQUEST, Json(json!({"authorized":false})));
    }
    let Ok(bytes) = STANDARD.decode(encoded) else {
        return (StatusCode::BAD_REQUEST, Json(json!({"authorized":false})));
    };
    let a = a.clone();
    let approved = tokio::task::spawn_blocking(move || pairing::verify_files(&a, &bytes))
        .await
        .unwrap_or(false);
    if approved {
        (StatusCode::OK, Json(json!({"authorized":true})))
    } else {
        (StatusCode::UNAUTHORIZED, Json(json!({"authorized":false})))
    }
}

fn ensure_token_file(path: &str, group_readable: bool) -> Result<(), Box<dyn std::error::Error>> {
    let file = std::path::Path::new(path);
    #[cfg(not(unix))]
    let _ = group_readable;
    if file.is_file() {
        return Ok(());
    }
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)?
    }
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).map_err(|e| format!("secure OS randomness unavailable: {e:?}"))?;
    let value: String = random.iter().map(|v| format!("{v:02x}")).collect();
    use std::io::Write;
    let mut handle = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(file)?;
    handle.write_all(value.as_bytes())?;
    handle.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            file,
            std::fs::Permissions::from_mode(if group_readable { 0o440 } else { 0o600 }),
        )?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path =
        env::var("KH_AUTH_API_TOKEN_FILE").unwrap_or_else(|_| "/run/secrets/auth_api_token".into());
    ensure_token_file(&path, false)?;
    if let Ok(service_file) = env::var("KH_AUTH_MCP_TOKEN_FILE") {
        ensure_token_file(&service_file, true)?;
    }
    let api_token = std::fs::read_to_string(&path)?.trim().to_string();
    if api_token.len() < 32 {
        return Err("Auth API token file must contain at least 32 characters".into());
    }
    let state_dir =
        PathBuf::from(env::var("KH_AUTH_STATE_DIR").unwrap_or_else(|_| "/auth/state".into()));
    std::fs::create_dir_all(&state_dir)?;
    let verifier = env::var("KH_AUTH_VERIFIER").ok().map(PathBuf::from);
    if verifier.as_ref().is_some_and(|p| !p.is_absolute()) {
        return Err("Verifier path must be absolute".into());
    }
    let python = match (
        env::var("KH_AUTH_PYTHON").ok(),
        env::var("KH_AUTH_BRIDGE_SCRIPT").ok(),
        env::var("KH_AUTH_COVER_PNG").ok(),
    ) {
        (None, None, None) => None,
        (Some(interpreter), Some(script), Some(cover)) => {
            let paths = [
                PathBuf::from(interpreter),
                PathBuf::from(script),
                PathBuf::from(cover),
            ];
            if paths.iter().any(|p| !p.is_absolute() || !p.is_file()) {
                return Err("Python reference paths must be existing absolute files".into());
            }
            Some(PythonBridge {
                python_exe: paths[0].clone(),
                script: paths[1].clone(),
                cover: paths[2].clone(),
            })
        }
        _ => {
            return Err(
                "Set KH_AUTH_PYTHON, KH_AUTH_BRIDGE_SCRIPT and KH_AUTH_COVER_PNG together".into(),
            );
        }
    };
    let pair_a = env::var("KH_AUTH_PAIR_A").ok().map(PathBuf::from);
    if pair_a.as_ref().is_some_and(|p| !p.is_file()) {
        return Err("Pairing A image missing".into());
    }
    let relay = match (
        env::var("KH_AUTH_MCP_A_HALF_URL").ok(),
        env::var("KH_AUTH_MCP_TOKEN_FILE").ok(),
        env::var("KH_AUTH_MASTER_SHA256_FILE").ok(),
    ) {
        (None, None, None) => None,
        (Some(url), Some(file), Some(master_file)) => {
            let master_file=PathBuf::from(master_file);
            if !master_file.is_absolute() || !master_file.is_file() {
                return Err("AuthGate master file must be an existing absolute path".into())
            }
            let contents=std::fs::read_to_string(&master_file)?;
            if contents.trim().len()!=64 || !contents.trim().bytes().all(|c|c.is_ascii_hexdigit()) {
                return Err("AuthGate master must be 64 hexadecimal characters".into());
            }
            if !url.starts_with("http://127.0.0.1:")
                && !url.starts_with("http://localhost:")
                && !url.starts_with("http://mcp:41370/")
            {
                return Err("MCP A-half endpoint must be private".into());
            }
            let token = std::fs::read_to_string(file)?.trim().to_owned();
            if token.len() < 32 {
                return Err("Auth/MCP shared service token is missing".into());
            }
            let seconds = env::var("KH_AUTH_LEASE_SECONDS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(300);
            if !(5..=3600).contains(&seconds) {
                return Err("Lease must be from 5 to 3600 seconds".into());
            }
            Some(Arc::new(relay::Relay::new(token, url, master_file, seconds)?))
        }
        _ => return Err("Set KH_AUTH_MCP_A_HALF_URL, KH_AUTH_MCP_TOKEN_FILE and KH_AUTH_MASTER_SHA256_FILE together".into()),
    };
    let settings = Arc::new(Settings {
        api_token,
        state_dir,
        verifier,
        pair_a,
        python,
        relay,
    });
    let bind = env::var("KH_AUTH_BIND").unwrap_or_else(|_| "127.0.0.1:41371".into());
    let app = Router::new()
        .route("/health", get(health))
        .route("/verify", post(verify))
        .route("/verify-pair", post(verify_pair))
        .route("/verify-images", post(verify_images))
        .route("/reference/admin", post(reference_admin))
        .route("/agent/login", post(relay::login))
        .route("/agent/next", post(relay::next))
        .route("/agent/result", post(relay::result))
        .route("/relay/command", post(relay::command))
        .layer(DefaultBodyLimit::max(28 * 1024 * 1024))
        .with_state(settings);
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    eprintln!("Auth Server listening on {bind} (verification fails closed without StegoSplit)");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn token_cannot_be_replayed_as_another_header() {
        let secret = "correct-secret-with-32-or-more-characters";
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {secret}").parse().unwrap());
        assert!(authorized(&headers, secret));
        assert!(!authorized(
            &headers,
            "another-secret-with-32-or-more-characters"
        ));
    }
    #[test]
    fn reject_non_png_and_oversized_png() {
        assert!(!acceptable_image("bad"));
        assert!(acceptable_image(&STANDARD.encode(PNG_HEADER)));
        let mut too_large = vec![0; MAX_IMAGE_BYTES + 1];
        too_large[..8].copy_from_slice(&PNG_HEADER);
        assert!(!acceptable_image(&STANDARD.encode(too_large)));
    }
}
