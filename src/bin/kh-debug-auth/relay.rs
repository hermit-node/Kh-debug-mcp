//! AuthGate-only relay: MCP owns A, user-side agent submits B directly here.
//! Temporary exact SHA-256 equality check, NOT real StegoSplit cryptography.
use super::{Settings, authorized};
use std::path::PathBuf;
use subtle::ConstantTimeEq;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::{Mutex, mpsc, oneshot},
    time::timeout,
};

fn valid_halves(a:&str,b:&str,master:&str)->bool {
    if a.len()!=32 || b.len()!=32 || master.len()!=64 ||
        !a.bytes().chain(b.bytes()).chain(master.bytes()).all(|c| c.is_ascii_hexdigit()) {
        return false
    }
    let assembled = format!("{}{}",a.to_ascii_lowercase(),b.to_ascii_lowercase());
    bool::from(assembled.as_bytes().ct_eq(master.to_ascii_lowercase().as_bytes()))
}
#[cfg(test)]
mod checksum_tests {
    use super::*;
    #[test]
    fn matched_halves_only() {
        let m="537b05c88c8780ce074e1cadab11089bed2966cc8adda8c7b66fa89e1aaaec3f";
        assert!(valid_halves(&m[..32],&m[32..],m));
        assert!(!valid_halves(&m[32..],&m[..32],m));
        assert!(!valid_halves(&m[..32],"ffffffffffffffffffffffffffffffff",m));
        assert!(!valid_halves(&m[..31],&m[32..],m));
    }
}
pub struct Relay {
    service_token: String,
    a_half_url: String,
    master_file: PathBuf,
    client: reqwest::Client,
    lease: Duration,
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    pending: Mutex<HashMap<u64, Pending>>,
    next_id: AtomicU64,
}
struct Session {
    user: String,
    b_half: String,
    expires: Instant,
    sender: mpsc::Sender<Job>,
    receiver: Mutex<mpsc::Receiver<Job>>,
}
struct Job {
    id: u64,
    command: String,
    seconds: u64,
    shell: String,
}
struct Pending {
    token: String,
    tx: oneshot::Sender<Value>,
}
impl Relay {
    pub fn new(
        service_token: String,
        a_half_url: String,
        master_file: PathBuf,
        lease_seconds: u64,
    ) -> Result<Self, reqwest::Error> {
        Ok(Self {
            service_token,
            a_half_url,
            master_file,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()?,
            lease: Duration::from_secs(lease_seconds),
            sessions: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        })
    }
    async fn a_half(&self) -> Option<String> {
        let resp = self.client.get(&self.a_half_url)
            .bearer_auth(&self.service_token).send().await.ok()?;
        if !resp.status().is_success() {return None}
        let body: Value = resp.json().await.ok()?;
        let part = body["a_half"].as_str()?;
        if part.len()!=32 || !part.bytes().all(|c| c.is_ascii_hexdigit()) {return None}
        Some(part.to_ascii_lowercase())
    }
    async fn check_halves(&self, b_half: &str) -> bool {
        let Some(a_half) = self.a_half().await else {return false};
        let Ok(master) = tokio::fs::read_to_string(&self.master_file).await else {return false};
        valid_halves(&a_half,b_half,master.trim())
    }
    async fn validate(&self, token: &str, session: &Session) -> bool {
        let valid = Instant::now() < session.expires
            && self.check_halves(&session.b_half).await;
        if !valid {
            self.sessions.lock().await.remove(token);
            self.pending.lock().await.retain(|_,p|p.token != token);
        }
        valid
    }
    async fn locate(&self, headers: &HeaderMap) -> Option<(String, Arc<Session>)> {
        let token = headers
            .get("authorization")?
            .to_str()
            .ok()?
            .strip_prefix("Bearer ")?;
        self.sessions
            .lock()
            .await
            .get(token)
            .cloned()
            .map(|s| (token.to_owned(), s))
    }
}
fn response(status: StatusCode, v: Value) -> (StatusCode, Json<Value>) {
    (status, Json(v))
}
fn denied() -> (StatusCode, Json<Value>) {
    response(StatusCode::UNAUTHORIZED, json!({"authorized":false}))
}
pub async fn login(
    State(state): State<Arc<Settings>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(relay) = state.relay.as_ref() else {
        return denied();
    };
    let user = body["user_id"].as_str().unwrap_or("");
    let b = body["b_half"].as_str().unwrap_or("");
    if user.is_empty() || user.len() > 128 || !relay.check_halves(b).await {
        return denied();
    }
    let mut random = [0u8; 32];
    if getrandom::fill(&mut random).is_err() {
        return response(StatusCode::INTERNAL_SERVER_ERROR, json!({}));
    }
    let token: String = random.iter().map(|c| format!("{c:02x}")).collect();
    let (tx, rx) = mpsc::channel(8);
    let mut sessions = relay.sessions.lock().await;
    if sessions
        .values()
        .any(|s| s.user == user && Instant::now() < s.expires)
    {
        return response(
            StatusCode::CONFLICT,
            json!({"error":"user already connected"}),
        );
    }
    sessions.insert(
        token.clone(),
        Arc::new(Session {
            user: user.into(),
            b_half: b.to_ascii_lowercase(),
            expires: Instant::now() + relay.lease,
            sender: tx,
            receiver: Mutex::new(rx),
        }),
    );
    response(
        StatusCode::OK,
        json!({"authenticated":true,"session_token":token,
        "lease_seconds":relay.lease.as_secs()}),
    )
}
pub async fn next(
    State(state): State<Arc<Settings>>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let Some(relay) = state.relay.as_ref() else {
        return denied();
    };
    let Some((token, session)) = relay.locate(&headers).await else {
        return denied();
    };
    if !relay.validate(&token, &session).await {
        return denied();
    }
    let mut recv = session.receiver.lock().await;
    match timeout(Duration::from_secs(1), recv.recv()).await {
        Ok(Some(job)) => response(
            StatusCode::OK,
            json!({"job_id":job.id,
            "command":job.command,"timeout_seconds":job.seconds,"shell":job.shell}),
        ),
        _ => response(StatusCode::OK, json!({"job_id":null})),
    }
}
pub async fn result(
    State(state): State<Arc<Settings>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(relay) = state.relay.as_ref() else {
        return denied();
    };
    let Some((token, session)) = relay.locate(&headers).await else {
        return denied();
    };
    if !relay.validate(&token, &session).await {
        return denied();
    }
    let Some(id) = body["job_id"].as_u64() else {
        return response(StatusCode::BAD_REQUEST, json!({}));
    };
    let Some(output) = body.get("output") else {
        return response(StatusCode::BAD_REQUEST, json!({}));
    };
    if output.to_string().len() > 130_000 {
        return response(StatusCode::PAYLOAD_TOO_LARGE, json!({}));
    }
    let mut pending = relay.pending.lock().await;
    let Some(job) = pending.remove(&id) else {
        return denied();
    };
    if job.token != token {
        pending.insert(id, job);
        return denied();
    }
    let text = output["content"][0]["text"].as_str().unwrap_or("");
    let failed = output["isError"].as_bool().unwrap_or(true);
    let _ = job
        .tx
        .send(json!({"content":[{"type":"text","text":text}],"isError":failed}));
    response(StatusCode::OK, json!({"accepted":true}))
}
pub async fn command(
    State(state): State<Arc<Settings>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(relay) = state.relay.as_ref() else {
        return denied();
    };
    if !authorized(&headers, &relay.service_token) {
        return denied();
    }
    let cmd = body["command"].as_str().unwrap_or("");
    let seconds = body["timeout_seconds"].as_u64().unwrap_or(30);
    let target = body["target_user"].as_str();
    let shell = body["shell"].as_str().unwrap_or("powershell");
    if !matches!(shell, "powershell" | "sh") {
        return response(
            StatusCode::BAD_REQUEST,
            json!({"error":"unsupported shell type"}),
        );
    }
    if cmd.is_empty() || cmd.len() > 8192 || !(1..=120).contains(&seconds) {
        return response(
            StatusCode::BAD_REQUEST,
            json!({"error":"invalid command or timeout"}),
        );
    }
    let choices: Vec<(String, Arc<Session>)> = relay
        .sessions
        .lock()
        .await
        .iter()
        .filter(|(_, s)| target.is_none_or(|u| s.user == u))
        .map(|(token, s)| (token.clone(), s.clone()))
        .collect();
    if choices.len() != 1 {
        return response(
            StatusCode::CONFLICT,
            json!({"error":"No uniquely selected authenticated agent"}),
        );
    }
    let (token, session) = choices.into_iter().next().unwrap();
    if !relay.validate(&token, &session).await {
        return denied();
    }
    let id = relay.next_id.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = oneshot::channel();
    relay.pending.lock().await.insert(
        id,
        Pending {
            token: token.clone(),
            tx,
        },
    );
    if session
        .sender
        .send(Job {
            id,
            command: cmd.into(),
            seconds,
            shell: shell.into(),
        })
        .await
        .is_err()
    {
        relay.pending.lock().await.remove(&id);
        return response(
            StatusCode::BAD_GATEWAY,
            json!({"error":"Agent disconnected"}),
        );
    }
    let output = timeout(Duration::from_secs(seconds + 15), rx).await;
    relay.pending.lock().await.remove(&id);
    if !relay.validate(&token, &session).await {
        return denied();
    }
    match output {
        Ok(Ok(v)) => response(StatusCode::OK, json!({"result":v})),
        _ => response(
            StatusCode::GATEWAY_TIMEOUT,
            json!({"error":"No agent result"}),
        ),
    }
}
