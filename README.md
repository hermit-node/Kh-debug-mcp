# Kh-debug-mcp

Rust MCP + independent Rust AuthGate + disposable Rust diagnostic agent.
This repository is experimental: the current **tunnel test uses SHA-256 equality
of A and B** instead of real StegoSplit. The original Python StegoSplit v0.6
reference integration remains in `dev/` for future authentication.

## Roles

1. **MCP (Docker)** holds **A**. ChatGPT connects to its Streamable HTTP MCP
   endpoint and requests `run_remote_powershell`. MCP communicates with AuthGate
   over a private authenticated service endpoint; it never connects directly to
   the diagnostic machine. An internal, token-protected endpoint returns only
   A's SHA-256 hash to AuthGate.
2. **AuthGate (separate Docker image)** is the sole relay between MCP and users.
   The diagnostic agent submits B directly to AuthGate. AuthGate fetches A's
   checksum from MCP, compares the two, then issues an expiring in-memory agent
   session. Before sending a job, accepting a result, or allowing another poll,
   it checks again. When AuthGate is down, remote execution is blocked.
3. **Diagnostic EXE (Windows)** holds **B**, opens outbound HTTP(S) to AuthGate,
   executes only jobs received via that approved channel, and closes when
   AuthGate stops/denies the session. There is no agent-side listening port,
   OpenSSH server, or permanent background installation.

The two Docker services stay running together on a private Docker network. The
user agent contacts AuthGate only. They use authenticated HTTP calls, **not yet
a continuously open TCP/WebSocket tunnel**.

## Docker

```bash
git clone https://github.com/hermit-node/Kh-debug-mcp.git
cd Kh-debug-mcp
docker compose up -d --build
```

The default test master A is `assets/kernelhermit-default.png`, copied
unchanged into the MCP image. The matching **test** B must be an exact copy of
this same PNG; different files are rejected. This temporary SHA-256 match is
not equivalent to real one-A/many-B StegoSplit. The original StegoSplit codec
and issuance routines have not been changed.

- MCP: `http://127.0.0.1:41370/mcp` (host loopback only)
- AuthGate: `http://127.0.0.1:41371` (host loopback only by default)
- `Dockerfile`: MCP image with PowerShell 7 inside Linux container
- `Dockerfile.auth`: independent AuthGate image
- Persistent `kh-debug-mcp-screenshots`: **96 PNG files maximum**, **10 MiB
  each**, mounted as `/data/screenshots`
- Persistent `kh-debug-auth-state`: future registry and private admin token
- Persistent `kh-debug-service-auth`: automatically generated shared internal
  service token; no user-entered master passphrase
- Containers run without host Docker socket or privileged mode

Do not expose these development HTTP endpoints to the public internet.
For a real KH24 → KHzz/CA8D deployment, give the agent an HTTPS endpoint on
a trusted private network or a TLS-protected reverse proxy. The out-of-box
loopback binding intentionally does **not** accept remote devices.

## Native Windows agent

```powershell
cargo build --release --bin kh-debug-agent
$env:KH_AGENT_AUTH_URL = 'http://127.0.0.1:41371'
$env:KH_AGENT_USER = 'testagent'
$env:KH_AGENT_B = 'C:\path\to\B.png'
.\target\release\kh-debug-agent.exe
```

For the full remote deployment, configure `KH_AGENT_AUTH_URL` to use trusted
HTTPS. Do not send B over unsecured cross-machine HTTP.

## Tests

`dev/sha_relay_smoke.ps1` tests three separate Rust processes on **one Windows
machine**, including no-AuthGate blocking, no direct MCP agent endpoint,
mismatched B rejection, authorized command routing, AuthGate shutdown and
agent disconnection. `.github/workflows/docker-smoke.yml` tests the two Docker
containers on GitHub's runner with a simulated agent job.

The original StegoSplit Python compatibility bridge and its working
one-A/many-B tests remain in `dev/stegosplit_reference_bridge.py`. That
Python reference will be used to replace the temporary SHA-256 gate later.

**Security limitations:** SHA-256 equality of identical images is only a
functional test and is not strong authentication; a copied B can be replayed.
This prototype has no per-device attestation or replay-resistant challenge
and has not been security audited. Revoking a session or stopping AuthGate
blocks new jobs and results, but cannot necessarily stop a PowerShell command
that the user machine already started. The demo should not be exposed to
untrusted networks. The local `run_powershell` MCP tool executes only *inside
the MCP container*, separate from the AuthGate-controlled remote tool.
