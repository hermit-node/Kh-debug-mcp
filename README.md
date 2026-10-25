# Kh-debug-mcp

> [!WARNING]
> **WORK IN PROGRESS (WIP) — EXPERIMENTAL PROTOTYPE**
>
> This repository is for **development and controlled testing only**. It is **not
> production-ready**, security-audited, or suitable for exposure to the public
> internet. The current image check compares **SHA-256 hashes of identical PNG
> files**; it is **not** the real one-A/many-B StegoSplit authentication scheme.
> A copied test B can be reused to authenticate.
>
> **Do not rely on this project to protect real systems or credentials.**

Rust MCP + independent Rust AuthGate + disposable Rust diagnostic agent.

### Current status

- **Working prototype:** Separate MCP, AuthGate, and optional user-agent
  containers; authenticated command relay through AuthGate; actual `/bin/sh`
  execution inside the test agent; blocked access if AuthGate is unavailable.
- **Temporary implementation:** Identical A/B PNG SHA-256 comparison, with
  short-lived in-memory sessions and HTTP request/response polling.
- **Still to implement:** Proper one-A/many-B StegoSplit verification in Rust,
  credential issuance and per-B revocation, secure remote transport, robust
  session and process cancellation, and a usable configuration/UI flow.
- **Reference implementation:** Original Python StegoSplit v0.6 routines are
  preserved under `dev/` for development and comparison; the final Docker
  images do not include those Python modules.

Passing CI demonstrates the **test scenario**, not production-grade security.

## Roles

1. **MCP (Docker)** holds **A**. ChatGPT connects to its Streamable HTTP MCP
   endpoint and requests `run_remote_powershell` (Windows) or `run_remote_shell` (Linux).
   MCP communicates with AuthGate
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

The two default Docker services run together across separate
networks: MCP is on `mcp_auth`, the optional test user is on `auth_agent`, and
AuthGate joins both. The user agent **cannot resolve or reach MCP directly** and
contacts AuthGate only. They use authenticated HTTP calls, **not yet
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
- `Dockerfile.agent`: optional **real Linux user-agent container** with /bin/sh,
  bundled B PNG, and no inbound ports; it is disabled by default.
  Run `docker compose --profile test-agent up -d --build` to launch all
  three containers for a shell-command test.
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
agent disconnection.

`.github/workflows/docker-smoke.yml` tests **all three real containers** on
GitHub's runner: MCP sends a shell script through AuthGate to the actual
diagnostic agent, the agent executes /bin/sh and returns its real stdout.
It checks Docker network separation, mismatched-B rejection, and AuthGate
shutdown. The test script is `tests/container-agent/diagnostic.sh`.

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
