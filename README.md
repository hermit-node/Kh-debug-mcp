# Kh-debug-mcp

> [!WARNING]
> **WORK IN PROGRESS (WIP) — EXPERIMENTAL PROTOTYPE**
>
> This repository is for **development and controlled testing only**. It is **not
> production-ready**, security-audited, or suitable for exposure to the public
> internet. The current gate **concatenates two public 32-hex literal test
> halves** and compares them to a full 64-hex test master. It is **not**
> real StegoSplit image authentication. The test fragments can be copied.
>
> **Do not rely on this project to protect real systems or credentials.**

Rust MCP + independent Rust AuthGate + disposable Rust diagnostic agent.

**Credential ownership:** AuthGate alone holds the full master; MCP holds the
A half and the diagnostic user agent holds B. For now they are plain literal
hex strings. We will later replace these sources with image-based A/B
without changing the fail-closed relay architecture.

### Current status

- **Working prototype:** Separate MCP, AuthGate, and optional user-agent
  containers; authenticated command relay through AuthGate; actual `/bin/sh`
  execution inside the test agent; blocked access if AuthGate is unavailable.
- **Temporary implementation:** Public SHA-256-style 64-hex test master in
  AuthGate, 32-hex A half in MCP, 32-hex B half in the user agent. AuthGate
  joins the halves, compares the result against its own master, and uses
  short-lived in-memory sessions and HTTP request/response polling.
- **Still to implement:** Real image-based one-master / one-A / many-B
  StegoSplit verification in Rust,
  credential issuance and per-B revocation, secure remote transport, robust
  session and process cancellation, and a usable configuration/UI flow.
- **Reference implementation:** Historical Python StegoSplit v0.6 routines
  remain in `dev/` for test vectors and comparison only. They use a previous
  ownership arrangement and are not shipped in the Docker images.

Passing CI demonstrates the **test scenario**, not production-grade security.

## Roles

1. **MCP (Docker)** holds **A** (currently a literal 32-hex half). ChatGPT connects to its Streamable HTTP MCP
   endpoint and requests `run_remote_powershell` (Windows) or `run_remote_shell` (Linux).
   MCP communicates with AuthGate
   over a private authenticated service endpoint; it never connects directly to
   the diagnostic machine. An internal, token-protected endpoint returns only
   the A half to AuthGate.
2. **AuthGate (separate Docker image)** is the sole relay between MCP and users.
   The diagnostic agent submits B directly to AuthGate. AuthGate fetches A's
   half from MCP, joins it with B, and compares against the **full master**
   that only AuthGate holds before issuing an expiring in-memory session. Before sending a job, accepting a result, or allowing another poll,
   it checks again. When AuthGate is down, remote execution is blocked.
3. **Diagnostic EXE (Windows)** holds **B** (currently the second 32-hex half), opens outbound HTTP(S) to AuthGate,
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

The **public test-only master** is `tests/fixtures/master.sha256` (64 hex
characters). Its A and B literal halves are in `tests/fixtures/a-half.txt`
and `tests/fixtures/b-half.txt`. Docker builds place *only the corresponding
fixture* in each runtime container. These public test strings prove routing,
**not authentication security**. The lossless KernelHermit PNG stays bundled
as artwork for later real StegoSplit A/B images.

- MCP: `http://127.0.0.1:41370/mcp` (host loopback only)
- AuthGate: `http://127.0.0.1:41371` (host loopback only by default)
- `Dockerfile`: MCP image with PowerShell 7 inside Linux container
- `Dockerfile.auth`: independent AuthGate image
- `Dockerfile.agent`: optional **real Linux user-agent container** with /bin/sh,
  bundled literal B half, and no inbound ports; it is disabled by default.
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
$env:KH_AGENT_B_HALF_FILE = 'C:\path\to\b-half.txt'
.\target\release\kh-debug-agent.exe
```

For the full remote deployment, configure `KH_AGENT_AUTH_URL` to use trusted
HTTPS. Do not send B over unsecured cross-machine HTTP.

## Tests

`dev/sha_relay_smoke.ps1` tests three separate Rust processes on **one Windows
machine**, including no-AuthGate blocking, no direct MCP agent endpoint,
mismatched B-half rejection, authorized command routing, AuthGate shutdown and
agent disconnection.

`.github/workflows/docker-smoke.yml` tests **all three real containers** on
GitHub's runner: MCP sends a shell script through AuthGate to the actual
diagnostic agent, the agent executes /bin/sh and returns its real stdout.
It checks Docker network separation, mismatched-B rejection, and AuthGate
shutdown. The test script is `tests/container-agent/diagnostic.sh`.

The original StegoSplit Python compatibility bridge and its working
one-A/many-B tests remain in `dev/stegosplit_reference_bridge.py`. That
historical reference can help us implement image-based verification later,
without changing master/AuthGate, A/MCP, and B/user ownership.

**Security limitations:** The public literal half-string prototype only
tests relay plumbing and is not secure authentication. The halves can be replayed.
This prototype has no per-device attestation or replay-resistant challenge
and has not been security audited. Revoking a session or stopping AuthGate
blocks new jobs and results, but cannot necessarily stop a PowerShell command
that the user machine already started. The demo should not be exposed to
untrusted networks. The local `run_powershell` MCP tool executes only *inside
the MCP container*, separate from the AuthGate-controlled remote tool.
