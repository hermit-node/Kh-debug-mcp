# Kh-debug-mcp

A small Rust Streamable HTTP MCP server for ChatGPT, with a PowerShell tool and persistent storage for **up to 96 PNG images**.

## Docker (Linux containers)

```bash
git clone https://github.com/hermit-node/Kh-debug-mcp.git
cd Kh-debug-mcp
docker compose up -d --build
```

- Docker host endpoint: `http://127.0.0.1:41370/mcp`
- Health check: `http://127.0.0.1:41370/health`
- Persistent Docker volume: `kh-debug-mcp-screenshots`, mounted at `/data/screenshots`.
- Each PNG is limited to 10 MiB. Images are not recompressed or modified.
- The **96-image maximum** is enforced by the Rust image-store implementation.
- Tools: `run_powershell`, `list_images`, `save_image` (base64 PNG), `delete_image`.
- Docker starts automatically after reboots, unless you explicitly stop the service.
- No Windows OpenSSH service, Docker socket mount, or host administrator access is required.

**Important:** PowerShell in Docker executes **inside the Linux container**, not on the physical Docker host. It uses PowerShell 7 (`pwsh`), which does not supply Windows-only cmdlets. To diagnose the Windows host itself, use the native Windows EXE below instead. The Docker image requires a supported Linux/CPU architecture and has not been validated on every Docker platform.

## Separate Auth Server Dockerfile

Compose automatically launches a short-lived pairing generator, the independent
**Rust Auth Server** (built using `Dockerfile.auth`) and the MCP. It creates a
mathematical brush-stroke **A/B PNG pair with a random 64-bit key** on first run;
A remains with Auth and B remains with MCP. Both are required for the MCP to
start and accept command tools. To build Auth separately:

```bash
docker build -f Dockerfile.auth -t kh-debug-auth:local .
```

The PNG pairing is a new experimental Rust implementation and **not compatible
with the Windows-only StegoSplit v0.6 binary codec**. Existing StegoSplit
verification remains a separate optional integration. The 64-bit key is
weaker than modern authentication keys and this is not a production-grade
access-control system.

See [AUTH_SERVER.md](AUTH_SERVER.md) for provisioning, separated persistent
pairing volumes, verification flow, and security limitations. No master
passphrase is required.

## Native Windows executable

```powershell
cargo test
cargo build --release
.\target\release\kh-debug-mcp.exe
```

Native Windows PowerShell runs in the context of the Windows user who starts the EXE. On native Windows the server defaults to `127.0.0.1:41370`; images default to a local `./screenshots` directory.

## ChatGPT integration

The server supports MCP Streamable HTTP (`initialize`, `ping`, `tools/list`, `tools/call`). Connect ChatGPT through a **Secure MCP Tunnel** to the local `http://127.0.0.1:41370/mcp` endpoint. Never expose this command-execution service directly to the public Internet.

When a trusted proxy forwards a different `Host` header, configure `KH_DEBUG_ALLOWED_HOSTS` as a comma-separated allowlist of the exact host-and-port values. Configure `KH_DEBUG_BIND` only when different in-container binding is necessary. Compose intentionally publishes to **host loopback only**.

## Security and storage

This is a basic MCP experiment, **not a hardened public service**. It has no application-level authentication. Allow access only from a trusted local interface and trusted tunnel; other containers sharing the same Docker network may also be able to reach it. It executes PowerShell with the permissions of its process. Do not use `privileged` mode or mount the host's Docker socket.

The image volume persists when the container is recreated. `docker compose down` preserves it; `docker compose down -v` destroys it. PNGs are stored as raw files, not encrypted at rest, so do not place sensitive StegoSplit credentials there until you have a suitable protection and authorization design.

No Norm or existing CA8D stack files are modified by this repo. No automatic system SSH setup, authentication pairing, or secondary-computer tunnel is included.
