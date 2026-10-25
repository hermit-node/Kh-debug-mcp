# Kh-debug-mcp

**A minimal Rust MCP server that lets ChatGPT run PowerShell on the Windows computer hosting it.**

The server exposes one MCP tool: `run_powershell(command, timeout_seconds)`.

## Build (Windows / Rust)

```powershell
cargo test
cargo build --release
.\target\release\kh-debug-mcp.exe
```

It listens on `http://127.0.0.1:41370/mcp`. The endpoint uses MCP Streamable HTTP,
with JSON-RPC `initialize`, `notifications/initialized`, `tools/list`, and `tools/call`.

## Connect ChatGPT

ChatGPT cannot reach your computer's localhost by itself. Set up an **OpenAI Secure
MCP Tunnel** on this Windows computer, pointing to `http://127.0.0.1:41370/mcp`.
Then add the tunnel as a custom MCP connection in ChatGPT Plugins **if your
account/workspace supports custom MCP plugins with write/execute tools**.

Official setup: https://developers.openai.com/api/docs/guides/tools-connectors-mcp
ChatGPT plugin setup: https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt

Without the tunnel, this server can be tested from the same machine:
```powershell
$body = '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
Invoke-RestMethod -Uri http://127.0.0.1:41370/mcp -Method Post -ContentType application/json -Body $body
```

## Safety

- Binds **only to 127.0.0.1**; it is intentionally **not** an internet-exposed endpoint.
- Connect through a controlled secure tunnel; do not add public port forwarding.
- Arbitrary PowerShell code runs with the **same privileges as the Windows account
  running the EXE**. Never launch it as Administrator unless necessary and intended.
- No auto-start, Windows service, SSH, pairing credentials, permanent remote access,
  or files copied to Norm or CA8D.
- Command length 8 KiB; 30-second default timeout (max 120); response truncated to
  64 KiB. This is an initial functional prototype, not a hardened multi-user service.
- Stopping the EXE stops the local MCP server.

## Scope

This is only the **ChatGPT → MCP → PowerShell** foundation. It does not contain
the later machine-to-machine tunnel or StegoSplit authentication. Those are not
required to test a simple MCP server on the hosting PC.