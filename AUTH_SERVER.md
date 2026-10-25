# Auth Server and automatic A/B painting initialization

Run the three-service Compose stack:

```bash
docker compose up -d --build
```

**On the first startup only**, the short-lived `pairgen` container generates a mathematically
painted RGB PNG pair from operating-system random data, with a **random 64-bit pairing key**.
It embeds:
- **A.png:** Pair verifier (SHA-256 of the 64-bit key), embedded in the artwork
- **B.png:** The 64-bit key, embedded in the corresponding artwork

The two PNGs share the same mathematical brush-stroke background. The Auth Server
can check both the concealed verifier/key relationship and the rest of the image.
The images should look similar but are not byte-identical.

Pairgen exits successfully, leaving:
- `kh-debug-pair-a` volume → **Auth Server only**, mounted read-only
- `kh-debug-pair-b` volume → **MCP only**, mounted read-only
- `kh-debug-auth-state` volume → Auth Server's private configuration, including a
  random 256-bit internal API token generated automatically without a passphrase
- `kh-debug-mcp-screenshots` volume → regular `screenshots` (up to **96 PNGs, 10 MiB each**)

Neither long-running container can mount or read the other's pairing volume by
default. Pairgen can access both during initial setup; it does not stay running.

## Authentication flow

1. Auth Server loads A and starts on the private Docker network, port 41371.
2. MCP loads B and sends it to `http://auth:41371/verify-pair`.
3. Auth Server compares A and B. The MCP **does not open its HTTP listener** unless
   verification succeeds.
4. The MCP checks again before every `tools/call`; if A/B verification fails,
   command execution is denied.

The Auth Server has **no published host port**. The MCP is published only on
`127.0.0.1:41370/mcp`, for an explicitly configured secure MCP tunnel.

On restart, both images are reused unchanged. If one image is missing or tampered
with, startup fails closed. Pairgen **never silently replaces** one image or
regenerates an existing valid pair.

## Dockerfiles

- `Dockerfile` builds the MCP server, including PowerShell 7 for container-local commands.
- `Dockerfile.auth` builds the independent Rust Auth Server and the one-time
  pairing generator binary, reusing the Auth Server image for initialization.

## Limitations and security

**This is a new experimental Rust image-pair format, not an implementation of
Norm's compiled StegoSplit v0.6 algorithm.** Native StegoSplit compatibility is
not yet provided. The optional `/verify` API for a true StegoSplit verifier
remains fail-closed until that verifier is separately installed.

**64-bit keys are weaker than modern 128/256-bit authentication secrets.**
This is a requested 64-bit prototype, not hardened authentication. B is a
copyable bearer image; anyone who obtains B can attempt to present it again.
The current internal Docker HTTP handshake is not mutually authenticated or
end-to-end encrypted. Use only on a trusted Docker host and private Docker network,
and do not expose the MCP or Auth Server directly to public networks.

Regenerating credentials means intentionally removing the A and B pairing
volumes **together** and starting Compose again. Do not run `docker compose down -v`
unless you also intend to delete the screenshots and Auth Server state volumes.
Deleting either image alone makes the two components unable to authenticate.

The server can run the existing `run_powershell` tool only **inside its
container**. It does not execute commands on the underlying Docker host.

Existing CA8D or Norm Docker deployments are not modified by this repository.
