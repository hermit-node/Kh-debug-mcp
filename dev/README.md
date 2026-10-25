# Historical Python StegoSplit verifier (legacy reference only)

> **Legacy test harness — not the current Docker architecture.**
> Do not use the earlier data-flow instructions claiming that MCP holds B
> or that AuthGate holds A. Those instructions described an abandoned
> Windows-native test, not the agreed design.

## Current three-part ownership

- **AuthGate owns the master and authorization database.**
- **MCP owns A.**
- **User diagnostic agent owns B.**

AuthGate retrieves A from MCP, verifies against its own master and the user's
B, then controls all command routing. The master is never provisioned to
either endpoint.

The **current Docker prototype** tests this routing with a 64-character
literal master split into two 32-character halves. It does not decode
images for authentication yet. See [AUTH_SERVER.md](../AUTH_SERVER.md).

## Why the Python scripts are retained

The historical Windows Python StegoSplit v0.6 code and compiled modules
on KHzz can generate expected outputs and test vectors for a future Rust
image-based implementation. The original verifier internally stored a
`master.png` under its issuer/verifier state and had a different earlier
integration layout. That layout is not the new three-role deployment design.
No Python or `.pyd` files are packaged in the Docker containers.

`stegosplit_reference_bridge.py` is preserved as a historical development
adapter only. Do not deploy it or follow its old ownership contract.
