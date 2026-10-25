# Windows StegoSplit v0.6 reference bridge

Development-only compatibility harness. The final application remains Rust-only;
Python and private .pyd modules are not packaged in either Linux Docker image.

## Data flow

1. Rust Auth Server stores and owns master image A under its private state path.
2. Rust accepts client image B, username and password, loads private A, and
   sends BOTH images over a local process stdin pipe to the Python adapter.
3. The ORIGINAL paired_auth.py implementation verifies A/B differential
   encryption and the per-user credential registry, password, expiration and
   revocation. Authorization is returned as JSON, not a reusable key.
4. Rust MCP checks Auth at startup and on every PowerShell tools/call. A
   revoked B no longer grants access. The MCP never receives master A.

## Configuration (Windows native Rust binaries only)

Build using: cargo build --bin kh-debug-auth --bin kh-debug-mcp

Set absolute paths in the Auth Server environment:
- STEGOSPLIT_BACKEND_DIR : local v0.6 directory with compiled Python modules
- KH_AUTH_PYTHON : existing Python executable (e.g. venv/Scripts/python.exe)
- KH_AUTH_BRIDGE_SCRIPT : dev/stegosplit_reference_bridge.py
- KH_AUTH_COVER_PNG : assets/kernelhermit-default.png
- KH_AUTH_STATE_DIR : new, private writable directory for issuer + verifier
- KH_AUTH_API_TOKEN_FILE : file with >=32 random characters (admin bearer)
- KH_AUTH_BIND : 127.0.0.1:41371

Launch target/debug/kh-debug-auth.exe. Keep listener loopback-only for now.

POST /reference/admin with Authorization: Bearer <admin token>, JSON body:
- {"operation":"bootstrap"} provisions issuer and verifier from configured cover
- {"operation":"issue","user_id":"alice","password":"...","expires_days":30}
  issues and enrolls a separate B; response includes base64 B and credential ID
- {"operation":"list"} lists enrolled users/IDs/expiration/revocation
- {"operation":"revoke","credential_id":"32hexchars"} revokes just one B

POST /verify-pair with JSON username/password/B:
{"expected_user":"alice","password":"...","b_png_base64":"..."}
The Rust Auth Server retrieves private A, sends A+B to Python, and checks the
Python registry result. The client never chooses or submits master A.

Native Rust MCP environment:
- KH_DEBUG_AUTH_URL : http://127.0.0.1:41371/verify-pair
- KH_DEBUG_PAIR_B : absolute path to registered B.png
- KH_DEBUG_PAIR_USER : registered name
- KH_DEBUG_PAIR_PASSWORD_FILE : path to local password file for the B
Then launch target/debug/kh-debug-mcp.exe. The password file is for testing
only; replace it with a secure login flow later.

## Verified on KHzz

A temporary isolated registry successfully issued three separate B PNGs from
one A, authenticated correct passwords, denied wrong passwords, and revoked
Bob without affecting Alice or Carol. Rust MCP executed PowerShell while its
B was valid, and denied execution after B revocation. Test processes and
temporary secrets were cleaned up.

## Limitations

The original .pyd libraries run on Windows CPython 3.14, not inside the current
Linux Docker images. The Docker stack remains the earlier experimental 1:1
PNG gate; it has NOT yet been converted into this v0.6 one-A/many-B backend.
The temporary SQLite credential registry is not encrypted at rest. The
reference HTTP endpoint has no TLS or rate limiter and should not be exposed
outside a controlled loopback test environment. This is not audited security.
