# AuthGate relay

For current functionality, see [README.md](README.md).

**MCP has A. User agent has B. AuthGate has neither installed as a
credential file.** AuthGate asks MCP for A's checksum through an internal,
bearer-authenticated HTTP endpoint; it computes B's SHA-256 from the submitted
image. SHA equality admits the user-side agent to a short-lived relay session.

Flow:

```text
ChatGPT -> MCP Docker (holds A) -> AuthGate Docker -> user diagnostic EXE (holds B)
               ^                          ^
               |__________________________|
                AuthGate fetches A digest
```

User agent calls AuthGate `/agent/login`, `/agent/next`, and
`/agent/result`. MCP sends `POST /relay/command` to AuthGate using an
automatically generated private service token. AuthGate rechecks the master
checksum on login, command delivery, agent polling and result acceptance.
It drops the session on mismatch, unavailable MCP or lease expiration.

If AuthGate stops or is deleted, MCP's remote PowerShell tool **fails closed**.
The diagnostic EXE has no inbound network listener and loses access if AuthGate
stops. Restarting AuthGate does not restore old in-memory session tokens; the
agent must authenticate again.

Docker binds AuthGate to host loopback by default; private HTTPS/TLS ingress
is needed for real access from KH24 or another computer. Never publish the
plain-HTTP test port to an untrusted network.

This is a temporary **checksum-only** test. Genuine StegoSplit A/B images
differ at the pixel level and therefore won't pass this SHA equality gate.
The existing Windows Python StegoSplit v0.6 implementation was separately
verified for one A/many independent B credentials and is preserved in dev.
It will replace SHA equality after the three-role tunnel tests are complete.

The default artwork is a lossless PNG. No WebP, JPEG, recompression, resizing
or post-embedding pixel modification is performed.

`docker compose down` retains volumes. `docker compose down -v` destroys
screenshots and internal Auth/MCP state and tokens.
