# AuthGate-only remote relay (v0.5.2 WIP)

> **Proof of concept only. The public test half-strings are not secure authentication.**

## Ownership

| Component | Owns | Test fixture |
| --- | --- | --- |
| AuthGate | Complete 64-character SHA-256-style master value | `tests/fixtures/master.sha256` |
| MCP | First 32-character literal hex half (A) | `tests/fixtures/a-half.txt` |
| User agent | Last 32-character literal hex half (B) | `tests/fixtures/b-half.txt` |

All three fixtures contain values derived from the SHA-256 digest of the
default KernelHermit PNG, **but no runtime image decoding is performed**.
The master is installed only into AuthGate's container and is not mounted
into MCP or the user agent. All fixtures are public and thus unsuitable
for any real authentication use.

At login, the user agent submits B directly to AuthGate. AuthGate obtains
A from MCP using the privately networked and bearer-authenticated
`GET /internal/a-half` endpoint. AuthGate concatenates `A + B` and
compares it with its stored master. It repeats the check on every
command, agent poll, and result acceptance, dropping the session if
the master changes, a half mismatches, or MCP is unavailable.

```text
ChatGPT -> MCP [A] -> AuthGate [MASTER] -> User agent [B]
             ^           |
             +-----------+
           AuthGate fetches A directly from MCP
```

MCP sends commands through AuthGate's `/relay/command` endpoint, authenticated
with a separate non-public service token. The agent uses AuthGate's
`/agent/login`, `/agent/next`, and `/agent/result` endpoints.
The two Docker networks prevent the user agent from contacting MCP
directly. No direct inbound port is exposed by the user agent.

When AuthGate stops, **new relay commands fail closed**. Its old session
tokens do not survive a restart. A shell process already launched in the
user container could still finish locally.

## Future StegoSplit integration

Replace the *source of A and B data* with real decoded A/B images while
keeping AuthGate in charge of the master and all authorization.
The master must never be sent to MCP or the user agent.
Implement individual B issuance, expiry, and revocation. The original
Python v0.6 scripts in `dev/` are historical test references, **not**
the Docker runtime or a current credential ownership model.

See [README.md](README.md) for installation and WIP limitations.
