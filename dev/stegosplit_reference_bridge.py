"""Development-only adapter to the ORIGINAL StegoSplit v0.6 compiled Python backend.
Rust owns network access. This process runs for one JSON request and exits.
Never import this in production Rust/Docker builds; port the algorithms later.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
import time

BACKEND = Path(os.environ["STEGOSPLIT_BACKEND_DIR"]).resolve(strict=True)
sys.path.insert(0, str(BACKEND))
import authority
import paired_auth

MAX_PNG = 10 * 1024 * 1024
ALIAS = re.compile(r"^[a-z][a-z0-9]{0,8}$")
USER = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def image_from_request(payload, name):
    value = payload.get(name)
    if not isinstance(value, str) or len(value) > 14_000_000:
        raise ValueError("missing or excessive image data")
    raw = base64.b64decode(value, validate=True)
    if len(raw) > MAX_PNG or not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("invalid PNG")
    return raw


def execute(request):
    root = Path(os.environ["KH_AUTH_STATE_DIR"]).resolve()
    issuer, verifier = root / "issuer", root / "verifier"
    account = os.environ.get("KH_STEGO_ACCOUNT", "kh")
    if not ALIAS.fullmatch(account):
        raise ValueError("invalid account alias")

    op = request.get("operation")
    if op == "bootstrap":
        if issuer.exists() or verifier.exists():
            raise ValueError("already initialized; refusing to replace master A")
        png = image_from_request(request, "cover_png_base64")
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="kh-cover-") as d:
            cover = Path(d) / "cover.png"
            cover.write_bytes(png)
            authority.initialize_issuer(str(cover), str(issuer), server_account=account)
            authority.provision_verifier(str(issuer), str(verifier), server_account=account)
        return {"initialized": True, "master_a_sha256": hashlib.sha256((verifier / "master.png").read_bytes()).hexdigest()}

    if not (verifier / "master.png").is_file():
        raise ValueError("registered master A missing")

    if op == "issue":
        name, password = request.get("user_id"), request.get("password")
        if not isinstance(name, str) or not USER.fullmatch(name):
            raise ValueError("invalid user name")
        if not isinstance(password, str) or not password or len(password) > 256:
            raise ValueError("invalid password")
        days = request.get("expires_days", 30)
        if type(days) is not int or not (1 <= days <= 3650):
            raise ValueError("invalid expiration")
        clients = root / "clients"
        clients.mkdir(exist_ok=True)
        # Distinct unique filename, even if a user is reissued a credential.
        import uuid
        identity = uuid.uuid4().hex
        client_path = clients / (identity + ".png")
        manifest_path = clients / (identity + ".enroll.json")
        issued = authority.issue_user(str(issuer), name, str(client_path), password,
            str(manifest_path), expires_days=days, server_account=account)
        authority.enroll(str(verifier), str(manifest_path))
        return {"issued": True, "credential_id": issued["credential_id"],
                "user_id": name, "b_png_base64": base64.b64encode(client_path.read_bytes()).decode("ascii")}

    if op == "verify":
        a = image_from_request(request, "a_png_base64")
        b = image_from_request(request, "b_png_base64")
        registered_a = (verifier / "master.png").read_bytes()
        if not __import__("hmac").compare_digest(hashlib.sha256(a).digest(), hashlib.sha256(registered_a).digest()):
            return {"authorized": False}
        user, password = request.get("expected_user"), request.get("password")
        if not isinstance(user, str) or not USER.fullmatch(user):
            return {"authorized": False}
        if not isinstance(password, str) or not password:
            return {"authorized": False}
        with tempfile.TemporaryDirectory(prefix="kh-verify-") as d:
            b_path = Path(d) / "incoming.png"
            b_path.write_bytes(b)
            result = paired_auth.verify(verifier, b_path, password, expected_user=user)
        return {"authorized": bool(result.get("authorized")),
                **({"user_id":result["user_id"],"credential_id":result["credential_id"]}
                    if result.get("authorized") else {})}

    if op == "revoke":
        cid = request.get("credential_id")
        if not isinstance(cid, str) or not re.fullmatch(r"[0-9a-f]{32}", cid):
            raise ValueError("invalid credential_id")
        paired_auth.revoke(verifier, cid)
        # Prevent a future manifest replay. The verifier is the authority for access.
        return {"revoked": True, "credential_id": cid}

    if op == "list":
        with sqlite3.connect(verifier / paired_auth.DB) as db:
            records = db.execute("SELECT cid,uid,expires,revoked FROM credentials ORDER BY uid,cid").fetchall()
        return {"credentials": [{"credential_id":cid,"user_id":uid,
            "expires":exp,"revoked":bool(rev) or exp <= time.time()}
            for cid,uid,exp,rev in records]}

    raise ValueError("unknown operation")


def main():
    try:
        request = json.load(sys.stdin)
        if not isinstance(request, dict):
            raise ValueError("expected object")
        print(json.dumps(execute(request), separators=(",", ":")))
    except Exception as exc:
        # Do not print user-supplied secrets or tracebacks into the API response.
        print(json.dumps({"error":type(exc).__name__,"authorized":False}, separators=(",", ":")))
        sys.exit(1)

if __name__ == "__main__":
    main()
