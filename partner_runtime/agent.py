"""Partner-side runtime with local OAuth refresh and safe API-key rotation."""
from __future__ import annotations
import argparse
import base64
import json
import os
import ssl
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from getpass import getpass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

VALIDATOR_DIR = Path(__file__).resolve().parents[1] / "talq_validator"
sys.path.insert(0, str(VALIDATOR_DIR))
from validate_response import validate

DEFAULT_CONFIG = Path("partner-agent.json")


def decrypt_vault(path: Path, passphrase: str) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    key = Scrypt(salt=base64.b64decode(data["salt"]), length=32, n=2**14, r=8, p=1).derive(passphrase.encode("utf-8"))
    plain = AESGCM(key).decrypt(base64.b64decode(data["nonce"]), base64.b64decode(data["ciphertext"]), None)
    record = json.loads(plain.decode("utf-8"))
    if not isinstance(record, dict):
        raise ValueError(f"Invalid encrypted vault structure: {path}")
    return record


def encrypt_vault(path: Path, record: dict, passphrase: str) -> None:
    salt, nonce = os.urandom(16), os.urandom(12)
    key = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(passphrase.encode("utf-8"))
    ciphertext = AESGCM(key).encrypt(nonce, json.dumps(record, separators=(",", ":")).encode(), None)
    data = {"salt": base64.b64encode(salt).decode(), "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()}
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2)
            stream.write("\\n")
        try:
            os.chmod(temp, 0o600)
        except OSError:
            pass
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def call(base_url: str, path: str, method: str, *, headers=None, body=None, ca_cert=None, timeout=30):
    data = body
    request = Request(base_url.rstrip("/") + path, data=data, method=method,
                      headers={"Accept": "application/json", **(headers or {})})
    context = ssl.create_default_context(cafile=ca_cert) if ca_cert else ssl.create_default_context()
    try:
        with urlopen(request, context=context, timeout=timeout) as response:
            raw = response.read()
            return response.status, response.headers.get("Content-Type", ""), raw
    except HTTPError as exc:
        return exc.code, exc.headers.get("Content-Type", ""), exc.read()


def json_call(base_url: str, path: str, method: str, *, headers=None, body=None, ca_cert=None, timeout=30):
    status, content_type, raw = call(base_url, path, method, headers=headers, body=body, ca_cert=ca_cert, timeout=timeout)
    try:
        result = json.loads(raw.decode("utf-8")) if raw else {}
    except Exception as exc:
        raise ValueError(f"{method} {path} returned non-JSON HTTP {status}") from exc
    if status < 200 or status >= 300:
        raise RuntimeError(f"{method} {path} failed with HTTP {status}: {result}")
    return result


def oauth_token(cfg: dict, oauth: dict) -> str:
    client_id, secret = oauth.get("client_id"), oauth.get("client_secret")
    if not client_id or not secret:
        raise ValueError("OAuth vault must contain client_id and client_secret")
    basic = base64.b64encode(f"{client_id}:{secret}".encode()).decode("ascii")
    form = urlencode({"grant_type": "client_credentials"}).encode("ascii")
    result = json_call(cfg["base_url"], "/oauth/token", "POST",
        headers={"Authorization": "Basic " + basic, "Content-Type": "application/x-www-form-urlencoded"},
        body=form, ca_cert=cfg.get("ca_cert"), timeout=int(cfg.get("timeout_seconds", 30)))
    if not result.get("access_token"):
        raise RuntimeError("OAuth token endpoint did not return access_token")
    return result["access_token"]


def verify_key(cfg: dict, key: str) -> bool:
    status, _, raw = call(cfg["base_url"], "/auth/verify", "GET",
        headers={"X-API-Key": key}, ca_cert=cfg.get("ca_cert"), timeout=int(cfg.get("timeout_seconds", 30)))
    if status != 200:
        return False
    try:
        return json.loads(raw.decode("utf-8")).get("authenticated") is True
    except Exception:
        return False


def maybe_rotate_key(cfg: dict, api_record: dict, api_pass: str, bearer: str) -> dict:
    expires = api_record.get("expires_at")
    if not expires:
        print("[INFO] API-key vault has no expiry metadata; automatic rotation skipped.")
        return api_record
    expiry = datetime.fromisoformat(expires.replace("Z", "+00:00"))
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    threshold = int(cfg.get("rotate_before_days", 7))
    if expiry - datetime.now(timezone.utc) > timedelta(days=threshold):
        return api_record
    old_id = api_record.get("key_id")
    if not isinstance(old_id, int):
        raise ValueError("Cannot rotate: API-key vault has no integer key_id")
    auth = {"Authorization": "Bearer " + bearer}
    rotated = json_call(cfg["base_url"], f"/integrations/me/api-keys/{old_id}/rotate", "POST",
        headers=auth, ca_cert=cfg.get("ca_cert"), timeout=int(cfg.get("timeout_seconds", 30)))
    new_key, new_id = rotated.get("api_key"), rotated.get("key_id")
    if not new_key or not isinstance(new_id, int) or rotated.get("previous_key_id") != old_id:
        raise RuntimeError("Key rotation response incomplete; old local vault retained")
    if not verify_key(cfg, new_key):
        raise RuntimeError("Replacement key did not verify; old local vault retained")
    replacement = {"api_key": new_key, "key_id": new_id, "expires_at": rotated.get("expires_at")}
    encrypt_vault(Path(cfg.get("api_key_vault", "partner_api_key.enc")), replacement, api_pass)
    json_call(cfg["base_url"], f"/integrations/me/api-keys/{old_id}/retire", "POST",
        headers=auth, ca_cert=cfg.get("ca_cert"), timeout=int(cfg.get("timeout_seconds", 30)))
    if verify_key(cfg, api_record["api_key"]):
        raise RuntimeError("Old key remains valid after retirement; manual investigation required")
    print(f"[OK] API key rotated, verified, stored locally and old key retired (new key ID {new_id}).")
    return replacement


def run_job(job: dict, cfg: dict, api_key: str) -> bool:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    root = Path(cfg.get("output_dir", "partner-agent-data"))
    responses, quarantine, reports = root / "responses", root / "quarantine", root / "reports"
    for folder in (responses, quarantine, reports):
        folder.mkdir(parents=True, exist_ok=True)
    method = job.get("method", "GET").upper()
    if method != "GET":
        raise ValueError("Only read-only GET jobs are supported by the polling agent")
    path = job["path"]
    status, content_type, raw = call(cfg["base_url"], path, method,
        headers={"X-API-Key": api_key}, ca_cert=cfg.get("ca_cert"),
        timeout=int(cfg.get("timeout_seconds", 30)))
    filename = f"{stamp}-{job.get('name', 'job').replace('/', '_')}"
    try:
        payload = json.loads(raw.decode("utf-8"))
        result = validate(method, path, status, content_type, payload)
    except Exception as exc:
        payload = None
        result = {"passed": False, "errors": [f"Response parse/validation error: {exc}"],
                  "specification": cfg.get("talq_version", "2.7.1")}
    result.update({"job": job.get("name", path), "received_at": datetime.now(timezone.utc).isoformat()})
    (reports / f"{filename}.json").write_text(json.dumps(result, indent=2) + "\\n", encoding="utf-8")
    if result.get("passed"):
        (responses / f"{filename}.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\\n", encoding="utf-8")
        print(f"[PASS] {method} {path} — TALQ OpenAPI schema valid")
        return True
    (quarantine / f"{filename}.json").write_bytes(raw)
    print(f"[QUARANTINE] {method} {path} — {result.get('errors')}")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=int)
    args = parser.parse_args()
    cfg = json.loads(args.config.read_text(encoding="utf-8"))
    api_path = Path(cfg.get("api_key_vault", "partner_api_key.enc"))
    oauth_path = Path(cfg.get("oauth_vault", "partner_oauth_credentials.enc"))
    api_pass = getpass("API-key vault passphrase: ")
    oauth_pass = getpass("OAuth vault passphrase: ")
    api_record = decrypt_vault(api_path, api_pass)
    oauth_record = decrypt_vault(oauth_path, oauth_pass)
    if not api_record.get("api_key"):
        raise SystemExit("API-key vault is missing api_key")
    jobs = cfg.get("jobs", [])
    if not jobs:
        raise SystemExit("No GET jobs configured in partner-agent.json")
    interval = args.interval or int(cfg.get("poll_interval_seconds", 300))
    if interval < 15:
        raise SystemExit("Minimum polling interval is 15 seconds")
    print("Local partner runtime active. OAuth access tokens are reacquired each cycle; Ctrl+C stops it.")
    while True:
        cycle_ok = True
        try:
            bearer = oauth_token(cfg, oauth_record)
            api_record = maybe_rotate_key(cfg, api_record, api_pass, bearer)
        except (OSError, ValueError, RuntimeError, KeyError, URLError) as exc:
            print(f"[CREDENTIAL ERROR] {exc}")
            cycle_ok = False
        if cycle_ok:
            for job in jobs:
                try:
                    cycle_ok = run_job(job, cfg, api_record["api_key"]) and cycle_ok
                except (OSError, ValueError, RuntimeError, KeyError, URLError) as exc:
                    cycle_ok = False
                    print(f"[JOB ERROR] {job.get('name', job.get('path', 'job'))}: {exc}")
        if args.once:
            return 0 if cycle_ok else 1
        time.sleep(interval)


if __name__ == "__main__":
    raise SystemExit(main())
