"""Partner-side retrieval agent: scheduled or one-shot, local-only state.

Configure jobs in partner-agent.json. Each response is validated against the
pinned TALQ Gateway OpenAPI 2.7.1 spec before it is marked accepted. Failures
are quarantined locally. Credentials never leave this process except in the
TLS-authenticated request header.
"""
from __future__ import annotations
import argparse
import base64
import json
import os
import ssl
import time
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import sys
VALIDATOR_DIR = Path(__file__).resolve().parents[1] / "talq_validator"
sys.path.insert(0, str(VALIDATOR_DIR))
from validate_response import validate

ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = Path("partner-agent.json")

def decrypt_api_key(vault_path: Path, passphrase: str) -> str:
    data = json.loads(vault_path.read_text(encoding="utf-8"))
    key = Scrypt(salt=base64.b64decode(data["salt"]), length=32, n=2**14, r=8, p=1).derive(passphrase.encode())
    plain = AESGCM(key).decrypt(base64.b64decode(data["nonce"]), base64.b64decode(data["ciphertext"]), None)
    record = json.loads(plain.decode("utf-8"))
    api_key = record.get("api_key")
    if not api_key:
        raise ValueError("Encrypted API-key vault has no api_key field")
    return api_key

def fetch(base_url: str, path: str, api_key: str, ca_cert: str | None, timeout: int) -> tuple[int, str, bytes]:
    request = Request(base_url.rstrip("/") + path, headers={"Accept": "application/json", "X-API-Key": api_key}, method="GET")
    context = ssl.create_default_context(cafile=ca_cert) if ca_cert else ssl.create_default_context()
    try:
        with urlopen(request, context=context, timeout=timeout) as response:
            return response.status, response.headers.get("Content-Type", ""), response.read()
    except HTTPError as exc:
        return exc.code, exc.headers.get("Content-Type", ""), exc.read()

def run_job(job: dict, cfg: dict, api_key: str) -> bool:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_root = Path(cfg.get("output_dir", "partner-agent-data"))
    raw_dir, quarantine_dir, reports_dir = out_root / "responses", out_root / "quarantine", out_root / "reports"
    for folder in (raw_dir, quarantine_dir, reports_dir):
        folder.mkdir(parents=True, exist_ok=True)
    method = job.get("method", "GET").upper()
    if method != "GET":
        raise ValueError("The initial partner agent supports GET jobs only; mutating TALQ operations require explicit workflows")
    path = job["path"]
    status, content_type, raw = fetch(cfg["base_url"], path, api_key, cfg.get("ca_cert"), int(cfg.get("timeout_seconds", 30)))
    filename = f"{stamp}-{job.get('name','job').replace('/','_')}"
    try:
        payload = json.loads(raw.decode("utf-8"))
        result = validate(method, path, status, content_type, payload)
    except Exception as exc:
        result = {"passed": False, "errors": [f"Response parse/validation error: {exc}"], "specification": cfg.get("talq_version", "2.7.1")}
        payload = None
    result.update({"job": job.get("name", path), "received_at": datetime.now(timezone.utc).isoformat()})
    report_path = reports_dir / f"{filename}.json"
    report_path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if result.get("passed"):
        (raw_dir / f"{filename}.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"[PASS] {method} {path} — TALQ OpenAPI response schema valid")
        return True
    (quarantine_dir / f"{filename}.json").write_bytes(raw)
    print(f"[QUARANTINE] {method} {path} — {result.get('errors')}")
    return False

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--once", action="store_true", help="run configured jobs once")
    parser.add_argument("--interval", type=int, help="override configured polling interval in seconds")
    args = parser.parse_args()
    cfg = json.loads(args.config.read_text(encoding="utf-8"))
    api_vault = Path(cfg.get("api_key_vault", "partner_api_key.enc"))
    passphrase = getpass("API-key vault passphrase: ")
    api_key = decrypt_api_key(api_vault, passphrase)
    jobs = cfg.get("jobs", [])
    if not jobs:
        raise SystemExit("No jobs configured. Add TALQ Gateway GET paths to partner-agent.json.")
    interval = args.interval or int(cfg.get("poll_interval_seconds", 300))
    if interval < 15:
        raise SystemExit("Minimum polling interval is 15 seconds.")
    print("FlowSense local partner agent started. Credentials remain local; Ctrl+C stops it.")
    while True:
        cycle_ok = True
        for job in jobs:
            try:
                cycle_ok = run_job(job, cfg, api_key) and cycle_ok
            except (OSError, ValueError, KeyError, URLError) as exc:
                cycle_ok = False
                print(f"[ERROR] {job.get('name', job.get('path','job'))}: {exc}")
        if args.once:
            return 0 if cycle_ok else 1
        time.sleep(interval)

if __name__ == "__main__":
    raise SystemExit(main())
