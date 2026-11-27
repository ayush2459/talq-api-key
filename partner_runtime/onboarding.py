"""Partner-side onboarding and credential bootstrap.

The partner generates and retains its RSA private key locally. FlowSense
administrator approval remains an explicit security gate. After approval,
this client claims the one-time encrypted credential envelope and writes the
OAuth client credentials to the same Scrypt/AES-GCM vault format used by the
existing partner test client.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import ssl
import tempfile
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

DEFAULT_URL = os.environ.get("FLOWSENSE_BASE_URL", "https://192.168.1.10:8018")


class OnboardingError(RuntimeError):
    pass


def request_json(base_url: str, path: str, method: str = "GET", *,
                 body: dict | None = None, headers: dict | None = None,
                 ca_cert: str | None = None) -> dict:
    payload = json.dumps(body).encode("utf-8") if body is not None else None
    request = Request(base_url.rstrip("/") + path, data=payload, method=method,
                      headers={"Accept": "application/json",
                               **({"Content-Type": "application/json"} if payload else {}),
                               **(headers or {})})
    context = ssl.create_default_context(cafile=ca_cert) if ca_cert else ssl.create_default_context()
    try:
        with urlopen(request, context=context, timeout=30) as response:
            raw = response.read()
            return json.loads(raw.decode("utf-8")) if raw else {}
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise OnboardingError(f"{method} {path}: HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise OnboardingError(f"Cannot connect to FlowSense: {exc.reason}") from exc


def save_private_key(path: Path, key: rsa.RSAPrivateKey, passphrase: str) -> None:
    encoded = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
        try:
            os.chmod(temp, 0o600)
        except OSError:
            pass
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def encrypt_vault(path: Path, record: dict, passphrase: str) -> None:
    salt, nonce = os.urandom(16), os.urandom(12)
    key = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(passphrase.encode("utf-8"))
    ciphertext = AESGCM(key).encrypt(nonce, json.dumps(record, separators=(",", ":")).encode(), None)
    vault = {"salt": base64.b64encode(salt).decode(),
             "nonce": base64.b64encode(nonce).decode(),
             "ciphertext": base64.b64encode(ciphertext).decode()}
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(vault, stream, indent=2)
            stream.write("\\n")
        try:
            os.chmod(temp, 0o600)
        except OSError:
            pass
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def decrypt_envelope(envelope: dict, private_key_path: Path, passphrase: str) -> dict:
    private_key = serialization.load_pem_private_key(
        private_key_path.read_bytes(), password=passphrase.encode("utf-8")
    )
    if envelope.get("algorithm") != "RSA-OAEP-256+A256GCM":
        raise OnboardingError("Unsupported credential envelope algorithm")
    aes_key = private_key.decrypt(
        base64.b64decode(envelope["encrypted_key"]),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )
    plaintext = AESGCM(aes_key).decrypt(
        base64.b64decode(envelope["nonce"]),
        base64.b64decode(envelope["ciphertext"]), None
    )
    value = json.loads(plaintext.decode("utf-8"))
    if not value.get("client_id") or not value.get("client_secret"):
        raise OnboardingError("Decrypted credential package is incomplete")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=DEFAULT_URL)
    parser.add_argument("--ca-cert")
    sub = parser.add_subparsers(dest="command", required=True)
    submit = sub.add_parser("submit", help="generate local RSA key and submit partner request")
    submit.add_argument("--contact", required=True)
    submit.add_argument("--email", required=True)
    submit.add_argument("--organization", required=True)
    submit.add_argument("--purpose", required=True)
    submit.add_argument("--client-address", required=True)
    submit.add_argument("--state-file", type=Path, default=Path("partner-onboarding.json"))
    submit.add_argument("--private-key", type=Path, default=Path("partner_onboarding_private.pem"))
    status = sub.add_parser("status", help="check approval and credential readiness")
    status.add_argument("--state-file", type=Path, default=Path("partner-onboarding.json"))
    claim = sub.add_parser("claim", help="claim credentials once and save encrypted OAuth vault")
    claim.add_argument("--state-file", type=Path, default=Path("partner-onboarding.json"))
    claim.add_argument("--private-key", type=Path, default=Path("partner_onboarding_private.pem"))
    claim.add_argument("--oauth-vault", type=Path, default=Path("partner_oauth_credentials.enc"))
    args = parser.parse_args()

    try:
        if args.command == "submit":
            if args.state_file.exists() or args.private_key.exists():
                raise OnboardingError("State/private-key file already exists; refusing to overwrite it")
            key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            key_pass = getpass.getpass("New local private-key passphrase: ")
            if len(key_pass) < 12:
                raise OnboardingError("Use a private-key passphrase of at least 12 characters")
            public_pem = key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("ascii")
            result = request_json(args.base_url, "/v1/onboarding/requests", "POST", body={
                "contact_name": args.contact, "email": args.email,
                "organization": args.organization, "purpose": args.purpose,
                "client_address": args.client_address, "public_key_pem": public_pem,
            }, ca_cert=args.ca_cert)
            save_private_key(args.private_key, key, key_pass)
            state = {"request_id": result["request_id"], "status_token": result["status_token"],
                     "status_url": result["status_url"], "private_key": str(args.private_key)}
            args.state_file.write_text(json.dumps(state, indent=2) + "\\n", encoding="utf-8")
            try:
                os.chmod(args.state_file, 0o600)
            except OSError:
                pass
            print(f"[OK] Request {result['request_id']} submitted. Await administrator approval.")
            print(f"Local state: {args.state_file}; private key: {args.private_key}")
        else:
            state = json.loads(args.state_file.read_text(encoding="utf-8"))
            request_id = int(state["request_id"])
            headers = {"X-Onboarding-Token": state["status_token"]}
            if args.command == "status":
                result = request_json(args.base_url, f"/v1/onboarding/requests/{request_id}",
                                      headers=headers, ca_cert=args.ca_cert)
                print(json.dumps(result, indent=2))
                if result.get("status") == "credentials_ready":
                    print("Run the claim command now; the one-time claim has a short expiry.")
            else:
                status_result = request_json(args.base_url, f"/v1/onboarding/requests/{request_id}",
                                             headers=headers, ca_cert=args.ca_cert)
                if status_result.get("status") != "credentials_ready":
                    raise OnboardingError(f"Credentials are not ready (status: {status_result.get('status')})")
                envelope_result = request_json(args.base_url, f"/v1/onboarding/requests/{request_id}/claim",
                                               "POST", headers=headers, ca_cert=args.ca_cert)
                private_pass = getpass.getpass("Local private-key passphrase: ")
                credentials = decrypt_envelope(envelope_result["encrypted_credentials"],
                                               args.private_key, private_pass)
                vault_pass = getpass.getpass("New OAuth vault passphrase: ")
                if len(vault_pass) < 12:
                    raise OnboardingError("Use an OAuth vault passphrase of at least 12 characters")
                encrypt_vault(args.oauth_vault, credentials, vault_pass)
                print(f"[OK] One-time credentials claimed and stored in {args.oauth_vault}")
                print("OAuth client secret was not displayed. Next create an API key using the partner client.")
        return 0
    except (OnboardingError, OSError, KeyError, ValueError) as exc:
        print(f"[ERROR] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
