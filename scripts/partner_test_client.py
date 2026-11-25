"""Cross-platform FlowSense partner test client.

Commands:
  retrieve  - decrypt the local API-key vault and fetch synthetic test fixtures.
  verify    - verify the API key without printing it.
  rotate    - use the OAuth vault to issue, verify, store, and then retire a key.

Secrets stay on the partner machine. No secret values are printed.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import tempfile
from getpass import getpass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

DEFAULT_BASE_URL = "https://192.168.1.10:8018"
DEFAULT_API_VAULT = "partner_api_key.enc"
DEFAULT_OAUTH_VAULT = "partner_oauth_credentials.enc"


class PartnerClientError(RuntimeError):
    pass


def derive_key(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(
        passphrase.encode("utf-8")
    )


def decrypt_vault(path: Path, passphrase: str) -> dict[str, Any]:
    try:
        vault = json.loads(path.read_text(encoding="utf-8"))
        key = derive_key(passphrase, base64.b64decode(vault["salt"]))
        plaintext = AESGCM(key).decrypt(
            base64.b64decode(vault["nonce"]),
            base64.b64decode(vault["ciphertext"]),
            None,
        )
        value = json.loads(plaintext.decode("utf-8"))
    except FileNotFoundError as exc:
        raise PartnerClientError(f"Vault not found: {path}") from exc
    except Exception as exc:
        raise PartnerClientError(
            f"Could not decrypt {path}. Check the passphrase and vault file."
        ) from exc
    if not isinstance(value, dict):
        raise PartnerClientError(f"Unexpected data format in {path}")
    return value


def encrypt_vault(path: Path, value: dict[str, Any], passphrase: str) -> None:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(passphrase, salt)
    ciphertext = AESGCM(key).encrypt(
        nonce, json.dumps(value, separators=(",", ":")).encode("utf-8"), None
    )
    payload = {
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write beside the destination and atomically replace it after a complete write.
    fd, temporary_name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2)
            stream.write("\n")
        try:
            os.chmod(temporary_name, 0o600)
        except OSError:
            pass
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


class FlowSenseClient:
    def __init__(self, base_url: str, ca_cert: str | None, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        ca = ca_cert or os.environ.get("SSL_CERT_FILE")
        try:
            self.ssl_context = (
                ssl.create_default_context(cafile=ca)
                if ca else ssl.create_default_context()
            )
        except (OSError, ssl.SSLError) as exc:
            raise PartnerClientError(f"Could not load trusted CA certificate: {exc}") from exc

    def call(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> dict[str, Any]:
        request = Request(
            self.base_url + path,
            data=body,
            headers={"Accept": "application/json", **(headers or {})},
            method=method,
        )
        try:
            with urlopen(
                request, context=self.ssl_context, timeout=self.timeout
            ) as response:
                raw = response.read()
                return json.loads(raw.decode("utf-8")) if raw else {}
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise PartnerClientError(
                f"{method} {path} failed with HTTP {exc.code}: {detail}"
            ) from exc
        except URLError as exc:
            raise PartnerClientError(
                f"Cannot connect to {self.base_url}: {exc.reason}"
            ) from exc

    def expect_status(self, method: str, path: str, expected: int, *, headers=None) -> None:
        request = Request(self.base_url + path, headers=headers or {}, method=method)
        try:
            with urlopen(
                request, context=self.ssl_context, timeout=self.timeout
            ) as response:
                status = response.status
        except HTTPError as exc:
            status = exc.code
        except URLError as exc:
            raise PartnerClientError(f"Cannot connect to FlowSense: {exc.reason}") from exc
        if status != expected:
            raise PartnerClientError(
                f"Expected HTTP {expected} from {method} {path}; received HTTP {status}"
            )


def api_headers(api_key: str) -> dict[str, str]:
    return {"X-API-Key": api_key}


def verify_api_key(client: FlowSenseClient, api_key: str) -> dict[str, Any]:
    result = client.call("GET", "/auth/verify", headers=api_headers(api_key))
    if result.get("authenticated") is not True:
        raise PartnerClientError("API key verification did not return authenticated=true")
    print(
        "[OK] API key authenticated:",
        result.get("organization", "partner"),
        "| client:",
        result.get("client_address", "not reported"),
        "| key ID:",
        result.get("api_key_id", "not reported"),
    )
    return result


def retrieve_test_data(client: FlowSenseClient, api_key: str) -> None:
    verify_api_key(client, api_key)
    result = client.call("GET", "/v1/test-data", headers=api_headers(api_key))
    if result.get("environment") != "testing":
        raise PartnerClientError("Refusing response: server did not identify testing environment")
    if result.get("source") != "synthetic_test_fixture":
        raise PartnerClientError("Refusing response: source is not the synthetic test fixture")
    devices = result.get("devices")
    if not isinstance(devices, list) or not devices or not all(
        item.get("isSynthetic") is True for item in devices
    ):
        raise PartnerClientError("Response did not contain explicitly synthetic device records")
    print("\n[OK] Synthetic FlowSense test data retrieved")
    print(json.dumps(result, indent=2, ensure_ascii=False))


def oauth_access_token(
    client: FlowSenseClient, credentials: dict[str, Any]
) -> str:
    client_id = credentials.get("client_id")
    client_secret = credentials.get("client_secret")
    if not client_id or not client_secret:
        raise PartnerClientError("OAuth vault is missing client_id or client_secret")
    basic = base64.b64encode(
        f"{client_id}:{client_secret}".encode("utf-8")
    ).decode("ascii")
    form = urlencode({"grant_type": "client_credentials"}).encode("ascii")
    result = client.call(
        "POST",
        "/oauth/token",
        headers={
            "Authorization": "Basic " + basic,
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body=form,
    )
    token = result.get("access_token")
    if not token:
        raise PartnerClientError("OAuth server did not return an access token")
    print("[OK] OAuth access token issued; token value kept private")
    return token


def rotate_api_key(
    client: FlowSenseClient,
    api_vault_path: Path,
    oauth_vault_path: Path,
) -> None:
    old_passphrase = getpass("Existing API-key vault passphrase: ")
    old_record = decrypt_vault(api_vault_path, old_passphrase)
    old_key = old_record.get("api_key")
    old_id = old_record.get("key_id")
    if not old_key or not isinstance(old_id, int):
        raise PartnerClientError(
            "API-key vault must contain api_key and integer key_id. No changes made."
        )

    oauth_passphrase = getpass("OAuth credential vault passphrase: ")
    credentials = decrypt_vault(oauth_vault_path, oauth_passphrase)
    bearer = oauth_access_token(client, credentials)
    auth = {"Authorization": "Bearer " + bearer}

    rotated = client.call(
        "POST", f"/integrations/me/api-keys/{old_id}/rotate", headers=auth
    )
    new_key = rotated.get("api_key")
    new_id = rotated.get("key_id")
    previous_id = rotated.get("previous_key_id")
    if not new_key or not isinstance(new_id, int) or previous_id != old_id:
        raise PartnerClientError(
            "Rotation response was incomplete. Existing local vault was not changed."
        )

    # Verify the new credential before replacing the local vault or retiring the old key.
    verify_api_key(client, new_key)
    new_record = {
        "key_id": new_id,
        "api_key": new_key,
        "expires_at": rotated.get("expires_at"),
    }
    encrypt_vault(api_vault_path, new_record, old_passphrase)
    print(f"[OK] Replacement key {new_id} saved in encrypted local vault")

    # Retire only after the new key is safely stored and has passed authentication.
    client.call(
        "POST", f"/integrations/me/api-keys/{old_id}/retire", headers=auth
    )
    print(f"[OK] Previous key {old_id} retired")

    # Confirm old key is rejected and new key remains accepted.
    client.expect_status("GET", "/auth/verify", 401, headers=api_headers(old_key))
    print("[OK] Previous key now receives HTTP 401")
    verify_api_key(client, new_key)
    print("[DONE] API-key rotation and retirement test passed")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Cross-platform FlowSense partner test client; secrets remain local."
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("FLOWSENSE_BASE_URL", DEFAULT_BASE_URL),
        help="Partner API base URL (default: %(default)s)",
    )
    parser.add_argument(
        "--ca-cert",
        default=None,
        help="Path to FlowSense CA/server certificate; alternatively set SSL_CERT_FILE",
    )
    parser.add_argument(
        "--api-vault",
        default=os.environ.get("FLOWSENSE_PARTNER_API_KEY_VAULT", DEFAULT_API_VAULT),
        help="Encrypted API-key vault path",
    )
    parser.add_argument(
        "--oauth-vault",
        default=os.environ.get("FLOWSENSE_PARTNER_CREDENTIAL_VAULT", DEFAULT_OAUTH_VAULT),
        help="Encrypted OAuth credential vault path (rotate only)",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("retrieve", help="verify API key and retrieve synthetic test data")
    sub.add_parser("verify", help="verify the API key without retrieving data")
    sub.add_parser("rotate", help="rotate, verify, store, and retire the previous API key")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        client = FlowSenseClient(args.base_url, args.ca_cert)
        api_vault_path = Path(args.api_vault)
        if args.command in {"retrieve", "verify"}:
            passphrase = getpass("API-key vault passphrase: ")
            record = decrypt_vault(api_vault_path, passphrase)
            api_key = record.get("api_key")
            if not api_key:
                raise PartnerClientError("API-key vault does not contain api_key")
            if args.command == "retrieve":
                retrieve_test_data(client, api_key)
            else:
                verify_api_key(client, api_key)
        elif args.command == "rotate":
            rotate_api_key(client, api_vault_path, Path(args.oauth_vault))
        return 0
    except PartnerClientError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled; no further actions taken.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
