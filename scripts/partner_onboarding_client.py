"""Reference partner onboarding client.

Generates an RSA key pair locally, submits only the public key, polls status,
claims the one-time encrypted credential envelope, and decrypts it locally.
The private key is never transmitted to FlowSense.
"""
import base64
import json
import os
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE_URL = os.environ.get("FLOWSENSE_BASE_URL", "https://192.168.1.10:8000").rstrip("/")
PRIVATE_KEY_FILE = Path(os.environ.get("FLOWSENSE_PARTNER_PRIVATE_KEY", "partner_private_key.pem"))
STATUS_FILE = Path(os.environ.get("FLOWSENSE_PARTNER_ONBOARDING_FILE", "partner_onboarding.json"))


def call(method, path, *, body=None, headers=None):
    data = None if body is None else json.dumps(body).encode()
    request = Request(BASE_URL + path, data=data, headers={
        "Accept": "application/json",
        **({"Content-Type": "application/json"} if body is not None else {}),
        **(headers or {}),
    }, method=method)
    try:
        with urlopen(request, timeout=30) as response:
            raw = response.read()
            return json.loads(raw) if raw else {}
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {path} failed ({exc.code}): {detail}") from exc


def create_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    PRIVATE_KEY_FILE.write_bytes(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    try:
        PRIVATE_KEY_FILE.chmod(0o600)
    except OSError:
        pass
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return public_pem


def decrypt_envelope(envelope):
    private_key = serialization.load_pem_private_key(PRIVATE_KEY_FILE.read_bytes(), password=None)
    aes_key = private_key.decrypt(
        base64.b64decode(envelope["encrypted_key"]),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    plaintext = AESGCM(aes_key).decrypt(
        base64.b64decode(envelope["nonce"]),
        base64.b64decode(envelope["ciphertext"]),
        None,
    )
    return json.loads(plaintext)


def main():
    if PRIVATE_KEY_FILE.exists():
        raise SystemExit(f"{PRIVATE_KEY_FILE} already exists. Back it up or choose a new path; refusing to overwrite.")
    public_key = create_keypair()
    request_data = call("POST", "/v1/onboarding/requests", body={
        "contact_name": os.environ["PARTNER_CONTACT_NAME"],
        "email": os.environ["PARTNER_EMAIL"],
        "organization": os.environ["PARTNER_ORGANIZATION"],
        "purpose": os.environ["PARTNER_PURPOSE"],
        "client_address": os.environ["PARTNER_CLIENT_ADDRESS"],
        "public_key_pem": public_key,
    })
    state = {
        "request_id": request_data["request_id"],
        "status_token": request_data["status_token"],
        "status_url": request_data["status_url"],
    }
    STATUS_FILE.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    try:
        STATUS_FILE.chmod(0o600)
    except OSError:
        pass
    print(f"Request submitted: {state['request_id']}")
    print(f"Status token saved locally in {STATUS_FILE}; keep it private.")
    print(f"Private key saved locally in {PRIVATE_KEY_FILE}; never send it to FlowSense.")
    print("After FlowSense approves and provisions the request, run this script with --claim.")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--claim":
        state = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
        headers = {"X-Onboarding-Token": state["status_token"]}
        status = call("GET", state["status_url"], headers=headers)
        print(f"Onboarding status: {status['status']}")
        if status["status"] != "credentials_ready":
            raise SystemExit("Credentials are not ready yet.")
        result = call("POST", state["status_url"] + "/claim", headers=headers)
        credentials = decrypt_envelope(result["encrypted_credentials"])
        credential_file = Path("partner_oauth_credentials.json")
        credential_file.write_text(json.dumps(credentials, indent=2) + "\n", encoding="utf-8")
        try:
            credential_file.chmod(0o600)
        except OSError:
            pass
        print(f"Credentials decrypted and saved locally to {credential_file}. Protect this file.")
    else:
        main()
