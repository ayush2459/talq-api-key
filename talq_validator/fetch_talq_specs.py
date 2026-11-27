"""Download and pin the official TALQ 2.7.1 OpenAPI documents.

The Git blob IDs are pinned so a changed upstream file is rejected.
Run once while online; subsequent validation works offline.
"""
from __future__ import annotations
import hashlib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "specifications" / "2.7.1"
FILES = {
    "talq-data-model-2-7-1-online.json": (
        "https://raw.githubusercontent.com/TALQ-consortium/TALQ_specification/main/oas/talq-data-model-2-7-1-online.json",
        "7b1dc72ac3c35cdec0baa949d21adeff842852c2",
    ),
    "talq-api-gateway-2-7-1-online.json": (
        "https://raw.githubusercontent.com/TALQ-consortium/TALQ_specification/main/oas/talq-api-gateway-2-7-1-online.json",
        "6e658eff98634af941c7ce7e3087d4815e1dbcde",
    ),
    "talq-api-cms-2-7-1-online.json": (
        "https://raw.githubusercontent.com/TALQ-consortium/TALQ_specification/main/oas/talq-api-cms-2-7-1-online.json",
        "5e8ff7215f51a09ed364f360e3e8b1783a67cc90",
    ),
}

def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()

def main() -> int:
    ROOT.mkdir(parents=True, exist_ok=True)
    for name, (url, expected) in FILES.items():
        target = ROOT / name
        if target.exists():
            actual = git_blob_sha(target.read_bytes())
            if actual == expected:
                print(f"[OK] already verified: {name}")
                continue
            raise SystemExit(f"[ERROR] existing file hash mismatch: {target}; move it aside and retry")
        request = urllib.request.Request(url, headers={"User-Agent": "FlowSense-TALQ-Validator/1.0"})
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read()
        actual = git_blob_sha(data)
        if actual != expected:
            raise SystemExit(f"[ERROR] upstream content did not match pinned TALQ file: {name}")
        target.write_bytes(data)
        print(f"[OK] downloaded and verified {name} ({len(data)} bytes)")
    print("TALQ 2.7.1 specification set is ready for offline validation.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
