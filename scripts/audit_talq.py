#!/usr/bin/env python3
"""Audit route inventory against the pinned TALQ Gateway OpenAPI specification.

This is a route-coverage audit only. Matching paths does not prove TALQ conformance:
schemas, required profile operations, behavior, and live data mapping must also pass.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / "oas" / "talq-api-gateway-2-7-1-online.json"

def normalize(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "{}", path.rstrip("/") or "/")

def main() -> int:
    try:
        from app.main import app
    except Exception as exc:
        print(f"Could not import FastAPI app: {exc}", file=sys.stderr)
        return 2
    spec = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
    expected = set()
    for path, methods in spec.get("paths", {}).items():
        for method in methods:
            if method.lower() in {"get", "post", "put", "patch", "delete"}:
                expected.add((method.upper(), normalize(path)))
    actual = set()
    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None) or set()
        if not path:
            continue
        for method in methods:
            if method in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                actual.add((method, normalize(path)))
    matched = expected & actual
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    print(f"Official TALQ 2.7.1 operations: {len(expected)}")
    print(f"Path/method matches in current FastAPI app: {len(matched)}")
    print(f"Missing official operations: {len(missing)}")
    for method, path in missing:
        print(f"  MISSING {method:6} {path}")
    if extra:
        print(f"Non-TALQ/custom operations (may be valid adapter/admin routes): {len(extra)}")
        for method, path in extra:
            print(f"  CUSTOM  {method:6} {path}")
    print("\nWARNING: This checks route inventory only, not request/response schema or behavior.")
    return 1 if missing else 0

if __name__ == "__main__":
    raise SystemExit(main())
