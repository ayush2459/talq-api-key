"""Validate an HTTP JSON response against the official TALQ Gateway OpenAPI contract.

This checks the selected operation's response status/content-type/schema. It
does not establish semantic interoperability or official TALQ certification.
"""
from __future__ import annotations
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from jsonschema import RefResolver
from openapi_schema_validator import OAS30Validator

ROOT = Path(__file__).resolve().parent
SPEC = ROOT / "specifications" / "2.7.1" / "talq-api-gateway-2-7-1-online.json"

def resolve_pointer(document: dict[str, Any], pointer: str) -> Any:
    current: Any = document
    for token in pointer.lstrip("#/").split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        current = current[token]
    return current

def validate(method: str, path: str, status: int, content_type: str,
             payload: Any, spec_path: Path = SPEC) -> dict[str, Any]:
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    op_path = spec.get("paths", {}).get(path)
    errors: list[str] = []
    schema = None
    if not op_path:
        errors.append(f"Path {path!r} is not defined by the TALQ Gateway API")
    else:
        operation = op_path.get(method.lower())
        if not operation:
            errors.append(f"Method {method.upper()} is not defined for {path}")
        else:
            response = operation.get("responses", {}).get(str(status))
            if response is None:
                response = operation.get("responses", {}).get("default")
            if response is None:
                errors.append(f"HTTP {status} is not a documented response for {method.upper()} {path}")
            else:
                content = response.get("content", {})
                media = next((k for k in content if k.lower() == content_type.split(";")[0].strip().lower()), None)
                if media is None:
                    errors.append(f"Content-Type {content_type!r} is not documented; documented: {list(content)}")
                else:
                    schema = content[media].get("schema")
                    if schema is None:
                        errors.append("The selected response has no JSON schema")
    if schema is not None:
        resolver = RefResolver(base_uri=spec_path.resolve().as_uri(), referrer=spec)
        validator = OAS30Validator(schema, resolver=resolver)
        for error in sorted(validator.iter_errors(payload), key=lambda e: list(map(str, e.absolute_path))):
            where = "$" + "".join(f"[{p}]" if isinstance(p, int) else f".{p}" for p in error.absolute_path)
            errors.append(f"{where}: {error.message}")
    return {
        "validator": "FlowSense TALQ OpenAPI response validator",
        "specification": "TALQ 2.7.1",
        "specification_file": spec_path.name,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "method": method.upper(), "path": path, "http_status": status,
        "content_type": content_type,
        "checks": {"operation_declared": bool(op_path and op_path.get(method.lower())),
                   "response_schema_found": schema is not None,
                   "schema_valid": schema is not None and not errors},
        "passed": not errors,
        "errors": errors,
        "certification_notice": "Local OpenAPI response validation only; not TALQ Certification Tool output or certification."
    }

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--method", required=True)
    parser.add_argument("--path", required=True, help="TALQ path, e.g. /devices")
    parser.add_argument("--status", type=int, required=True)
    parser.add_argument("--content-type", default="application/json")
    parser.add_argument("--response", required=True, type=Path, help="File containing response JSON")
    parser.add_argument("--report", type=Path, help="Optional report JSON output path")
    args = parser.parse_args()
    try:
        payload = json.loads(args.response.read_text(encoding="utf-8"))
        result = validate(args.method, args.path, args.status, args.content_type, payload)
    except Exception as exc:
        print(f"[ERROR] Validation could not run: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if result["passed"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
