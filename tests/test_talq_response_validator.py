import json
from pathlib import Path

from talq_validator.validate_response import validate


def make_spec(path: Path) -> Path:
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Fixture", "version": "1.0"},
        "paths": {
            "/devices": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "OK",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["count", "devices"],
                                        "properties": {
                                            "count": {"type": "integer"},
                                            "devices": {"type": "array", "items": {"type": "object"}},
                                        },
                                    }
                                }
                            },
                        }
                    }
                }
            }
        },
    }
    path.write_text(json.dumps(spec), encoding="utf-8")
    return path


def test_valid_response_passes(tmp_path):
    spec = make_spec(tmp_path / "spec.json")
    result = validate("GET", "/devices", 200, "application/json", {"count": 0, "devices": []}, spec)
    assert result["passed"] is True


def test_missing_required_property_fails(tmp_path):
    spec = make_spec(tmp_path / "spec.json")
    result = validate("GET", "/devices", 200, "application/json", {"devices": []}, spec)
    assert result["passed"] is False
    assert any("count" in error for error in result["errors"])


def test_undocumented_path_fails_closed(tmp_path):
    spec = make_spec(tmp_path / "spec.json")
    result = validate("GET", "/private-route", 200, "application/json", {}, spec)
    assert result["passed"] is False
    assert "not defined" in result["errors"][0]
