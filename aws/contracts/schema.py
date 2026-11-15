"""Shared Draft 2020-12 validation, independent of HTTP or AWS transport."""
import json
from datetime import datetime
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

SCHEMA = json.loads(Path(__file__).with_name("schemas.json").read_text(encoding="utf-8"))
FORMATS = FormatChecker()


@FORMATS.checks("date-time", raises=ValueError)
def timestamp(value):
    # stdlib calendar validation; schema pattern enforces RFC 3339 syntax and timezone.
    return not isinstance(value, str) or datetime.fromisoformat(value.upper().replace("Z", "+00:00")).tzinfo is not None


VALIDATORS = {
    name: Draft202012Validator({"$ref": f"#/$defs/{name}", "$defs": SCHEMA["$defs"]}, format_checker=FORMATS)
    for name in SCHEMA["$defs"]
}


def validate_schema(name, value):
    try:
        VALIDATORS[name].validate(value)
    except ValidationError as exc:
        # Do not include instance values: raw evidence can contain secrets.
        path = "/".join(map(str, exc.absolute_path)) or "root"
        raise ValueError(f"invalid {name} at {path}: {exc.validator}") from None
    return value