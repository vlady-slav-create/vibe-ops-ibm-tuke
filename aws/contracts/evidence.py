"""Cloud boundary: export facts, never captured bodies, headers or query strings."""
import hashlib
import json
from pathlib import Path

import jq

from contracts.schema import SCHEMA, validate_schema

MAX_BYTES = 16384
NORMALIZE = jq.compile(Path(__file__).with_name("normalize.jq").read_text(encoding="utf-8"), args={
    "paths": SCHEMA["$defs"]["evidencePath"]["enum"],
    "redacted_field": SCHEMA["$defs"]["redactedField"]["pattern"],
})


def scan_snapshot(value):
    """Schema validates content; standard uniqueItems cannot enforce unique rule IDs."""
    rules = [finding["rule_id"] for finding in value["findings"]]
    if len(rules) != len(set(rules)):
        raise ValueError("duplicate rule ID")
    return value


def scan_hash(event):
    # Match jq -acS output plus newline, hashed by export.sh.
    content = {key: value for key, value in event.items() if key != "event_id"}
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    return hashlib.sha256(canonical.encode()).hexdigest()


def check_scan(event):
    scan_snapshot(event["current"])
    if len(json.dumps(event).encode()) > MAX_BYTES:
        raise ValueError("scan event too large")
    if scan_hash(event) != event["event_id"]:
        raise ValueError("invalid scan event hash")


def normalize(raw):
    validate_schema("rawEvent", raw)
    result = NORMALIZE.input_value(raw).first()
    if raw["source"] == "zap-passive":
        result["event_id"] = scan_hash(result)
        check_scan(result)
    else:
        # Preserve legacy network IDs, derived from raw capture before sanitization.
        result["event_id"] = hashlib.sha256(json.dumps(raw, sort_keys=True).encode()).hexdigest()
    validate_schema("event", result)
    return result


def validate(payload):
    validate_schema("invocation", payload)
    for event in payload["events"]:
        if event["source"] == "zap-passive":
            check_scan(event)
    return payload["events"]
