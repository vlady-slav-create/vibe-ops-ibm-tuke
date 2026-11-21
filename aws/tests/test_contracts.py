"""Offline boundary checks: python -m tests.test_contracts."""
import copy
import hashlib
import json

from jsonschema import Draft202012Validator

from contracts.evidence import normalize, validate
from contracts.schema import SCHEMA, validate_schema


def rejected(action, value):
    try:
        action(value)
    except ValueError:
        return
    raise AssertionError("invalid input accepted")


def main():
    Draft202012Validator.check_schema(SCHEMA)
    raw = {"source": "zap-passive", "event": "zap_scan", "asset_id": "demo-portal",
           "captured_at": "2026-11-14T00:00:00Z", "baseline": None,
           "current": {"findings": [{"rule_id": "10010", "risk": 1, "confidence": 2, "instances": 3}]}}
    event = normalize(raw)
    payload = {"mode": "single", "events": [event]}
    assert validate(payload) == [event]
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    assert event["event_id"] == hashlib.sha256(canonical.encode()).hexdigest()
    assert normalize({**raw, "ignored": "secret"}) == event
    assert normalize({key: value for key, value in raw.items() if key != "baseline"}) == event
    validate_schema("workflowInvocation", payload)
    rejected(lambda value: validate_schema("workflowInvocation", value), {**payload, "events": [event, event]})
    for mode in ("single", "orchestrator", "graph"):
        assert validate({**payload, "mode": mode}) == [event]
        validate_schema("resultKeys", [f"results/{mode}/{'a' * 64}.json"])
    rejected(validate, {**payload, "mode": "unknown"})
    for field, value in (("risk", True), ("risk", 4), ("confidence", -1),
                         ("instances", 1.5), ("rule_id", "１００１０"), ("extra", "secret")):
        bad = copy.deepcopy(raw)
        bad["current"]["findings"][0][field] = value
        rejected(normalize, bad)
    for stamp in ("2026-02-30T00:00:00Z", "2026-11-14T00:00:00", "2026-11-14"):
        rejected(normalize, {**raw, "captured_at": stamp})
    bad = copy.deepcopy(raw)
    bad["current"]["findings"].append(copy.deepcopy(bad["current"]["findings"][0]))
    rejected(normalize, bad)
    bad["current"]["findings"][1]["risk"] = 2
    rejected(normalize, bad)  # Different objects, same rule ID: uniqueItems is insufficient.
    rejected(normalize, {**raw, "baseline": bad["current"]})
    bad = copy.deepcopy(payload)
    bad["events"][0]["current"]["findings"][0]["risk"] = 2
    rejected(validate, bad)  # Structurally valid, but evidence hash no longer matches.
    rejected(validate, {**payload, "extra": True})
    for text in (" ", "line\nbreak", "line\rbreak", "tab\t", "control\x00", "trailing\n"):
        rejected(lambda value: validate_schema("text", value), text)
    assert validate_schema("text", "Review cookie policy") == "Review cookie policy"
    rejected(lambda value: validate_schema("resultKeys", value), [f"results/single/{'a' * 64}.json\n"])
    network = {"source": "network-capture", "event": "http_exchange",
               "captured_at": raw["captured_at"], "scheme": "https", "tls_terminated_by_proxy": True,
               "request": {"method": "GET", "path": "/login?token=secret", "body": "secret"},
               "response": {"status_code": 200, "headers": {"cookie": "secret"}},
               "redacted_fields": ["request.body.password", "request.body.untrusted"]}
    clean = normalize(network)
    assert clean["request"] == {"method": "GET", "path": "/login"}
    assert clean["response"] == {"status_code": 200}
    assert clean["redacted_fields"] == ["request.body.password"]
    assert clean["event_id"] == hashlib.sha256(json.dumps(network, sort_keys=True).encode()).hexdigest()
    fields = ["Response.Headers.Authorization", "REQUEST.BODY.user.Password", "request.body.password",
              "request.body.untrusted", "request.body.password\n", "other.body.token"]
    assert normalize({**network, "redacted_fields": fields})["redacted_fields"] == [
        "request.body.password", "response.headers.authorization"]
    assert normalize({**network, "request": {"method": "GET", "path": "/private?token=secret"}})["request"]["path"] == "[other]"
    validate({"mode": "single", "events": [clean]})
    for field in ("request.body.untrusted", "request.body.password\n", "Request.Body.Password"):
        bad = {**clean, "redacted_fields": [field]}
        rejected(lambda value: validate_schema("event", value), bad)
        rejected(validate, {"mode": "single", "events": [bad]})
    rejected(validate, {"mode": "single", "events": [{**clean, "redacted_fields": [
        "request.body.password", "request.body.password"]}]})
    for area, extra in (("request", {"body": "secret"}), ("response", {"headers": {"cookie": "secret"}})):
        bad = {**clean, area: {**clean[area], **extra}}
        rejected(validate, {"mode": "single", "events": [bad]})
    for area, fields in (("body", ("password", "passwd", "pwd", "secret", "token", "access_token",
                                   "refresh_token", "id_token", "api_key", "apikey")),
                         ("headers", ("authorization", "cookie", "set-cookie", "x-api-key"))):
        for side in ("request", "response"):
            for field in fields:
                validate_schema("redactedField", f"{side}.{area}.{field}")
                category = f"{side}.{area}.{field}"
                assert normalize({**network, "redacted_fields": [category]})["redacted_fields"] == [category]
    rejected(validate, {"mode": "single", "events": [{**clean, "body": "secret"}]})
    tls = normalize({"source": "network-capture", "event": "tls_client_rejected",
                     "captured_at": raw["captured_at"]})
    validate({"mode": "orchestrator", "events": [tls]})
    named = {"findings": [{"rule_id": "10021", "risk": 1, "confidence": 2, "instances": 1,
                          "name": "X-Content-Type-Options Header Missing"}]}
    validate_schema("snapshot", named)
    rejected(lambda value: validate_schema("snapshot", value),
             {"findings": [{**named["findings"][0], "name": "bad<script>"}]})
    print("PASS: JSON Schemas, malformed evidence, sanitization, duplicate rules, hash integrity")


if __name__ == "__main__":
    main()