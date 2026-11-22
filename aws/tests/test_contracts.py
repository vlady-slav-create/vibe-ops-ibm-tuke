"""Offline boundary checks: python -m tests.test_contracts."""
import copy
import hashlib
import json
from pathlib import Path

import jq

from jsonschema import Draft202012Validator

from contracts.evidence import normalize, validate
from contracts.schema import SCHEMA, validate_schema
from contracts.security_report import expected_items, validate_report
from agentcore_runtime.report_output import SecurityReport, report_from
from unittest.mock import Mock


def rejected(action, value):
    try:
        action(value)
    except ValueError:
        return
    raise AssertionError("invalid input accepted")


def main():
    Draft202012Validator.check_schema(SCHEMA)
    raw = {"source": "zap-passive", "event": "zap_scan", "asset_id": "demo-portal",
           "captured_at": "2026-11-14T00:00:00Z",
           "current": {"findings": [{"rule_id": "10010", "risk": 1, "confidence": 2, "instances": 3}]}}
    event = normalize(raw)
    payload = {"mode": "single", "events": [event]}
    assert validate(payload) == [event]
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    assert event["event_id"] == hashlib.sha256(canonical.encode()).hexdigest()
    assert normalize({**raw, "ignored": "secret"}) == event
    exposed = normalize({**raw, "exposure": {"http_requests": 4, "https_requests": 2}})
    assert exposed["exposure"]["http_requests"] == 4 and validate({"mode": "single", "events": [exposed]})
    rejected(normalize, {**raw, "exposure": {"http_requests": 4, "https_requests": 2, "url": "x"}})
    # Severity heuristics stay out of the event; agents infer impact from ZAP findings.
    rejected(normalize, {**raw, "exposure": {"http_requests": 4, "https_requests": 2, "http_secret_posts": 1}})
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
    rejected(validate, {**payload, "events": [{**event, "baseline": None}]})  # Sanitized events carry no baseline.
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
    rich = {"findings": [{**named["findings"][0], "paths": ["/login"], "schemes": ["http"], "params": ["token"]}]}
    validate_schema("snapshot", rich)
    for key, value in (("paths", ["/secret"]), ("schemes", ["ftp"]), ("params", ["a b"]), ("params", ["deadbeefcafe01"]), ("params", ["k12345"]), ("paths", ["/login?x=1"])):
        rejected(lambda v: validate_schema("snapshot", v), {"findings": [{**rich["findings"][0], key: value}]})
    rejected(lambda value: validate_schema("snapshot", value),
             {"findings": [{**named["findings"][0], "name": "bad<script>"}]})
    # Citation failures name the failed check (never model text); required list is deterministic.
    scan = {"event": "zap_scan", "event_id": "a" * 64, "current": {"findings": [
        {"rule_id": "10021"}, {"rule_id": "10035"}, {"rule_id": "10036"}]}}
    assert expected_items([scan]) == {("a" * 64, "security-headers"): {"10021", "10035"}, ("a" * 64, "other"): {"10036"}}
    item = {"event_id": "a" * 64, "group": "other", "rule_ids": ["10036"], "title": "t", "severity": "LOW",
            "rationale": "r", "owner_role": "o", "observation": "b", "hypothesis": "h", "fix": "f",
            "retest": "t", "limitations": "l"}
    for bad, reason in (({**item, "rule_ids": ["10036", "10112"]}, "rule_ids differ"),
                        ({**item, "group": "cookie-hardening"}, "unknown event_id or group")):
        try:
            validate_report({"summary": "s", "work_items": [bad]}, [scan])
        except ValueError as exc:
            assert reason in str(exc), exc
        else:
            raise AssertionError("bad citation accepted")
    # Model-supplied rule_ids are overwritten from evidence; a wrong group still fails.
    wrong = SecurityReport(summary="s", work_items=[{**item, "rule_ids": ["10036", "10112"]},
        {**item, "group": "security-headers", "rule_ids": ["10021"]}])
    done = report_from(Mock(stop_reason="end_turn", structured_output=wrong), [scan])
    assert [i["rule_ids"] for i in done["work_items"]] == [["10036"], ["10021", "10035"]]
    # ZAP export keeps allowlisted paths, schemes and param names; never values, queries or evidence.
    report = {"site": [{"@name": "http://server:8080", "alerts": [{"pluginid": "10024", "riskcode": "2",
        "confidence": "2", "count": "2", "name": "Sensitive Information in URL", "instances": [
            {"uri": "http://server:8080/api/grades?token=s3cr3t", "param": "token", "evidence": "s3cr3t"},
            {"uri": "http://server:8080/private/x?a=b", "param": "s3cr3t", "evidence": "s3cr3t"},
            {"uri": "http://server:8080/login?k=leakvalue", "param": "leakvalue"},
            {"uri": "http://server:8080/login", "param": "a1b2c3d4e5f6a7b8"},
            {"uri": "http://server:8080/login", "param": "key20261114"}]}]}]}
    har = {"log": {"entries": [{"request": {"method": "POST", "url": "http://server:8080/login",
                                            "postData": {"text": '{"password": "s3cr3t"}'}}}]}}
    export = jq.compile((Path(__file__).parents[2] / "zap" / "findings.jq").read_text(),
                        args={"captured_at": raw["captured_at"], "har": [har], "tls": [{"tls_client_rejected": 2}], "tls_scan": []})
    scanned = normalize(export.input_value(report).first())
    for leak in ("s3cr3t", "private", "leakvalue", "a1b2c3d4e5f6a7b8", "key20261114"):
        assert leak not in json.dumps(scanned), leak
    assert scanned["current"]["findings"][0] | {"paths": ["/api/grades", "/login", "[other]"], "schemes": ["http"], "params": ["token"]} \
        == scanned["current"]["findings"][0]
    assert scanned["exposure"] == {"http_requests": 1, "https_requests": 0, "tls_client_rejected": 2}
    # sslyze summary: allowlisted booleans and protocol/cipher names only; raw certificate fields never leave.
    tls_scan = json.loads((Path(__file__).parent / "sslyze_sample.json").read_text())
    export = jq.compile((Path(__file__).parents[2] / "zap" / "findings.jq").read_text(),
                        args={"captured_at": raw["captured_at"], "har": [], "tls": [], "tls_scan": [tls_scan]})
    tls_event = normalize(export.input_value(report).first())
    assert tls_event["tls_config"]["self_signed"] is True and tls_event["tls_config"]["chain_trusted_all_stores"] is False
    assert {"TLS 1.2", "TLS 1.3"} >= set(tls_event["tls_config"]["protocols_accepted"]) and "TLS 1.0" not in tls_event["tls_config"]["protocols_accepted"]
    assert ("tls", {"0"}) in [(g, r) for (_, g), r in expected_items([tls_event]).items()]
    for leak in ("CN=server", "2027-11-22", "server.crt", "fingerprint_sha256", "public_bytes"):
        assert leak not in json.dumps(tls_event), leak
    rejected(normalize, {**raw, "tls_config": {"scanned": True, "self_signed": "yes", "expired": False, "chain_trusted_all_stores": False,
                                               "protocols_accepted": [], "accepted_ciphers": []}})
    # Failed or incomplete scan emits no tls_config (unknown, never safe).
    unscanned = {**tls_scan, "server_scan_results": [{**tls_scan["server_scan_results"][0], "connectivity_status": "ERROR"}]}
    failed = jq.compile((Path(__file__).parents[2] / "zap" / "findings.jq").read_text(),
                        args={"captured_at": raw["captured_at"], "har": [], "tls": [], "tls_scan": [unscanned]})
    assert "tls_config" not in failed.input_value(report).first()
    print("PASS: JSON Schemas, malformed evidence, sanitization, duplicate rules, hash integrity")


if __name__ == "__main__":
    main()