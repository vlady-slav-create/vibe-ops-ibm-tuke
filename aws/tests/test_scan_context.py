"""Offline context check: python -m tests.test_scan_context."""
import copy
import hashlib
import io
import json
import sys
from pathlib import Path
from unittest.mock import Mock

from botocore.exceptions import ClientError

from contracts.evidence import normalize, validate
from contracts.scan_comparison import compare_scans
from lambda_functions.analyze_and_store import process
from lambda_functions.scan_context import advance_context, latest_key, pin_context
from lambda_functions.security_hub import findings_for


class S3:
    def __init__(self):
        self.objects = {}
        self.conflict = None

    def get_object(self, *, Bucket, Key):
        if Key not in self.objects:
            raise ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
        body = self.objects[Key]
        return {"Body": io.BytesIO(body), "ETag": hashlib.sha256(body).hexdigest()}

    def put_object(self, *, Bucket, Key, Body, ContentType, IfNoneMatch=None, IfMatch=None):
        if self.conflict:
            callback, self.conflict = self.conflict, None
            callback(Key)
        previous = self.objects.get(Key)
        if ((IfNoneMatch == "*" and previous is not None) or
                (IfMatch is not None and (previous is None or hashlib.sha256(previous).hexdigest() != IfMatch))):
            raise ClientError({"Error": {"Code": "PreconditionFailed"}}, "PutObject")
        self.objects[Key] = Body


def scan(day, rules=()):
    return normalize({"source": "zap-passive", "event": "zap_scan", "asset_id": "demo-portal",
                      "captured_at": f"2026-11-{day:02d}T00:00:00Z", "baseline": None,
                      "current": {"findings": [{"rule_id": rule, "risk": 1, "confidence": 2, "instances": 1}
                                               for rule in rules]}})


def key(event):
    return f"results/single/{event['event_id']}.json"


def main():
    s3, bucket = S3(), "demo-bucket"
    first, second, third = scan(10, ["10010"]), scan(11, ["10020"]), scan(12)
    assert pin_context(s3, bucket, first) == {"version": 1, "previous": None}
    advance_context(s3, bucket, first, key(first))
    pinned = pin_context(s3, bucket, second)
    assert pinned["previous"]["event"] == first
    original = copy.deepcopy(second)
    delta = compare_scans([second], pinned)[0]
    assert delta["added"] == ["10020"] and delta["absent"] == ["10010"]
    assert delta["baseline_source"] == "s3-context" and second == original
    validate({"mode": "single", "events": [second], "context": pinned})

    advance_context(s3, bucket, third, key(third))
    assert pin_context(s3, bucket, second) == pinned, "retry changed pinned baseline"
    advance_context(s3, bucket, second, key(second))
    assert json.loads(s3.objects[latest_key(second)])["previous"]["event"] == third
    assert pin_context(s3, bucket, scan(9))["previous"] is None, "used future scan as baseline"

    embedded = scan(13)
    embedded["baseline"] = {"findings": []}
    embedded = normalize(embedded)
    assert compare_scans([embedded], pinned)[0]["baseline_source"] == "embedded"
    assert compare_scans([embedded], pinned)[0]["absent"] == []

    invalid = copy.deepcopy(pinned)
    invalid["previous"]["event"]["current"]["findings"] = []
    try:
        validate({"mode": "single", "events": [second], "context": invalid})
    except ValueError:
        pass
    else:
        raise AssertionError("corrupt context accepted")

    # Simulate another worker advancing latest between read and conditional write.
    s3 = S3()
    advance_context(s3, bucket, first, key(first))
    def race(pointer):
        s3.objects[pointer] = json.dumps({"version": 1, "previous": {
            "event": third, "report_key": key(third)}}).encode()
    s3.conflict = race
    advance_context(s3, bucket, second, key(second))
    assert json.loads(s3.objects[latest_key(first)])["previous"]["event"] == third

    # A competing pin wins; caller must load winner rather than its local selection.
    s3 = S3()
    def pin_race(pointer):
        s3.objects[pointer] = json.dumps(pinned).encode()
    s3.conflict = pin_race
    assert pin_context(s3, bucket, second) == pinned

    # Failure after result persistence: retry repairs pointer without new inference.
    s3, runtime = S3(), Mock()
    report = {"summary": "Empty scan; coverage unverified.", "work_items": []}
    runtime.invoke_agent_runtime.return_value = {"response": io.BytesIO(json.dumps({
        "mode": "single", "report": report, "specialists": {}, "comparisons": compare_scans([third])}).encode())}
    put = s3.put_object
    def fail_update(**kwargs):
        if "/latest/" in kwargs["Key"]:
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "PutObject")
        return put(**kwargs)
    s3.put_object = fail_update
    try:
        process([third], s3, runtime, bucket, "runtime", "single")
    except ClientError:
        pass
    else:
        raise AssertionError("context persistence failure swallowed")
    assert key(third) in s3.objects
    s3.put_object = put
    assert process([third], s3, runtime, bucket, "runtime", "single") == {"keys": [key(third)]}
    assert runtime.invoke_agent_runtime.call_count == 1
    assert latest_key(third) in s3.objects

    # Empty current scan still publishes absence, not resolution, from stored deltas.
    saved = json.loads(s3.objects[key(third)])
    context = {"version": 1, "previous": {"event": first, "report_key": key(first)}}
    saved["context"] = context
    saved["comparisons"] = compare_scans([third], context)
    findings = findings_for(saved, "123456789012", "eu-central-1", "aws", bucket)
    changes = json.loads(findings[0]["ProductFields"]["baseline_changes"])
    assert changes["absent_not_resolved"] == ["10010"]
    assert saved["evidence"][0]["baseline"] is None

    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
    from report import render
    assert "Absent rule groups: 10010" in render(saved)

    # Real process handoff across two executions, without embedded baselines.
    s3, runtime = S3(), Mock()
    def invoke(**kwargs):
        payload = json.loads(kwargs["payload"])
        validate(payload)
        return {"response": io.BytesIO(json.dumps({
            "mode": payload["mode"], "report": report, "specialists": {},
            "comparisons": compare_scans(payload["events"], payload.get("context"))}).encode())}
    runtime.invoke_agent_runtime.side_effect = invoke
    process([scan(14)], s3, runtime, bucket, "runtime", "single")
    process([scan(15)], s3, runtime, bucket, "runtime", "graph")
    payload = json.loads(runtime.invoke_agent_runtime.call_args.kwargs["payload"])
    assert payload["context"]["previous"]["event"] == scan(14)
    assert payload["events"][0]["baseline"] is None
    assert json.loads(s3.objects[f"results/graph/{scan(15)['event_id']}.json"])["comparisons"][0]["baseline_source"] == "s3-context"
    print("PASS: cross-batch context, immutable pins, hashes, baseline precedence, races, ordering, retry repair")


if __name__ == "__main__":
    main()