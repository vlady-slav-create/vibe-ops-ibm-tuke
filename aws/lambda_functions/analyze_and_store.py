"""AgentCore analysis and conditional S3 persistence; returns only object keys."""
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone

import boto3
from botocore.config import Config

from contracts.evidence import validate
from contracts.security_report import validate_report
from contracts.schema import validate_schema
from lambda_functions.scan_context import advance_context, pin_context, read_json, write_json


def process(events, s3, runtime, bucket, runtime_arn, mode):
    validate_schema("workflowInvocation", {"mode": mode, "events": events})
    validate({"mode": mode, "events": events})
    event = events[0]
    key = f"results/{mode}/{event['event_id']}.json"
    saved, _ = read_json(s3, bucket, key)
    if saved is None:
        payload = {"mode": mode, "events": events}
        if event["event"] == "zap_scan":
            payload["context"] = pin_context(s3, bucket, event)
        saved = analyze(events, runtime, runtime_arn, mode, payload)
        if not write_json(s3, bucket, key, saved, IfNoneMatch="*"):
            saved, _ = read_json(s3, bucket, key)
    if saved is None or saved["mode"] != mode or saved["evidence"] != events:
        raise ValueError("saved analysis does not match invocation")
    validate_report(saved["report"], events)
    if event["event"] == "zap_scan":
        advance_context(s3, bucket, event, key)
    return {"keys": [key]}


def analyze(events, runtime, runtime_arn, mode, payload):
    event = events[0]
    # ponytail: full reports can exceed workflow state limits; keep streaming I/O here
    # until runtime supports writing its response directly to S3.
    response = runtime.invoke_agent_runtime(
        agentRuntimeArn=runtime_arn, runtimeSessionId=str(uuid.uuid4()),
        contentType="application/json", accept="application/json",
        payload=json.dumps(payload).encode())
    stream = response["response"]
    try:
        body = stream.read(262145)
    finally:
        stream.close()
    if response.get("statusCode", 200) != 200 or len(body) > 262144:
        raise RuntimeError("invalid runtime response")
    result = json.loads(body)
    validate_schema("analysisResult", result)
    if result["mode"] != mode:
        raise ValueError("invalid analysis mode")
    validate_report(result["report"], events)
    saved = {"mode": mode, "event_id": event["event_id"],
             "batch_id": hashlib.sha256(event["event_id"].encode()).hexdigest(),
             "analyzed_at": datetime.now(timezone.utc).isoformat(), "evidence": events,
             "report": result["report"], "specialists": result["specialists"]}
    if "context" in payload:
        saved["context"] = payload["context"]
    saved["comparisons"] = result["comparisons"]
    return saved


def handler(event, context):
    return process(event["events"], boto3.client("s3"), boto3.client("bedrock-agentcore", config=Config(
        read_timeout=240, connect_timeout=10, retries={"mode": "standard", "max_attempts": 1})),
        os.environ["RESULTS_BUCKET"], os.environ["RUNTIME_ARN"], event["mode"])
