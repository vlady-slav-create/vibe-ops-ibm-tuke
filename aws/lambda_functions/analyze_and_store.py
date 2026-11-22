"""AgentCore analysis and conditional S3 persistence; returns only object keys."""
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from contracts.evidence import validate
from contracts.security_report import validate_report
from contracts.schema import validate_schema


def read_json(s3, bucket, key):
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in {"NoSuchKey", "404"}:
            return None, None
        raise
    stream = response["Body"]
    try:
        body = stream.read(1048577)
    finally:
        stream.close()
    if len(body) > 1048576:
        raise ValueError("stored context or result too large")
    return json.loads(body), response["ETag"]


def write_json(s3, bucket, key, value, **condition):
    try:
        s3.put_object(Bucket=bucket, Key=key, ContentType="application/json",
                      Body=json.dumps(value).encode(), **condition)
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] in {"PreconditionFailed", "412", "ConditionalRequestConflict", "409"}:
            return False
        raise


def process(events, s3, runtime, bucket, runtime_arn, mode):
    validate_schema("workflowInvocation", {"mode": mode, "events": events})
    validate({"mode": mode, "events": events})
    event = events[0]
    key = f"results/{mode}/{event['event_id']}.json"
    saved, _ = read_json(s3, bucket, key)
    if saved is None:
        payload = {"mode": mode, "events": events}
        saved = analyze(events, runtime, runtime_arn, mode, payload)
        if not write_json(s3, bucket, key, saved, IfNoneMatch="*"):
            saved, _ = read_json(s3, bucket, key)
    if saved is None or saved["mode"] != mode or saved["evidence"] != events:
        raise ValueError("saved analysis does not match invocation")
    validate_report(saved["report"], events)
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
    return saved


def handler(event, context):
    return process(event["events"], boto3.client("s3"), boto3.client("bedrock-agentcore", config=Config(
        read_timeout=240, connect_timeout=10, retries={"mode": "standard", "max_attempts": 1})),
        os.environ["RESULTS_BUCKET"], os.environ["RUNTIME_ARN"], event["mode"])
