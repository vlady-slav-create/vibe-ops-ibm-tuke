"""Bounded S3 reads, immutable baseline pins and monotonic context updates."""
import json

from botocore.exceptions import ClientError

from contracts.evidence import scan_time, validate
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


def latest_key(event):
    # ponytail: one fixed demo scan scope per asset; include profile/coverage ID before supporting multiple scopes.
    return f"context/v1/latest/{event['asset_id']}.json"


def check_context(context, event):
    validate({"mode": "single", "events": [event], "context": context})
    return context


def pin_context(s3, bucket, event):
    key = f"context/v1/pins/{event['event_id']}.json"
    for _ in range(5):
        pinned, _ = read_json(s3, bucket, key)
        if pinned is not None:
            return check_context(pinned, event)
        latest, _ = read_json(s3, bucket, latest_key(event))
        if latest is not None:
            validate_schema("scanContext", latest)
        previous = latest["previous"] if latest is not None else None
        if previous is not None:
            prior = previous["event"]
            validate({"mode": "single", "events": [prior]})
            if prior["asset_id"] != event["asset_id"]:
                raise ValueError("context asset mismatch")
            if previous["report_key"].rsplit("/", 1)[-1] != prior["event_id"] + ".json":
                raise ValueError("context report mismatch")
            if scan_time(prior) >= scan_time(event):
                previous = None
        context = check_context({"version": 1, "previous": previous}, event)
        if write_json(s3, bucket, key, context, IfNoneMatch="*"):
            return context
    raise RuntimeError("scan context pin contention")


def advance_context(s3, bucket, event, report_key):
    key = latest_key(event)
    candidate = {"version": 1, "previous": {"event": event, "report_key": report_key}}
    for _ in range(5):
        latest, etag = read_json(s3, bucket, key)
        if latest is not None:
            validate_schema("scanContext", latest)
            if latest["previous"] is None:
                raise ValueError("latest context missing scan")
            prior = latest["previous"]["event"]
            validate({"mode": "single", "events": [prior]})
            if prior["asset_id"] != event["asset_id"]:
                raise ValueError("context asset mismatch")
            if scan_time(prior) >= scan_time(event):
                return
        if write_json(s3, bucket, key, candidate, **({"IfMatch": etag} if latest else {"IfNoneMatch": "*"})):
            return
    raise RuntimeError("scan context update contention")