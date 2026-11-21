"""Kinesis consumer: fan each validated record out to all three agent modes."""
import base64
import hashlib
import json
import os

import boto3
from botocore.exceptions import ClientError

from contracts.evidence import validate


def process(records, workflows, workflow_arn):
    for record in records:
        data = base64.b64decode(record["kinesis"]["data"], validate=True)
        if len(data) > 16384:
            raise ValueError("record too large")
        event = json.loads(data)
        for mode in ("single", "orchestrator", "graph"):
            payload = {"mode": mode, "events": [event]}
            validate(payload)
            # Separate executions run concurrently; retries resume partial fanout.
            name = hashlib.sha256(f"{mode}-{record['eventID']}".encode()).hexdigest()
            try:
                workflows.start_execution(stateMachineArn=workflow_arn, name=name,
                                          input=json.dumps(payload, sort_keys=True, separators=(",", ":")))
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ExecutionAlreadyExists":
                    raise


def handler(event, context):
    process(event["Records"], boto3.client("stepfunctions"),
            os.environ["WORKFLOW_ARN"])