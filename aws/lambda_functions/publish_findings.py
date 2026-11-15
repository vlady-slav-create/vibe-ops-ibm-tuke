"""Render saved analysis; Step Functions owns Security Hub delivery and retries."""
import json
import os

import boto3

from contracts.schema import validate_schema
from lambda_functions.security_hub import findings_for


def process(keys, s3, bucket, account, region, partition):
    validate_schema("resultKeys", keys)
    response = s3.get_object(Bucket=bucket, Key=keys[0])
    try:
        body = response["Body"].read(1048577)
    finally:
        response["Body"].close()
    if len(body) > 1048576:
        raise ValueError("saved analysis too large")
    findings = findings_for(json.loads(body), account, region, partition, bucket)
    result = {"Findings": findings, "expected_count": len(findings)}
    # Leave space for SDK response/metadata within Step Functions' 256 KiB limit.
    if len(json.dumps(result).encode()) > 240 * 1024:
        raise ValueError("rendered findings too large for workflow")
    return result


def handler(event, context):
    return process(event["keys"], boto3.client("s3"), os.environ["RESULTS_BUCKET"], os.environ["ACCOUNT_ID"],
                   os.environ["AWS_REGION"], os.environ["AWS_PARTITION"])