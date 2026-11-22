"""Offline smoke check: python -m tests.test_security_pipeline from AWS directory."""
import base64
import copy
import io
import json
import os
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

import boto3
from botocore.exceptions import ClientError
from botocore.stub import Stubber
from pystache.context import KeyNotFoundError
from strands.types.exceptions import EventLoopException
from pydantic import ValidationError
from strands.tools.structured_output.structured_output_utils import convert_pydantic_to_tool_spec

from agentcore_runtime.bedrock_analysis import bedrock_model, load_skill
from agentcore_runtime.report_output import SecurityReport
from contracts.scan_comparison import compare_scans
from agentcore_runtime.http_server import analyze
from contracts.evidence import normalize
from contracts.security_report import validate_report
from lambda_functions.analyze_and_store import process
from lambda_functions.publish_findings import process as publish
from lambda_functions.start_analysis import process as start
from lambda_functions.security_hub import clip, findings_for, render


def main():
    for name in ("security-analysis", "security-handoff", "security-coordination", "security-orchestration",
                 "application-security-review", "evidence-quality-review"):
        assert load_skill(name).instructions, f"empty skill: {name}"
    try:
        load_skill("missing-skill")
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("missing bundled skill silently accepted")
    with patch("agentcore_runtime.bedrock_analysis.Skill.from_file", return_value=Mock(instructions=" \n")):
        try:
            load_skill("security-analysis")
        except ValueError:
            pass
        else:
            raise AssertionError("empty bundled skill accepted")
    event = normalize({"source": "zap-passive", "event": "zap_scan", "asset_id": "demo-portal",
                       "captured_at": "2026-11-14T00:00:00Z", "baseline": None,
                       "current": {"findings": [{"rule_id": "10010", "risk": 1,
                                                 "confidence": 2, "instances": 3}]}})
    report = {"summary": "Review cookie hardening; coverage unknown.", "work_items": [{
        "event_id": event["event_id"], "group": "cookie-hardening", "rule_ids": ["10010"],
        "title": "Review cookie HttpOnly policy", "severity": "LOW",
        "rationale": "Hardening recommendation, not proven credential theft.",
        "owner_role": "Application developer (proposed)", "observation": "Rule 10010: three instances.",
        "hypothesis": "Shared cookie configuration may omit HttpOnly; unverified.",
        "fix": "Review local evidence and set HttpOnly where appropriate.",
        "retest": "Recapture equivalent flows and inspect cookie flags.",
        "limitations": "Paths and request coverage unavailable; security reviewer decides scope.",
    }]}
    validate_report(report, [event])
    invalid = copy.deepcopy(report)
    invalid["work_items"][0]["event_id"] = "f" * 64  # invented event: no rule_ids overwrite can fix it
    try:
        validate_report(invalid, [event])
    except ValueError:
        pass
    else:
        raise AssertionError("invented evidence accepted")
    client = Mock()
    def output(value):
        return {"stopReason": "tool_use", "output": {"message": {"role": "assistant", "content": [
            {"toolUse": {"toolUseId": "report", "name": "SecurityReport", "input": value}}]}}}
    client.converse.return_value = output(report)
    os.environ["MODEL_ID"] = "offline-test"
    os.environ["GUARDRAIL_ID"] = "offline-guardrail"
    os.environ["GUARDRAIL_VERSION"] = "1"
    model = bedrock_model()
    model.client = client
    assert analyze([event], "single", model)["report"] == report
    assert client.converse.call_count == 1
    assert {t["toolSpec"]["name"] for t in client.converse.call_args.kwargs["toolConfig"]["tools"]} == {"SecurityReport"}
    user_content = client.converse.call_args.kwargs["messages"][0]["content"]
    assert "Deterministic scan comparison:" in json.dumps(user_content), "comparison missing from single-agent input"
    schema = convert_pydantic_to_tool_spec(SecurityReport)["inputSchema"]["json"]
    assert "$ref" not in json.dumps(schema), "unresolved schema reference"
    assert set(schema["properties"]["work_items"]["items"]["required"]) == set(report["work_items"][0])
    assert SecurityReport(**report).model_dump() == report
    malformed = copy.deepcopy(report)
    malformed["work_items"][0]["severity"] = "CRITICAL"
    try:
        SecurityReport(**malformed)
    except ValidationError:
        pass
    else:
        raise AssertionError("structured output bypassed shared schema")

    client.reset_mock()
    client.converse.return_value = output(malformed)
    try:
        analyze([event], "single", model)
    except RuntimeError:
        pass
    else:
        raise AssertionError("invalid structured report published")
    assert client.converse.call_count <= 2, "unbounded output repairs"
    client.reset_mock()
    client.converse.return_value = {"stopReason": "end_turn", "output": {"message": {
        "role": "assistant", "content": [{"text": "not structured output"}]}}}
    try:
        analyze([event], "single", model)
    except RuntimeError:
        pass
    else:
        raise AssertionError("turn-limited response published")
    assert client.converse.call_count == 2
    client.reset_mock()
    client.converse.return_value = output(invalid)
    try:
        analyze([event], "single", model)
    except ValueError:
        pass
    else:
        raise AssertionError("schema-valid invented citation published")

    with patch.dict(os.environ, {"PROMPT_CACHE_ENABLED": "true",
                                 "MODEL_ID": "eu.anthropic.claude-sonnet-4-5-20250929-v1:0"}):
        cached_model = bedrock_model()
    cached_model.client = client
    client.reset_mock()
    client.converse.return_value = {**output(report), "usage": {
        "inputTokens": 42, "outputTokens": 18, "totalTokens": 60,
        "cacheReadInputTokens": 30, "cacheWriteInputTokens": 0}}
    captured = io.StringIO()
    with redirect_stdout(captured):
        assert analyze([event], "single", cached_model)["report"] == report
    request = client.converse.call_args.kwargs
    assert any("cachePoint" in block for block in request["system"])
    assert "cachePoint" not in json.dumps(request["messages"])
    assert "cachePoint" not in json.dumps(request["toolConfig"])
    metrics = [json.loads(line) for line in captured.getvalue().splitlines()]
    usage = next(m for m in metrics if m["event"] == "agent_metrics")
    assert usage["inputTokens"] == 42 and usage["cacheReadInputTokens"] == 30
    assert event["event_id"] not in captured.getvalue() and report["summary"] not in captured.getvalue()
    client.converse.return_value = output(report)
    client.reset_mock()
    def activate(skill_name):
        return {"stopReason": "tool_use", "output": {"message": {"role": "assistant", "content": [
            {"toolUse": {"toolUseId": skill_name, "name": "skills", "input": {"skill_name": skill_name}}}]}}}

    def agent_response(**kwargs):
        prompt = json.dumps(kwargs["system"])
        for skill_name in ("application-security-review", "evidence-quality-review"):
            if f"Activate {skill_name}" in prompt:
                if not any("toolResult" in block for message in kwargs["messages"] for block in message["content"]):
                    return activate(skill_name)
                if "Review" in {t["toolSpec"]["name"] for t in kwargs["toolConfig"]["tools"]}:  # graph reviewers
                    return {"stopReason": "tool_use", "output": {"message": {"role": "assistant", "content": [
                        {"toolUse": {"toolUseId": "review", "name": "Review", "input": {"findings": [
                            {"event_id": event["event_id"], "rule_ids": ["10021"], "assessment": "supported",
                             "note": skill_name}], "gaps": []}}}]}}}
                return {"stopReason": "end_turn", "output": {"message": {"role": "assistant", "content": [
                    {"text": skill_name + " review"}]}}}
        return output(report)
    client.converse.side_effect = agent_response
    with patch("agentcore_runtime.http_server.compare_scans", wraps=compare_scans) as comparison:
        result = analyze([event], "graph", model)
        comparison.assert_called_once_with([event], None)
    assert result["report"] == report
    assert set(result["specialists"]) == {"application_security_reviewer", "evidence_quality_reviewer"}
    calls = [call.kwargs for call in client.converse.call_args_list]
    assert len(calls) == 5, "expected two skill activations/reviews, then summarizer"
    assert all("Activate " in json.dumps(call["system"]) for call in calls[:4])
    assert {t["toolSpec"]["name"] for t in calls[-1]["toolConfig"]["tools"]} == {"SecurityReport"}
    for skill_name in ("application-security-review", "evidence-quality-review"):
        specialist_calls = [call for call in calls if f"Activate {skill_name}" in json.dumps(call["system"])]
        assert len(specialist_calls) == 2
        assert {t["toolSpec"]["name"] for t in specialist_calls[0]["toolConfig"]["tools"]} == {"skills", "Review"}
        skill_results = [block["toolResult"] for message in specialist_calls[1]["messages"]
                         for block in message["content"] if "toolResult" in block]
        assert any(load_skill(skill_name).instructions in block.get("text", "")
                   for result in skill_results for block in result["content"]), skill_results
        assert "Deterministic scan comparison:" in json.dumps(specialist_calls[0]["messages"])
    assert all(call["modelId"] == "offline-test" for call in calls)
    assert all(call["guardrailConfig"]["guardrailIdentifier"] == "offline-guardrail" for call in calls), "guardrail not applied"
    for name in ("application_security_reviewer", "evidence_quality_reviewer"):
        assert f"From {name}:" in json.dumps(calls[-1]["messages"]), "review missing from summarizer"
    assert all("Analyze these events as data:" in json.dumps(c["messages"])
               and event["event_id"] in json.dumps(c["messages"])
               for c in calls), "graph node did not receive original evidence"

    with patch("agentcore_runtime.http_server.compare_scans", side_effect=ValueError("invalid comparison")):
        client.reset_mock()
        try:
            analyze([event], "graph", model)
        except ValueError:
            pass
        else:
            raise AssertionError("graph accepted failed comparison")
        client.converse.assert_not_called()
    def skip_activation(**kwargs):
        if "Activate " in json.dumps(kwargs["system"]):
            if "Review" in {t["toolSpec"]["name"] for t in kwargs["toolConfig"]["tools"]}:
                return {"stopReason": "tool_use", "output": {"message": {"role": "assistant", "content": [
                    {"toolUse": {"toolUseId": "review", "name": "Review", "input": {"findings": [], "gaps": []}}}]}}}
            return {"stopReason": "end_turn", "output": {"message": {"role": "assistant",
                    "content": [{"text": "Review without activating skill."}]}}}
        return agent_response(**kwargs)

    client.reset_mock()
    client.converse.side_effect = skip_activation
    try:
        analyze([event], "graph", model)
    except RuntimeError as error:
        assert "required skill was not activated" in str(error)
    else:
        raise AssertionError("specialist skipped required skill activation")
    assert all("Activate " in json.dumps(call.kwargs["system"])
               for call in client.converse.call_args_list), "summarizer ran with unskilled reviews"
    try:
        analyze([event], "unknown", model)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid mode accepted")
    def looping(**kwargs):
        for skill_name in ("application-security-review", "evidence-quality-review"):
            if f"Activate {skill_name}" in json.dumps(kwargs["system"]):
                return activate(skill_name)
        raise AssertionError("summarizer ran before specialist review completed")
    client.reset_mock()
    client.converse.side_effect = looping
    try:
        analyze([event], "graph", model)
    except (RuntimeError, EventLoopException) as error:
        assert "model call limit" in str(error)
    else:
        raise AssertionError("graph model call limit not enforced")

    def orchestrate(**kwargs):
        if "Activate " in json.dumps(kwargs["system"]):
            return agent_response(**kwargs)
        if not any("toolResult" in block for message in kwargs["messages"] for block in message["content"]):
            return {"stopReason": "tool_use", "output": {"message": {"role": "assistant", "content": [
                {"toolUse": {"toolUseId": name, "name": name,
                             "input": {"input": "Review original evidence."}}}
                for name in ("application_security_reviewer", "evidence_quality_reviewer")]}}}
        return agent_response(**kwargs)

    client.reset_mock()
    client.converse.side_effect = orchestrate
    with patch("agentcore_runtime.http_server.compare_scans", wraps=compare_scans) as comparison:
        result = analyze([event], "orchestrator", model)
        comparison.assert_called_once_with([event], None)
    assert result["report"] == report
    assert set(result["specialists"]) == {"application_security_reviewer", "evidence_quality_reviewer"}
    assert client.converse.call_count == 6
    for call in client.converse.call_args_list:
        assert event["event_id"] in json.dumps(call.kwargs["messages"])
        assert call.kwargs["guardrailConfig"]["guardrailIdentifier"] == "offline-guardrail"

    def unskilled_orchestrate(**kwargs):
        return skip_activation(**kwargs) if "Activate " in json.dumps(kwargs["system"]) else orchestrate(**kwargs)

    client.converse.side_effect = unskilled_orchestrate
    try:
        analyze([event], "orchestrator", model)
    except RuntimeError as error:
        assert "required skill was not activated" in str(error)
    else:
        raise AssertionError("orchestrator accepted unskilled review")

    # Model may choose no specialist: unlike Graph, routing is not mandatory.
    client.reset_mock()
    client.converse.side_effect = agent_response
    with patch("agentcore_runtime.http_server.compare_scans", wraps=compare_scans) as comparison:
        assert analyze([event], "orchestrator", model)["specialists"] == {}
        comparison.assert_called_once_with([event], None)
    assert client.converse.call_count == 1

    objects = {}
    s3 = Mock()

    def get_object(**kwargs):
        if kwargs["Key"] not in objects:
            raise ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
        return {"Body": io.BytesIO(objects[kwargs["Key"]]), "ETag": "test-etag"}

    def put_object(**kwargs):
        objects[kwargs["Key"]] = kwargs["Body"]

    s3.get_object.side_effect = get_object
    s3.put_object.side_effect = put_object
    runtime = Mock()
    runtime.invoke_agent_runtime.return_value = {"response": io.BytesIO(json.dumps({
        "mode": "single", "report": report, "specialists": {}, "comparisons": compare_scans([event])}).encode())}
    records = [{"kinesis": {"data": base64.b64encode(json.dumps(event).encode()).decode()}}]
    args = ([event], s3, runtime, "demo-bucket", "runtime", "single")
    location = ("123456789012", "eu-central-1", "aws")
    keys = process(*args)["keys"]
    prepared = publish(keys, s3, "demo-bucket", *location)
    assert publish(keys, s3, "demo-bucket", *location) == prepared
    assert prepared["expected_count"] == len(prepared["Findings"])
    with patch("lambda_functions.publish_findings.findings_for", return_value=[{"Description": "x" * (240 * 1024)}]):
        try:
            publish(keys, s3, "demo-bucket", *location)
        except ValueError:
            pass
        else:
            raise AssertionError("oversized workflow output accepted")
    assert runtime.invoke_agent_runtime.call_count == 1, "retry repeated inference"
    assert s3.put_object.call_count == 3
    assert all(c.kwargs["IfNoneMatch"] == "*" for c in s3.put_object.call_args_list)
    assert process(*args)["keys"] == keys
    assert runtime.invoke_agent_runtime.call_count == 1, "saved-result reuse repeated inference"
    workflows = Mock()
    records[0]["eventID"] = "shardId-000000000000:123"
    start(records, workflows, "workflow")
    starts = workflows.start_execution.call_args_list[:]
    assert [json.loads(c.kwargs["input"])["mode"] for c in starts] == ["orchestrator"]
    assert len({c.kwargs["name"] for c in starts}) == 1
    assert all(json.loads(c.kwargs["input"])["events"] == [event] for c in starts)
    first = starts[0]
    start(records, workflows, "workflow")
    assert workflows.start_execution.call_args_list[1:] == starts
    assert json.loads(first.kwargs["input"]) == {"mode": "orchestrator", "events": [event]}
    assert len(first.kwargs["name"]) == 64
    for invalid_keys in [[], ["results/single/../../secret"], [keys[0], keys[0]]]:
        try:
            publish(invalid_keys, s3, "demo-bucket", *location)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid workflow handoff accepted")
    workflows.start_execution.side_effect = ClientError(
        {"Error": {"Code": "ExecutionAlreadyExists"}}, "StartExecution")
    start(records, workflows, "workflow")
    workflows.start_execution.reset_mock()
    workflows.start_execution.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException"}}, "StartExecution")
    try:
        start(records, workflows, "workflow")
    except ClientError:
        pass
    else:
        raise AssertionError("workflow start failure swallowed")
    assert json.loads(first.kwargs["input"]) == {"mode": "orchestrator", "events": [event]}
    try:
        publish(["outside/results.json"], s3, "demo-bucket", *location)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid result key accepted")
    findings = prepared["Findings"]
    assert len(findings) == 2
    assert all("Workflow" not in f and "RecordState" not in f for f in findings)
    assert findings[1]["ProductFields"]["rule_ids"] == "10010"
    saved = json.loads(objects[keys[0]])
    older_id = findings[1]["Id"]
    saved["analyzed_at"] = "2026-11-15T00:00:00Z"
    assert findings_for(saved, *location, "demo-bucket")[1]["Id"] == older_id
    special = copy.deepcopy(saved)
    value = 'Review "cookie" \\ flags & <headers> café {{not_a_template}}'
    special["report"]["summary"] = value + '\nNext human decision.'
    special["report"]["work_items"][0].update(title=value, observation=value, fix=value)
    rendered = findings_for(special, *location, "demo-bucket")
    assert special["report"]["summary"] in rendered[0]["Description"]
    assert rendered[1]["Title"] == f"[single] {value}"
    assert rendered[1]["ProductFields"]["observation"] == value
    assert rendered[1]["Remediation"]["Recommendation"]["Text"] == (
        f"Fix: {value}")
    assert f"What was found: {value}\n\nWhy it matters:" in rendered[1]["Description"]
    # Schema maxima must fit ASFF limits untouched: valid reports never need cutting.
    item = special["report"]["work_items"][0]
    item.update(rationale="r" * 300, owner_role="o" * 80, observation="b" * 450, fix="x" * 500)
    special["report"]["summary"] = "s" * 600
    bounded = findings_for(special, *location, "demo-bucket")
    assert "\u2026" not in bounded[1]["Description"] and "\u2026" not in bounded[1]["Remediation"]["Recommendation"]["Text"]
    assert len(bounded[1]["Description"]) <= 1024 and len(bounded[0]["Description"]) <= 1024
    assert clip("word " * 300, 1024).endswith("word\u2026") and len(clip("word " * 300, 1024)) <= 1024
    assert clip("x" * 600, 512) == "x" * 511 + "\u2026"
    assert len(bounded[1]["Remediation"]["Recommendation"]["Text"]) == 505  # fix max 500 fits ASFF 512; retest in ProductFields
    try:
        render("work-item.mustache", {})
    except KeyNotFoundError:
        pass
    else:
        raise AssertionError("missing template fields accepted")
    client = boto3.client("securityhub", region_name="eu-central-1", aws_access_key_id="test",
                          aws_secret_access_key="test")
    with Stubber(client) as stub:
        stub.add_response("batch_import_findings", {"FailedCount": 0, "SuccessCount": 2,
                                                  "FailedFindings": []}, {"Findings": rendered})
        client.batch_import_findings(Findings=rendered)
    saved["evidence"][0]["current"]["findings"][0]["confidence"] = 0
    assert findings_for(saved, *location, "demo-bucket")[1]["FindingProviderFields"]["Severity"]["Label"] == "INFORMATIONAL"
    saved["evidence"][0]["current"]["findings"] = []
    saved["report"]["work_items"] = []
    assert len(findings_for(saved, *location, "demo-bucket")) == 1
    print("PASS: agents, workflow starts/idempotency, S3 handoff validation, publish retries without inference, ASFF/templates")


if __name__ == "__main__":
    main()