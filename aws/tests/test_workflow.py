"""Offline integration wiring: python -m tests.test_workflow."""
import json
from pathlib import Path
from string import Template


def main():
    root = Path(__file__).resolve().parents[1]
    definition = Template((root / "terraform/workflow/analysis.asl.json").read_text()).safe_substitute(
        partition="aws", analyze_and_store_arn="analysis",
        publish_findings_arn="renderer")
    workflow = json.loads(definition)
    states = workflow["States"]
    assert workflow["StartAt"] == "AnalyzeAndStore"
    assert "FindSavedAnalysis" not in states, "Lambda owns result reuse and context repair"
    assert states["AnalyzeAndStore"]["Next"] == "PublishFindings"
    assert states["AnalyzeAndStore"]["Parameters"] == {"mode.$": "$.mode", "events.$": "$.events"}
    assert "Retry" not in states["AnalyzeAndStore"]
    publish = states["PublishFindings"]
    assert publish["Type"] == "Parallel" and len(publish["Branches"]) == 1
    assert "Retry" not in publish
    assert publish["OutputPath"] == "$[0]"
    branch = publish["Branches"][0]
    tasks = branch["States"]
    assert branch["StartAt"] == "RenderFindings"
    assert tasks["RenderFindings"]["Next"] == "ImportFindings"
    assert tasks["ImportFindings"]["Resource"].endswith(":aws-sdk:securityhub:batchImportFindings")
    assert tasks["ImportFindings"]["Parameters"] == {"Findings.$": "$.Findings"}
    check = tasks["CheckImport"]
    assert check["Choices"][0]["And"] == [
        {"Variable": "$.import.FailedCount", "NumericEquals": 0},
        {"Variable": "$.import.SuccessCount", "NumericEqualsPath": "$.expected_count"}]
    assert check["Default"] == "ImportRejected"
    assert tasks["ImportRejected"]["Type"] == "Fail"
    assert tasks["ImportRejected"]["Error"] == "SecurityHub.PartialImport"
    assert all(s.get("Resource") != "analysis" for s in tasks.values())
    for group in (states, tasks):
        for state in group.values():
            for target in ([state["Next"]] if "Next" in state else []):
                assert target in group
    iam = (root / "terraform/iam.tf").read_text()
    workflow_iam = iam.split('resource "aws_iam_role_policy" "workflow"')[1]
    assert '"s3:ListBucket"' not in workflow_iam
    assert "context/v1/*" in iam
    assert '"securityhub:BatchImportFindings"' in workflow_iam
    assert '"securityhub:BatchImportFindings"' not in iam.split('resource "aws_iam_role" "workflow"')[0]
    print("PASS: analysis/context handoff, Security Hub import, partial-failure retries, IAM")


if __name__ == "__main__":
    main()