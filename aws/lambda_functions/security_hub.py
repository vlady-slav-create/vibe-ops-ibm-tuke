"""Render validated agent recommendations as Security Hub ASFF findings."""
import json
from pathlib import Path

import pystache

from contracts.security_report import validate_report
from contracts.schema import validate_schema

TEMPLATES = Path(__file__).with_name("templates")


def render(name, context, escape=str):
    template = (TEMPLATES / name).read_text(encoding="utf-8")
    return pystache.Renderer(escape=escape, missing_tags="strict").render(template, context).rstrip("\n")


def clip(text, limit):
    """Fit ASFF length limits at a word boundary with an ellipsis, never mid-word."""
    if len(text) <= limit:
        return text
    head = text[:limit - 1]
    # Break at the last space if close to the end; else hard cut (one huge token keeps its content).
    space = max(head.rfind(" "), head.rfind("\n"))
    return (head[:space] if space > limit - 80 else head).rstrip(" ,;:\n") + "…"


def findings_for(saved, account, region, partition, bucket):
    """Stable IDs per mode/asset/fix group; no workflow changes or auto-resolution."""
    report = validate_report(saved["report"], saved["evidence"])
    event = next(e for e in saved["evidence"] if e["event_id"] == saved["event_id"])
    asset = event.get("asset_id", "demo-portal")
    context = {"account": account, "region": region, "partition": partition,
               "bucket": bucket, "asset": asset, "mode": saved["mode"],
               "event_id": event["event_id"], "captured_at": event["captured_at"],
               "analyzed_at": saved["analyzed_at"]}

    def finding(group, title, description, severity, remediation, fields):
        values = {**context, "group": group, "title": title, "description": clip(description, 1024),
                  "severity": severity, "remediation": clip(remediation, 512),
                  "fields": [{"key": key, "value": value} for key, value in fields.items()]}
        # Mustache defaults to HTML escaping; ASFF needs JSON string escaping instead.
        return json.loads(render("finding.json.mustache", values,
                                 escape=lambda value: json.dumps(value, ensure_ascii=False)[1:-1]))

    limits = "Agent recommendations require human review. Request coverage is not exported. Missing alerts never imply resolution."
    # Always show scan decision brief, including empty scans and evidence gaps.
    findings = [finding("scan-review", "Demo scan: security review required",
                        render("scan-review.mustache", {"summary": report["summary"], "limits": limits}),
                        "INFORMATIONAL", "Review evidence and proposed fixes. Confirm request coverage before closure.",
                        {"decision_brief": report["summary"]})]
    for item in report["work_items"]:
        if item["event_id"] != event["event_id"]:
            continue
        inventory = [f for f in event["current"]["findings"] if f["rule_id"] in item["rule_ids"]]
        # Do not promote groups classified entirely as false positive to exposure.
        severity = item["severity"] if any(f["confidence"] > 0 for f in inventory) else "INFORMATIONAL"
        description = render("work-item.mustache", item)
        findings.append(finding(item["group"], item["title"], description, severity,
                                render("remediation.mustache", item),
                                {"rule_ids": ",".join(sorted(item["rule_ids"])),
                                 "rule_names": "; ".join(f"{f['rule_id']} {f['name']}" for f in sorted(
                                     inventory, key=lambda f: f["rule_id"]) if "name" in f) or "not exported",
                                 "affected_paths": ",".join(sorted({p for f in inventory for p in f.get("paths", [])})) or "not exported",
                                 "schemes": ",".join(sorted({s for f in inventory for s in f.get("schemes", [])})) or "not exported",
                                 "param_names": ",".join(sorted({n for f in inventory for n in f.get("params", [])})) or "not exported",
                                 "instance_count": str(sum(f["instances"] for f in inventory)),
                                 "proposed_owner_role": item["owner_role"],
                                 "priority_rationale": item["rationale"],
                                 "observation": item["observation"], "hypothesis": item["hypothesis"],
                                 "limitations": item["limitations"],
                                 "acceptance_checks": item["retest"]}))
    return findings