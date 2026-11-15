"""Render validated agent recommendations as Security Hub ASFF findings."""
import json
from pathlib import Path

import pystache

from contracts.security_report import validate_report
from contracts.scan_comparison import compare_scans
from contracts.schema import validate_schema

TEMPLATES = Path(__file__).with_name("templates")


def render(name, context, escape=str):
    template = (TEMPLATES / name).read_text(encoding="utf-8")
    return pystache.Renderer(escape=escape, missing_tags="strict").render(template, context).rstrip("\n")


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
        values = {**context, "group": group, "title": title, "description": description[:1024],
                  "severity": severity, "remediation": remediation[:1024],
                  "fields": [{"key": key, "value": value} for key, value in fields.items()]}
        # Mustache defaults to HTML escaping; ASFF needs JSON string escaping instead.
        return json.loads(render("finding.json.mustache", values,
                                 escape=lambda value: json.dumps(value, ensure_ascii=False)[1:-1]))

    limits = "Agent recommendations require human review. Paths, transport and coverage are not exported. Missing alerts never imply resolution."
    changes = "Baseline unavailable."
    comparisons = saved.get("comparisons")
    if comparisons is None:  # Results saved before shared context was introduced.
        comparisons = compare_scans(saved["evidence"])
    validate_schema("comparisons", comparisons)
    delta = next((c for c in comparisons if c["event_id"] == event["event_id"]), None)
    if delta and delta["baseline_available"]:
        changes = json.dumps({"added": delta["added"], "absent_not_resolved": delta["absent"],
                              "changed": delta["changed"]})
    # Always show scan decision brief, including empty scans and evidence gaps.
    findings = [finding("scan-review", "Demo scan: security review required",
                        render("scan-review.mustache", {"summary": report["summary"], "limits": limits, "changes": changes}),
                        "INFORMATIONAL", "Review evidence and proposed fixes. Confirm comparable capture before closure.",
                        {"baseline_changes": changes, "decision_brief": report["summary"]})]
    for item in report["work_items"]:
        if item["event_id"] != event["event_id"]:
            continue
        inventory = [f for f in event["current"]["findings"] if f["rule_id"] in item["rule_ids"]]
        # Do not promote groups classified entirely as false positive to exposure.
        severity = item["severity"] if any(f["confidence"] > 0 for f in inventory) else "INFORMATIONAL"
        description = render("work-item.mustache", {**item, "limits": limits})
        findings.append(finding(item["group"], item["title"], description, severity,
                                render("remediation.mustache", item),
                                {"rule_ids": ",".join(sorted(item["rule_ids"])),
                                 "instance_count": str(sum(f["instances"] for f in inventory)),
                                 "proposed_owner_role": item["owner_role"],
                                 "priority_rationale": item["rationale"],
                                 "observation": item["observation"], "hypothesis": item["hypothesis"],
                                 "limitations": item["limitations"],
                                 "acceptance_checks": item["retest"]}))
    return findings