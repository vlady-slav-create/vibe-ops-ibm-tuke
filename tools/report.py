"""Render saved bridge result as Markdown; no AWS credentials or model calls needed."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "aws"))
from contracts.scan_comparison import compare_scans
from contracts.evidence import validate
from contracts.security_report import validate_report
from contracts.schema import validate_schema


def render(result):
    if not isinstance(result, dict):
        raise ValueError("expected saved bridge result")
    events = validate({"mode": result.get("mode"), "events": result.get("evidence")})
    report = result.get("report")
    if isinstance(report, dict):
        validate_report(report, events)
        sections = ["## Decision brief", report["summary"], "## Proposed work items"]
        for item in report["work_items"]:
            sections.extend([f"### {item['title']} ({item['severity']})",
                             f"Evidence: {item['event_id']}; rules: {', '.join(item['rule_ids'])}"])
            for key in ("rationale", "owner_role", "observation", "hypothesis", "fix", "retest", "limitations"):
                sections.append(f"- {key.replace('_', ' ').capitalize()}: {item[key]}")
        report = "\n\n".join(sections)
    if not isinstance(report, str) or not report.strip() or len(report.encode()) > 262144:
        raise ValueError("invalid agent report")
    lines = ["# Security review handoff", "",
             "> Agent-generated recommendations. Human review required; no changes executed.", "",
             report.strip(), "", "## Recorded evidence (deterministic)", "",
             "Counts below come from sanitized evidence, not model estimates.", ""]
    comparisons = result.get("comparisons")
    if comparisons is None:
        comparisons = compare_scans(events)
    validate_schema("comparisons", comparisons)
    comparisons = {c["event_id"]: c for c in comparisons}
    for event in events:
        lines.extend([f"### Event `{event['event_id']}`", "",
                      f"Captured: {event['captured_at']}", ""])
        if event["event"] != "zap_scan":
            lines.extend(["Legacy exchange evidence; no ZAP scan inventory or baseline comparison.", ""])
            continue
        current = event["current"]
        lines.extend([f"Asset: `{event['asset_id']}`. Coverage, paths and transport not exported.", "",
                      f"Rule groups: {len(current['findings'])}. Alert instances: "
                      f"{sum(f['instances'] for f in current['findings'])} (not affected users or leaked secrets).", "",
                      "| Rule ID | Scanner risk | Scanner confidence | Instances |",
                      "| --- | --- | --- | --- |"])
        for f in sorted(current["findings"], key=lambda f: (-f["risk"], f["rule_id"])):
            lines.append(f"| {f['rule_id']} | {f['risk']} | {f['confidence']} | {f['instances']} |")
        lines.extend(["", "Scanner risk: 0 informational, 1 low, 2 medium, 3 high. "
                      "Confidence: 0 false positive, 1 low, 2 medium, 3 high, 4 confirmed. "
                      "Scanner ratings are not agent work priority.", ""])
        delta = comparisons[event["event_id"]]
        if not delta["baseline_available"]:
            lines.extend(["Baseline unavailable; no change claim supported.", ""])
        else:
            for name in ("added", "changed", "absent", "unchanged"):
                lines.append(f"- {name.capitalize()} rule groups: {', '.join(delta[name]) or 'none'}")
            lines.extend(["", delta["limitation"], ""])
    lines.extend(["## Handling and limits", "",
                  "Raw HAR and ZAP report remain local. HAR cannot establish certificate validation "
                  "or malicious MITM. Unknown rule semantics require local ZAP lookup. "
                  "Review generated text before sharing or creating tickets.", ""])
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result", type=Path, help="downloaded results/<mode>/<event_id>.json")
    args = parser.parse_args()
    try:
        if args.result.stat().st_size > 1048576:
            raise ValueError("result too large")
        output = render(json.loads(args.result.read_text()))
    except (OSError, ValueError, TypeError, KeyError):
        parser.exit(1, "Invalid saved result; no report produced.\n")
    sys.stdout.write(output)