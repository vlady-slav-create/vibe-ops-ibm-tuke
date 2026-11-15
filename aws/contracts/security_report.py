"""Security report schema and evidence citation validation shared by both deployments."""

from contracts.schema import validate_schema

GROUPS = {
    "cookie-hardening": {"10010", "10011", "10054"},
    "security-headers": {"10020", "10021", "10035", "10038"},
    "url-exposure": {"10024"},
    "other": set(),
}


def group_for(rule):
    return next((group for group, rules in GROUPS.items() if rule in rules), "other")


def validate_report(report, events):
    validate_schema("report", report)
    items = report["work_items"]
    expected = {}
    for event in events:
        if event["event"] == "zap_scan":
            for finding in event["current"]["findings"]:
                expected.setdefault((event["event_id"], group_for(finding["rule_id"])), set()).add(finding["rule_id"])
    seen = set()
    for item in items:
        identity = (item["event_id"], item["group"])
        rules = item["rule_ids"]
        if identity in seen or identity not in expected or set(rules) != expected[identity]:
            raise ValueError("invalid or missing evidence citations")
        seen.add(identity)
    if seen != expected.keys():
        raise ValueError("work queue must cover every current rule group")
    return report
