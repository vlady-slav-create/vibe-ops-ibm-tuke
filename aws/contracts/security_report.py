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


def expected_items(events):
    """Deterministic work queue: one item per (event_id, group) with every current rule of that group."""
    expected = {}
    for event in events:
        if event["event"] == "zap_scan":
            for finding in event["current"]["findings"]:
                expected.setdefault((event["event_id"], group_for(finding["rule_id"])), set()).add(finding["rule_id"])
    return expected


def validate_report(report, events):
    validate_schema("report", report)
    expected = expected_items(events)
    seen = set()
    for item in report["work_items"]:
        identity = (item["event_id"], item["group"])
        # Reasons name the failed check only, never model text.
        if identity in seen:
            raise ValueError("invalid or missing evidence citations: duplicate group")
        if identity not in expected:
            raise ValueError("invalid or missing evidence citations: unknown event_id or group")
        if set(item["rule_ids"]) != expected[identity]:
            raise ValueError("invalid or missing evidence citations: rule_ids differ from group rules")
        seen.add(identity)
    if seen != expected.keys():
        raise ValueError("work queue must cover every current rule group")
    return report
