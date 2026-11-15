"""Read-only baseline comparison of sanitized scan evidence; no model calls."""


def compare_scans(events, context=None):
    comparisons = []
    for event in events:
        if event["event"] != "zap_scan":
            continue
        current, baseline = event["current"], event["baseline"]
        previous = context.get("previous") if context else None
        if baseline is None and previous is not None:
            baseline = previous["event"]["current"]
        item = {"event_id": event["event_id"], "baseline_available": baseline is not None}
        if baseline is not None:
            item["baseline_source"] = "embedded" if event["baseline"] is not None else "s3-context"
            if item["baseline_source"] == "s3-context":
                item["baseline_event_id"] = previous["event"]["event_id"]
            before = {f["rule_id"]: f for f in baseline["findings"]}
            after = {f["rule_id"]: f for f in current["findings"]}
            item.update(added=sorted(after.keys() - before.keys()), absent=sorted(before.keys() - after.keys()),
                        changed=sorted(k for k in before.keys() & after.keys() if before[k] != after[k]),
                        unchanged=sorted(k for k in before.keys() & after.keys() if before[k] == after[k]),
                        limitation="Coverage, paths and transport are not exported; scan comparability is unverified. Absent is not resolved.")
        comparisons.append(item)
    return comparisons
