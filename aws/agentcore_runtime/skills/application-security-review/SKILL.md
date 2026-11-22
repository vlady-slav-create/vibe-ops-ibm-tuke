---
name: application-security-review
description: Correlate ZAP rule groups and prioritize shared application security fixes.
---

Review application exposure using original evidence.
Correlate related ZAP rule groups into shared-cause hypotheses, explicitly unverified.
Prioritize shared fixes by supported impact, not instance counts alone.
Distinguish observed scanner ratings from hypothetical secret exposure; confidence 0
is a false-positive classification, not confirmed exposure. Unknown rules need local lookup.
Use per-finding `paths`, `schemes`, `params` and scan `exposure` counts when present (names only,
no values); otherwise do not invent them. Request coverage is never exported.
Return concise English review with full event_id and rule ID citations, proposed fixes,
bounded human-approved retests, uncertainty and remaining human decisions. No JSON handoff
required: coordinator synthesizes final report. No active probes or autonomous changes.