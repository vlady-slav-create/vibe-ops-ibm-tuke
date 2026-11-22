---
name: security-handoff
description: Group security findings into a cited, prioritized JSON handoff for human review.
---

Produce a structured security handoff for Security Hub, not a scanner alert dump.
Decision brief: recommended next human decision, most important supported risk,
and blocker/uncertainty. Do not declare incident, breach, safe system or resolved issue
without evidence. Do not invent business impact, organizational owners, SLAs or effort savings.
Prioritized work queue:
Group related rules into the smallest useful set of shared-fix work items, not one
ticket per alert. For each item include priority and rationale (distinct from scanner risk),
proposed owner role (not assigned person), observed evidence with full event_id and rule IDs,
shared-cause hypothesis explicitly labeled, concrete fix, acceptance/retest checklist,
and remaining human decision. Treat confidence 0 as scanner false-positive classification;
do not promote it to confirmed exposure. Unknown rules need local rule lookup, not invented fixes.
Scan limits:
No scan history is supplied; claim no regression or resolution. Absence is not resolution; equal
counts do not establish equivalent authenticated requests or scanner configuration.
Evidence gaps and next checks:
List only actionable missing evidence, minimal human-approved checks and conclusions
not supported (including malicious MITM attribution from HAR). No active probing tools.
Analyst handoff:
Separate developer/platform follow-up from security review. State what has been grouped
or compared, outstanding human decisions and specialist disagreement. No invented ticket
creation or notification. No HTML, remote images or external links.
Empty findings still require coverage limits and next decision, not an all-clear.
Keep report concise, with no raw traffic or fabricated evidence.
FINAL RESPONSE: call SecurityReport with this object; no Markdown fences or prose outside it:
{"summary":"Decision brief, next decision, blockers and specialist disagreement (max 600 chars)",
 "work_items":[{"event_id":"full input event ID","group":"cookie-hardening",
 "rule_ids":["rule ID"],"title":"max 120 chars","severity":"LOW",
 "rationale":"priority rationale, max 300 chars","owner_role":"proposed role, max 80 chars",
 "observation":"observed evidence, max 450 chars","hypothesis":"explicitly unverified, max 400 chars",
 "fix":"concrete fix, max 500 chars","retest":"acceptance checks, max 500 chars",
 "limitations":"missing evidence and remaining human decision, max 500 chars"}]}
Length caps are hard limits and the report is rejected when exceeded: aim for about 20% under each
cap (rationale 240, observation 360, hypothesis 320 chars); be terse, cite facts once, no repetition.
Use plain text in string fields, no line breaks. Severity: INFORMATIONAL, LOW, MEDIUM or HIGH.
Write for an engineer who has not read the scan: plain words, short sentences, no event ID
prefixes or field labels inside values (no "Hypothesis:" or "Event 23fe0303:"). Name each rule
by ZAP title, not only number. fix: imperative steps naming what to change and where, e.g.
"Add header X-Content-Type-Options: nosniff in the reverse proxy for all responses".
retest: numbered checks a human can run. Event IDs belong in event_id only.
For EACH ZAP event group ALL current rule IDs exactly once, using the fixed shared-fix groups listed under SHARED-FIX GROUPS (rule membership is
supplied by the runtime; `other` holds every rule not listed). Exactly one item per nonempty group per event.
Do not group across events. Do not invent rules.
For empty ZAP scans or legacy exchanges return no work items for that event; summary must
explain evidence limits, never all-clear. Unknown rules need local lookup, not invented fixes.
No CRITICAL priority without evidence; confidence 0 is false-positive classification.
Do not claim assignment, ticket creation, notification or verified resolution.
