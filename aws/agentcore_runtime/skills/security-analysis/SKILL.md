---
name: security-analysis
description: Interpret sanitized classroom network evidence and ZAP findings without overstating conclusions.
---

Report findings with event_id citations, observed facts, severity, uncertainty and fixes.
HTTP plus secret-field presence supports possible plaintext credential exposure; redaction
does not reveal whether a password was empty. A 401 or 404 alone is not an attack.
HTTPS decrypted at an intercepting proxy is not plaintext on the client-to-proxy wire.
TLS rejection alone does not prove an attack. Separate observation from inference.
Do not invent packet content, certificate properties or end-to-end TLS guarantees.
ZAP already performs vulnerability detection: do not pretend to discover its findings.
For zap_scan events, investigate related rule groups. Paths, HTTP/HTTPS transport and
request coverage are NOT exported; never infer them from counts or rule absence.
Use supplied deterministic scan comparison before claiming regression
or resolution. Missing alerts are not proof of a fix: coverage may differ, rules may change,
and HAR contains no certificate validation evidence. Risk and confidence are scanner ratings
(0..3 and 0..4); false-positive confidence 0 is not confirmed exposure. Counts are recorded
alert instances, not number of leaked secrets or affected users. Unknown rule IDs must remain
unknown; never invent rule semantics. Known ZAP rules: 10010 cookie without HttpOnly;
10011 cookie without Secure; 10020 missing anti-clickjacking header; 10021 missing
X-Content-Type-Options; 10024 sensitive information in URL; 10035 missing HSTS;
10038 missing CSP; 10054 cookie without SameSite. These are not all equivalent in impact.
Agent task: group likely shared causes, choose highest-impact remediation order, challenge
false positives, state missing evidence, and propose bounded human-approved verification.
Return an incident brief with citations, hypothesis versus observation, prioritized fixes,
verification steps and residual risk. No autonomous changes or uncaptured historical claims.
Return concise English findings, including normal observations and limitations.
