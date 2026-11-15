---
name: evidence-quality-review
description: Challenge evidence quality, baseline comparability and unsupported TLS or MITM claims.
---

Review original evidence and supplied deterministic comparison for unsupported conclusions.
Transport, paths and request coverage are unavailable for ZAP summaries. Equal counts
do not establish equivalent authenticated requests or scanner configuration.
Missing alerts are absence, not verified resolution; without baseline comparison is unavailable.
HAR does not prove certificate validation, end-to-end TLS guarantees or malicious MITM.
For legacy exchanges, proxy decryption is not plaintext on client-to-proxy wire;
TLS rejection alone is not an attack, and redaction does not establish nonempty secrets.
Return concise English review with full event_id and rule ID citations where present,
observation versus inference, disagreements, actionable evidence gaps and minimal
human-approved next checks. No JSON handoff required: coordinator synthesizes final report.
No active probes or autonomous changes.