---
name: asvs-v11-business-logic
description: OWASP ASVS 4.0.3 V11 Business Logic. Load when evidence involves business logic, anti-automation, rate limits.
---

OWASP ASVS 4.0.3 V11 Business Logic, verbatim from https://github.com/OWASP/ASVS/tree/v4.0.3/4.0/en. Cite as "ASVS 4.0.3 <id>" only when a cited
finding supports it. Requirements ZAP cannot observe are unverified, never failed.

V11.1 Business Logic Security
- 11.1.1 [L1,L2,L3, CWE-841] Verify that the application will only process business logic flows for the same user in sequential step order and without skipping steps.
- 11.1.2 [L1,L2,L3, CWE-799] Verify that the application will only process business logic flows with all steps being processed in realistic human time, i.e. transactions are not submitted too quickly.
- 11.1.3 [L1,L2,L3, CWE-770] Verify the application has appropriate limits for specific business actions or transactions which are correctly enforced on a per user basis.
- 11.1.4 [L1,L2,L3, CWE-770] Verify that the application has anti-automation controls to protect against excessive calls such as mass data exfiltration, business logic requests, file uploads or denial of service attacks.
- 11.1.5 [L1,L2,L3, CWE-841] Verify the application has business logic limits or validation to protect against likely business risks or threats, identified using threat modeling or similar methodologies.
- 11.1.6 [L2,L3, CWE-367] Verify that the application does not suffer from "Time Of Check to Time Of Use" (TOCTOU) issues or other race conditions for sensitive operations.
- 11.1.7 [L2,L3, CWE-754] Verify that the application monitors for unusual events or activity from a business logic perspective. For example, attempts to perform actions out of order or actions which a normal user would never attempt.
- 11.1.8 [L2,L3, CWE-390] Verify that the application has configurable alerting when automated attacks or unusual activity is detected.
