---
name: asvs-v7-error-handling-and-logging
description: OWASP ASVS 4.0.3 V7 Error Handling and Logging. Load when evidence involves logging, error handling, stack traces and error disclosure.
---

OWASP ASVS 4.0.3 V7 Error Handling and Logging, verbatim from https://github.com/OWASP/ASVS/tree/v4.0.3/4.0/en. Cite as "ASVS 4.0.3 <id>" only when a cited
finding supports it. Requirements ZAP cannot observe are unverified, never failed.

V7.1 Log Content
- 7.1.1 [L1,L2,L3, CWE-532] Verify that the application does not log credentials or payment details. Session tokens should only be stored in logs in an irreversible, hashed form. ([C9, C10](https://owasp.org/www-project-proactive-controls/#div-numbering))
- 7.1.2 [L1,L2,L3, CWE-532] Verify that the application does not log other sensitive data as defined under local privacy laws or relevant security policy.
- 7.1.3 [L2,L3, CWE-778] Verify that the application logs security relevant events including successful and failed authentication events, access control failures, deserialization failures and input validation failures. ([C5, C7](https://owasp.org/www-project-proactive-controls/#div-numbering))
- 7.1.4 [L2,L3, CWE-778] Verify that each log event includes necessary information that would allow for a detailed investigation of the timeline when an event happens.

V7.2 Log Processing
- 7.2.1 [L2,L3, CWE-778] Verify that all authentication decisions are logged, without storing sensitive session tokens or passwords. This should include requests with relevant metadata needed for security investigations.
- 7.2.2 [L2,L3, CWE-285] Verify that all access control decisions can be logged and all failed decisions are logged. This should include requests with relevant metadata needed for security investigations.

V7.3 Log Protection
- 7.3.1 [L2,L3, CWE-117] Verify that all logging components appropriately encode data to prevent log injection.
- 7.3.2 [] [DELETED, DUPLICATE OF 7.3.1]
- 7.3.3 [L2,L3, CWE-200] Verify that security logs are protected from unauthorized access and modification.
- 7.3.4 [L2,L3] Verify that time sources are synchronized to the correct time and time zone. Strongly consider logging only in UTC if systems are global to assist with post-incident forensic analysis.

V7.4 Error Handling
- 7.4.1 [L1,L2,L3, CWE-210] Verify that a generic message is shown when an unexpected or security sensitive error occurs, potentially with a unique ID which support personnel can use to investigate.
- 7.4.2 [L2,L3, CWE-544] Verify that exception handling (or a functional equivalent) is used across the codebase to account for expected and unexpected error conditions.
- 7.4.3 [L2,L3, CWE-431] Verify that a "last resort" error handler is defined which will catch all unhandled exceptions.
