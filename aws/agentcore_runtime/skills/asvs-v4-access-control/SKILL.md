---
name: asvs-v4-access-control
description: OWASP ASVS 4.0.3 V4 Access Control. Load when evidence involves access control, authorization, IDOR, admin interfaces.
---

OWASP ASVS 4.0.3 V4 Access Control, verbatim from https://github.com/OWASP/ASVS/tree/v4.0.3/4.0/en. Cite as "ASVS 4.0.3 <id>" only when a cited
finding supports it. Requirements ZAP cannot observe are unverified, never failed.

V4.1 General Access Control Design
- 4.1.1 [L1,L2,L3, CWE-602] Verify that the application enforces access control rules on a trusted service layer, especially if client-side access control is present and could be bypassed.
- 4.1.2 [L1,L2,L3, CWE-639] Verify that all user and data attributes and policy information used by access controls cannot be manipulated by end users unless specifically authorized.
- 4.1.3 [L1,L2,L3, CWE-285] Verify that the principle of least privilege exists - users should only be able to access functions, data files, URLs, controllers, services, and other resources, for which they possess specific authorization. This implies protection against spoofing and elevation of privilege.
- 4.1.4 [] [DELETED, DUPLICATE OF 4.1.3]
- 4.1.5 [L1,L2,L3, CWE-285] Verify that access controls fail securely including when an exception occurs.

V4.2 Operation Level Access Control
- 4.2.1 [L1,L2,L3, CWE-639] Verify that sensitive data and APIs are protected against Insecure Direct Object Reference (IDOR) attacks targeting creation, reading, updating and deletion of records, such as creating or updating someone else's record, viewing everyone's records, or deleting all records.
- 4.2.2 [L1,L2,L3, CWE-352] Verify that the application or framework enforces a strong anti-CSRF mechanism to protect authenticated functionality, and effective anti-automation or anti-CSRF protects unauthenticated functionality.

V4.3 Other Access Control Considerations
- 4.3.1 [L1,L2,L3, CWE-419] Verify administrative interfaces use appropriate multi-factor authentication to prevent unauthorized use.
- 4.3.2 [L1,L2,L3, CWE-548] Verify that directory browsing is disabled unless deliberately desired. Additionally, applications should not allow discovery or disclosure of file or directory metadata, such as Thumbs.db, .DS_Store, .git or .svn folders.
- 4.3.3 [L2,L3, CWE-732] Verify the application has additional authorization (such as step up or adaptive authentication) for lower value systems, and / or segregation of duties for high value applications to enforce anti-fraud controls as per the risk of application and past fraud.
