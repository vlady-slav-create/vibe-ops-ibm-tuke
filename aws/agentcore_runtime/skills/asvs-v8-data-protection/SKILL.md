---
name: asvs-v8-data-protection
description: OWASP ASVS 4.0.3 V8 Data Protection. Load when evidence involves data protection, sensitive data in responses, caching of sensitive data.
---

OWASP ASVS 4.0.3 V8 Data Protection, verbatim from https://github.com/OWASP/ASVS/tree/v4.0.3/4.0/en. Cite as "ASVS 4.0.3 <id>" only when a cited
finding supports it. Requirements ZAP cannot observe are unverified, never failed.

V8.1 General Data Protection
- 8.1.1 [L2,L3, CWE-524] Verify the application protects sensitive data from being cached in server components such as load balancers and application caches.
- 8.1.2 [L2,L3, CWE-524] Verify that all cached or temporary copies of sensitive data stored on the server are protected from unauthorized access or purged/invalidated after the authorized user accesses the sensitive data.
- 8.1.3 [L2,L3, CWE-233] Verify the application minimizes the number of parameters in a request, such as hidden fields, Ajax variables, cookies and header values.
- 8.1.4 [L2,L3, CWE-770] Verify the application can detect and alert on abnormal numbers of requests, such as by IP, user, total per hour or day, or whatever makes sense for the application.
- 8.1.5 [L3, CWE-19] Verify that regular backups of important data are performed and that test restoration of data is performed.
- 8.1.6 [L3, CWE-19] Verify that backups are stored securely to prevent data from being stolen or corrupted.

V8.2 Client-side Data Protection
- 8.2.1 [L1,L2,L3, CWE-525] Verify the application sets sufficient anti-caching headers so that sensitive data is not cached in modern browsers.
- 8.2.2 [L1,L2,L3, CWE-922] Verify that data stored in browser storage (such as localStorage, sessionStorage, IndexedDB, or cookies) does not contain sensitive data.
- 8.2.3 [L1,L2,L3, CWE-922] Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated.

V8.3 Sensitive Private Data
- 8.3.1 [L1,L2,L3, CWE-319] Verify that sensitive data is sent to the server in the HTTP message body or headers, and that query string parameters from any HTTP verb do not contain sensitive data.
- 8.3.2 [L1,L2,L3, CWE-212] Verify that users have a method to remove or export their data on demand.
- 8.3.3 [L1,L2,L3, CWE-285] Verify that users are provided clear language regarding collection and use of supplied personal information and that users have provided opt-in consent for the use of that data before it is used in any way.
- 8.3.4 [L1,L2,L3, CWE-200] Verify that all sensitive data created and processed by the application has been identified, and ensure that a policy is in place on how to deal with sensitive data.
- 8.3.5 [L2,L3, CWE-532] Verify accessing sensitive data is audited (without logging the sensitive data itself), if the data is collected under relevant data protection directives or where logging of access is required.
- 8.3.6 [L2,L3, CWE-226] Verify that sensitive information contained in memory is overwritten as soon as it is no longer required to mitigate memory dumping attacks, using zeroes or random data.
- 8.3.7 [L2,L3, CWE-327] Verify that sensitive or private information that is required to be encrypted, is encrypted using approved algorithms that provide both confidentiality and integrity.
- 8.3.8 [L2,L3, CWE-285] Verify that sensitive personal information is subject to data retention classification, such that old or out of date data is deleted automatically, on a schedule, or as the situation requires.
