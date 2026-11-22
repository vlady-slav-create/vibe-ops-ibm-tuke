---
name: asvs-v10-malicious-code
description: OWASP ASVS 4.0.3 V10 Malicious Code. Load when evidence involves malicious code, integrity, subresource integrity, subdomain takeover.
---

OWASP ASVS 4.0.3 V10 Malicious Code, verbatim from https://github.com/OWASP/ASVS/tree/v4.0.3/4.0/en. Cite as "ASVS 4.0.3 <id>" only when a cited
finding supports it. Requirements ZAP cannot observe are unverified, never failed.

V10.1 Code Integrity
- 10.1.1 [L3, CWE-749] Verify that a code analysis tool is in use that can detect potentially malicious code, such as time functions, unsafe file operations and network connections.

V10.2 Malicious Code Search
- 10.2.1 [L2,L3, CWE-359] Verify that the application source code and third party libraries do not contain unauthorized phone home or data collection capabilities. Where such functionality exists, obtain the user's permission for it to operate before collecting any data.
- 10.2.2 [L2,L3, CWE-272] Verify that the application does not ask for unnecessary or excessive permissions to privacy related features or sensors, such as contacts, cameras, microphones, or location.
- 10.2.3 [L3, CWE-507] Verify that the application source code and third party libraries do not contain back doors, such as hard-coded or additional undocumented accounts or keys, code obfuscation, undocumented binary blobs, rootkits, or anti-debugging, insecure debugging features, or otherwise out of date, insecure, or hidden functionality that could be used maliciously if discovered.
- 10.2.4 [L3, CWE-511] Verify that the application source code and third party libraries do not contain time bombs by searching for date and time related functions.
- 10.2.5 [L3, CWE-511] Verify that the application source code and third party libraries do not contain malicious code, such as salami attacks, logic bypasses, or logic bombs.
- 10.2.6 [L3, CWE-507] Verify that the application source code and third party libraries do not contain Easter eggs or any other potentially unwanted functionality.

V10.3 Application Integrity
- 10.3.1 [L1,L2,L3, CWE-16] Verify that if the application has a client or server auto-update feature, updates should be obtained over secure channels and digitally signed. The update code must validate the digital signature of the update before installing or executing the update.
- 10.3.2 [L1,L2,L3, CWE-353] Verify that the application employs integrity protections, such as code signing or subresource integrity. The application must not load or execute code from untrusted sources, such as loading includes, modules, plugins, code, or libraries from untrusted sources or the Internet.
- 10.3.3 [L1,L2,L3, CWE-350] Verify that the application has protection from subdomain takeovers if the application relies upon DNS entries or DNS subdomains, such as expired domain names, out of date DNS pointers or CNAMEs, expired projects at public source code repos, or transient cloud APIs, serverless functions, or storage buckets (*autogen-bucket-id*.cloud.example.com) or similar. Protections can include ensuring that DNS names used by applications are regularly checked for expiry or change.
