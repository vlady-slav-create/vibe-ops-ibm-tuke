---
name: asvs-v9-communication
description: OWASP ASVS 4.0.3 V9 Communication. Load when evidence involves transport: HTTP versus HTTPS, TLS versions, ciphers, certificates.
---

OWASP ASVS 4.0.3 V9 Communication, verbatim from https://github.com/OWASP/ASVS/tree/v4.0.3/4.0/en. Cite as "ASVS 4.0.3 <id>" only when a cited
finding supports it. Requirements ZAP cannot observe are unverified, never failed.

V9.1 Client Communication Security
- 9.1.1 [L1,L2,L3, CWE-319] Verify that TLS is used for all client connectivity, and does not fall back to insecure or unencrypted communications.
- 9.1.2 [L1,L2,L3, CWE-326] Verify using up to date TLS testing tools that only strong cipher suites are enabled, with the strongest cipher suites set as preferred.
- 9.1.3 [L1,L2,L3, CWE-326] Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol should be the preferred option.

V9.2 Server Communication Security
- 9.2.1 [L2,L3, CWE-295] Verify that connections to and from the server use trusted TLS certificates. Where internally generated or self-signed certificates are used, the server must be configured to only trust specific internal CAs and specific self-signed certificates. All others should be rejected.
- 9.2.2 [L2,L3, CWE-319] Verify that encrypted communications such as TLS is used for all inbound and outbound connections, including for management ports, monitoring, authentication, API, or web service calls, database, cloud, serverless, mainframe, external, and partner connections. The server must not fall back to insecure or unencrypted protocols.
- 9.2.3 [L2,L3, CWE-287] Verify that all encrypted connections to external systems that involve sensitive information or functions are authenticated.
- 9.2.4 [L2,L3, CWE-299] Verify that proper certification revocation, such as Online Certificate Status Protocol (OCSP) Stapling, is enabled and configured.
- 9.2.5 [L3, CWE-544] Verify that backend TLS connection failures are logged.
