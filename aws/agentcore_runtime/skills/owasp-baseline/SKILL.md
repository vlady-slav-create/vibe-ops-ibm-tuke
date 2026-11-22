---
name: owasp-baseline
description: OWASP ASVS 4.0.3 and Cheat Sheet baseline for interpreting ZAP findings. Cite only the references listed here.
---

Use as a yardstick for ZAP findings and transport evidence. It adds no rules: never report a
gap ZAP or the evidence does not show. Cite only IDs below; never invent others.

- ASVS 4.0.3 V9.1.1 (CWE-319): TLS for all client connectivity, no fallback to cleartext. Credentials
  or session cookies seen on `http` schemes/paths fail it; rate that on its own merits.
- ASVS V9.1.2, V9.1.3 (CWE-326): strong ciphers, TLS 1.2+ only. ZAP's HAR import cannot test these;
  say unverified unless evidence exists.
- ASVS V9.2.1 (CWE-295): trusted certificates; self-signed only with pinned trust. Needs certificate
  evidence; `tls_client_rejected` alone is not proof.
- ASVS V3.4.1 Secure, V3.4.2 HttpOnly, V3.4.3 SameSite on cookie session tokens (CWE-614, 1004, 16).
  Cookie rules are ZAP Low; a `Secure` gap matters more when the cookie was set over `http`.
- OWASP HTTP Headers Cheat Sheet: `X-Content-Type-Options: nosniff`; `Strict-Transport-Security`
  (for example `max-age=63072000; includeSubDomains; preload`, only after HTTPS works everywhere);
  drop version detail from `Server` and `X-Powered-By`.
- OWASP Transport Layer Security Cheat Sheet: HTTPS for all pages, redirect HTTP to HTTPS, then HSTS,
  `Secure` cookies, `Cache-Control: no-store` for sensitive responses.

Rate each finding by its own evidence. Do not raise a header rule (HSTS, nosniff) because of cleartext
traffic on other paths; put transport risk on the finding that carries it. Prefer the fix order
"redirect HTTP to HTTPS, then HSTS". `includeSubDomains` and `preload` are risky on shared domains.
