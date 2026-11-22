---
name: asvs-v13-api-and-web-service
description: OWASP ASVS 4.0.3 V13 API and Web Service. Load when evidence involves web service and REST/GraphQL API, content types, CORS.
---

OWASP ASVS 4.0.3 V13 API and Web Service, verbatim from https://github.com/OWASP/ASVS/tree/v4.0.3/4.0/en. Cite as "ASVS 4.0.3 <id>" only when a cited
finding supports it. Requirements ZAP cannot observe are unverified, never failed.

V13.1 Generic Web Service Security
- 13.1.1 [L1,L2,L3, CWE-116] Verify that all application components use the same encodings and parsers to avoid parsing attacks that exploit different URI or file parsing behavior that could be used in SSRF and RFI attacks.
- 13.1.2 [] [DELETED, DUPLICATE OF 4.3.1]
- 13.1.3 [L1,L2,L3, CWE-598] Verify API URLs do not expose sensitive information, such as the API key, session tokens etc.
- 13.1.4 [L2,L3, CWE-285] Verify that authorization decisions are made at both the URI, enforced by programmatic or declarative security at the controller or router, and at the resource level, enforced by model-based permissions.
- 13.1.5 [L2,L3, CWE-434] Verify that requests containing unexpected or missing content types are rejected with appropriate headers (HTTP response status 406 Unacceptable or 415 Unsupported Media Type).

V13.2 RESTful Web Service
- 13.2.1 [L1,L2,L3, CWE-650] Verify that enabled RESTful HTTP methods are a valid choice for the user or action, such as preventing normal users using DELETE or PUT on protected API or resources.
- 13.2.2 [L1,L2,L3, CWE-20] Verify that JSON schema validation is in place and verified before accepting input.
- 13.2.3 [L1,L2,L3, CWE-352] Verify that RESTful web services that utilize cookies are protected from Cross-Site Request Forgery via the use of at least one or more of the following: double submit cookie pattern, CSRF nonces, or Origin request header checks.
- 13.2.4 [] [DELETED, DUPLICATE OF 11.1.4]
- 13.2.5 [L2,L3, CWE-436] Verify that REST services explicitly check the incoming Content-Type to be the expected one, such as application/xml or application/json.
- 13.2.6 [L2,L3, CWE-345] Verify that the message headers and payload are trustworthy and not modified in transit. Requiring strong encryption for transport (TLS only) may be sufficient in many cases as it provides both confidentiality and integrity protection. Per-message digital signatures can provide additional assurance on top of the transport protections for high-security applications but bring with them additional complexity and risks to weigh against the benefits.

V13.3 SOAP Web Service
- 13.3.1 [L1,L2,L3, CWE-20] Verify that XSD schema validation takes place to ensure a properly formed XML document, followed by validation of each input field before any processing of that data takes place.
- 13.3.2 [L2,L3, CWE-345] Verify that the message payload is signed using WS-Security to ensure reliable transport between client and service.

V13.4 GraphQL
- 13.4.1 [L2,L3, CWE-770] Verify that a query allow list or a combination of depth limiting and amount limiting is used to prevent GraphQL or data layer expression Denial of Service (DoS) as a result of expensive, nested queries. For more advanced scenarios, query cost analysis should be used.
- 13.4.2 [L2,L3, CWE-285] Verify that GraphQL or other data layer authorization logic should be implemented at the business logic layer instead of the GraphQL layer.
