---
name: asvs-v3-session-management
description: OWASP ASVS 4.0.3 V3 Session Management. Load when evidence involves session tokens and cookies: Secure, HttpOnly, SameSite, session in URL, logout.
---

OWASP ASVS 4.0.3 V3 Session Management, verbatim from https://github.com/OWASP/ASVS/tree/v4.0.3/4.0/en. Cite as "ASVS 4.0.3 <id>" only when a cited
finding supports it. Requirements ZAP cannot observe are unverified, never failed.

V3.1 Fundamental Session Management Security
- 3.1.1 [L1,L2,L3, CWE-598] Verify the application never reveals session tokens in URL parameters.

V3.2 Session Binding
- 3.2.1 [L1,L2,L3, CWE-384] Verify the application generates a new session token on user authentication.
- 3.2.2 [L1,L2,L3, CWE-331] Verify that session tokens possess at least 64 bits of entropy.
- 3.2.3 [L1,L2,L3, CWE-539] Verify the application only stores session tokens in the browser using secure methods such as appropriately secured cookies (see section 3.4) or HTML 5 session storage.
- 3.2.4 [L2,L3, CWE-331] Verify that session tokens are generated using approved cryptographic algorithms.

V3.3 Session Termination
- 3.3.1 [L1,L2,L3, CWE-613] Verify that logout and expiration invalidate the session token, such that the back button or a downstream relying party does not resume an authenticated session, including across relying parties.
- 3.3.2 [L1=30 days,L2=12 hours or 30 minutes of inactivity, 2FA optional,L3=12 hours or 15 minutes of inactivity, with 2FA, CWE-613] If authenticators permit users to remain logged in, verify that re-authentication occurs periodically both when actively used or after an idle period.
- 3.3.3 [L2,L3, CWE-613] Verify that the application gives the option to terminate all other active sessions after a successful password change (including change via password reset/recovery), and that this is effective across the application, federated login (if present), and any relying parties.
- 3.3.4 [L2,L3, CWE-613] Verify that users are able to view and (having re-entered login credentials) log out of any or all currently active sessions and devices.

V3.4 Cookie-based Session Management
- 3.4.1 [L1,L2,L3, CWE-614] Verify that cookie-based session tokens have the 'Secure' attribute set.
- 3.4.2 [L1,L2,L3, CWE-1004] Verify that cookie-based session tokens have the 'HttpOnly' attribute set.
- 3.4.3 [L1,L2,L3, CWE-16] Verify that cookie-based session tokens utilize the 'SameSite' attribute to limit exposure to cross-site request forgery attacks.
- 3.4.4 [L1,L2,L3, CWE-16] Verify that cookie-based session tokens use the "__Host-" prefix so cookies are only sent to the host that initially set the cookie.
- 3.4.5 [L1,L2,L3, CWE-16] Verify that if the application is published under a domain name with other applications that set or use session cookies that might disclose the session cookies, set the path attribute in cookie-based session tokens using the most precise path possible.

V3.5 Token-based Session Management
- 3.5.1 [L2,L3, CWE-290] Verify the application allows users to revoke OAuth tokens that form trust relationships with linked applications.
- 3.5.2 [L2,L3, CWE-798] Verify the application uses session tokens rather than static API secrets and keys, except with legacy implementations.
- 3.5.3 [L2,L3, CWE-345] Verify that stateless session tokens use digital signatures, encryption, and other countermeasures to protect against tampering, enveloping, replay, null cipher, and key substitution attacks.

V3.6 Federated Re-authentication
- 3.6.1 [L3, CWE-613] Verify that Relying Parties (RPs) specify the maximum authentication time to Credential Service Providers (CSPs) and that CSPs re-authenticate the user if they haven't used a session within that period.
- 3.6.2 [L3, CWE-613] Verify that Credential Service Providers (CSPs) inform Relying Parties (RPs) of the last authentication event, to allow RPs to determine if they need to re-authenticate the user.

V3.7 Defenses Against Session Management Exploits
- 3.7.1 [L1,L2,L3, CWE-306] Verify the application ensures a full, valid login session or requires re-authentication or secondary verification before allowing any sensitive transactions or account modifications.
