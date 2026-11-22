---
name: asvs-v6-stored-cryptography
description: OWASP ASVS 4.0.3 V6 Stored Cryptography. Load when evidence involves stored cryptography, algorithms, random values, secrets management.
---

OWASP ASVS 4.0.3 V6 Stored Cryptography, verbatim from https://github.com/OWASP/ASVS/tree/v4.0.3/4.0/en. Cite as "ASVS 4.0.3 <id>" only when a cited
finding supports it. Requirements ZAP cannot observe are unverified, never failed.

V6.1 Data Classification
- 6.1.1 [L2,L3, CWE-311] Verify that regulated private data is stored encrypted while at rest, such as Personally Identifiable Information (PII), sensitive personal information, or data assessed likely to be subject to EU's GDPR.
- 6.1.2 [L2,L3, CWE-311] Verify that regulated health data is stored encrypted while at rest, such as medical records, medical device details, or de-anonymized research records.
- 6.1.3 [L2,L3, CWE-311] Verify that regulated financial data is stored encrypted while at rest, such as financial accounts, defaults or credit history, tax records, pay history, beneficiaries, or de-anonymized market or research records.

V6.2 Algorithms
- 6.2.1 [L1,L2,L3, CWE-310] Verify that all cryptographic modules fail securely, and errors are handled in a way that does not enable Padding Oracle attacks.
- 6.2.2 [L2,L3, CWE-327] Verify that industry proven or government approved cryptographic algorithms, modes, and libraries are used, instead of custom coded cryptography.
- 6.2.3 [L2,L3, CWE-326] Verify that encryption initialization vector, cipher configuration, and block modes are configured securely using the latest advice.
- 6.2.4 [L2,L3, CWE-326] Verify that random number, encryption or hashing algorithms, key lengths, rounds, ciphers or modes, can be reconfigured, upgraded, or swapped at any time, to protect against cryptographic breaks.
- 6.2.5 [L2,L3, CWE-326] Verify that known insecure block modes (i.e. ECB, etc.), padding modes (i.e. PKCS#1 v1.5, etc.), ciphers with small block sizes (i.e. Triple-DES, Blowfish, etc.), and weak hashing algorithms (i.e. MD5, SHA1, etc.) are not used unless required for backwards compatibility.
- 6.2.6 [L2,L3, CWE-326] Verify that nonces, initialization vectors, and other single use numbers must not be used more than once with a given encryption key. The method of generation must be appropriate for the algorithm being used.
- 6.2.7 [L3, CWE-326] Verify that encrypted data is authenticated via signatures, authenticated cipher modes, or HMAC to ensure that ciphertext is not altered by an unauthorized party.
- 6.2.8 [L3, CWE-385] Verify that all cryptographic operations are constant-time, with no 'short-circuit' operations in comparisons, calculations, or returns, to avoid leaking information.

V6.3 Random Values
- 6.3.1 [L2,L3, CWE-338] Verify that all random numbers, random file names, random GUIDs, and random strings are generated using the cryptographic module's approved cryptographically secure random number generator when these random values are intended to be not guessable by an attacker.
- 6.3.2 [L2,L3, CWE-338] Verify that random GUIDs are created using the GUID v4 algorithm, and a Cryptographically-secure Pseudo-random Number Generator (CSPRNG). GUIDs created using other pseudo-random number generators may be predictable.
- 6.3.3 [L3, CWE-338] Verify that random numbers are created with proper entropy even when the application is under heavy load, or that the application degrades gracefully in such circumstances.

V6.4 Secret Management
- 6.4.1 [L2,L3, CWE-798] Verify that a secrets management solution such as a key vault is used to securely create, store, control access to and destroy secrets.
- 6.4.2 [L2,L3, CWE-320] Verify that key material is not exposed to the application but instead uses an isolated security module like a vault for cryptographic operations.
