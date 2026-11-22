---
name: asvs-v12-files-and-resources
description: OWASP ASVS 4.0.3 V12 Files and Resources. Load when evidence involves file upload, file execution, path traversal, SSRF.
---

OWASP ASVS 4.0.3 V12 Files and Resources, verbatim from https://github.com/OWASP/ASVS/tree/v4.0.3/4.0/en. Cite as "ASVS 4.0.3 <id>" only when a cited
finding supports it. Requirements ZAP cannot observe are unverified, never failed.

V12.1 File Upload
- 12.1.1 [L1,L2,L3, CWE-400] Verify that the application will not accept large files that could fill up storage or cause a denial of service.
- 12.1.2 [L2,L3, CWE-409] Verify that the application checks compressed files (e.g. zip, gz, docx, odt) against maximum allowed uncompressed size and against maximum number of files before uncompressing the file.
- 12.1.3 [L2,L3, CWE-770] Verify that a file size quota and maximum number of files per user is enforced to ensure that a single user cannot fill up the storage with too many files, or excessively large files.

V12.2 File Integrity
- 12.2.1 [L2,L3, CWE-434] Verify that files obtained from untrusted sources are validated to be of expected type based on the file's content.

V12.3 File Execution
- 12.3.1 [L1,L2,L3, CWE-22] Verify that user-submitted filename metadata is not used directly by system or framework filesystems and that a URL API is used to protect against path traversal.
- 12.3.2 [L1,L2,L3, CWE-73] Verify that user-submitted filename metadata is validated or ignored to prevent the disclosure, creation, updating or removal of local files (LFI).
- 12.3.3 [L1,L2,L3, CWE-98] Verify that user-submitted filename metadata is validated or ignored to prevent the disclosure or execution of remote files via Remote File Inclusion (RFI) or Server-side Request Forgery (SSRF) attacks.
- 12.3.4 [L1,L2,L3, CWE-641] Verify that the application protects against Reflective File Download (RFD) by validating or ignoring user-submitted filenames in a JSON, JSONP, or URL parameter, the response Content-Type header should be set to text/plain, and the Content-Disposition header should have a fixed filename.
- 12.3.5 [L1,L2,L3, CWE-78] Verify that untrusted file metadata is not used directly with system API or libraries, to protect against OS command injection.
- 12.3.6 [L2,L3, CWE-829] Verify that the application does not include and execute functionality from untrusted sources, such as unverified content distribution networks, JavaScript libraries, node npm libraries, or server-side DLLs.

V12.4 File Storage
- 12.4.1 [L1,L2,L3, CWE-552] Verify that files obtained from untrusted sources are stored outside the web root, with limited permissions.
- 12.4.2 [L1,L2,L3, CWE-509] Verify that files obtained from untrusted sources are scanned by antivirus scanners to prevent upload and serving of known malicious content.

V12.5 File Download
- 12.5.1 [L1,L2,L3, CWE-552] Verify that the web tier is configured to serve only files with specific file extensions to prevent unintentional information and source code leakage. For example, backup files (e.g. .bak), temporary working files (e.g. .swp), compressed files (.zip, .tar.gz, etc) and other extensions commonly used by editors should be blocked unless required.
- 12.5.2 [L1,L2,L3, CWE-434] Verify that direct requests to uploaded files will never be executed as HTML/JavaScript content.

V12.6 SSRF Protection
- 12.6.1 [L1,L2,L3, CWE-918] Verify that the web or application server is configured with an allow list of resources or systems to which the server can send requests or load data/files from.
