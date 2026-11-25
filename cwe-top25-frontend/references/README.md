# CWE Top 25 (2025) reference files

One file per weakness in MITRE's 2025 CWE Top 25, for the capstone code-review skill. Copy them into the skill's `references/` folder.

Each file has two parts:

1. **Review guide**: plain-language meaning, how to spot it in Java, C# and React/Node, safe look-alikes, how to tell it apart from related CWEs, vulnerable and secure code, fix guidance, how to verify, and a severity guide.
2. **MITRE CWE entry (complete)**: every field of MITRE's entry from CWE v5.0: description, extended description, alternate terms, consequences, likelihood, modes of introduction, platforms, all potential mitigations, detection methods, demonstrative examples with code, observed CVEs, relationships, CAPEC attack patterns, taxonomy mappings, mapping notes, notes, memberships (OWASP Top Ten and past Top 25 lists), references, and a summary of the entry history (dates and previous names; the full change log stays on MITRE.s site).

| Rank | CWE | Name | File |
|---|---|---|---|
| 1 | CWE-79 | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') | [cwe-79-xss.md](cwe-79-xss.md) |
| 2 | CWE-89 | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') | [cwe-89-sql-injection.md](cwe-89-sql-injection.md) |
| 3 | CWE-352 | Cross-Site Request Forgery (CSRF) | [cwe-352-csrf.md](cwe-352-csrf.md) |
| 4 | CWE-862 | Missing Authorization | [cwe-862-missing-authorization.md](cwe-862-missing-authorization.md) |
| 5 | CWE-787 | Out-of-bounds Write | [cwe-787-out-of-bounds-write.md](cwe-787-out-of-bounds-write.md) |
| 6 | CWE-22 | Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | [cwe-22-path-traversal.md](cwe-22-path-traversal.md) |
| 7 | CWE-416 | Use After Free | [cwe-416-use-after-free.md](cwe-416-use-after-free.md) |
| 8 | CWE-125 | Out-of-bounds Read | [cwe-125-out-of-bounds-read.md](cwe-125-out-of-bounds-read.md) |
| 9 | CWE-78 | Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') | [cwe-78-os-command-injection.md](cwe-78-os-command-injection.md) |
| 10 | CWE-94 | Improper Control of Generation of Code ('Code Injection') | [cwe-94-code-injection.md](cwe-94-code-injection.md) |
| 11 | CWE-120 | Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') | [cwe-120-classic-buffer-overflow.md](cwe-120-classic-buffer-overflow.md) |
| 12 | CWE-434 | Unrestricted Upload of File with Dangerous Type | [cwe-434-unrestricted-upload.md](cwe-434-unrestricted-upload.md) |
| 13 | CWE-476 | NULL Pointer Dereference | [cwe-476-null-pointer-dereference.md](cwe-476-null-pointer-dereference.md) |
| 14 | CWE-121 | Stack-based Buffer Overflow | [cwe-121-stack-buffer-overflow.md](cwe-121-stack-buffer-overflow.md) |
| 15 | CWE-502 | Deserialization of Untrusted Data | [cwe-502-deserialization.md](cwe-502-deserialization.md) |
| 16 | CWE-122 | Heap-based Buffer Overflow | [cwe-122-heap-buffer-overflow.md](cwe-122-heap-buffer-overflow.md) |
| 17 | CWE-863 | Incorrect Authorization | [cwe-863-incorrect-authorization.md](cwe-863-incorrect-authorization.md) |
| 18 | CWE-20 | Improper Input Validation | [cwe-20-improper-input-validation.md](cwe-20-improper-input-validation.md) |
| 19 | CWE-284 | Improper Access Control | [cwe-284-improper-access-control.md](cwe-284-improper-access-control.md) |
| 20 | CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | [cwe-200-sensitive-information-exposure.md](cwe-200-sensitive-information-exposure.md) |
| 21 | CWE-306 | Missing Authentication for Critical Function | [cwe-306-missing-authentication.md](cwe-306-missing-authentication.md) |
| 22 | CWE-918 | Server-Side Request Forgery (SSRF) | [cwe-918-ssrf.md](cwe-918-ssrf.md) |
| 23 | CWE-77 | Improper Neutralization of Special Elements used in a Command ('Command Injection') | [cwe-77-command-injection.md](cwe-77-command-injection.md) |
| 24 | CWE-639 | Authorization Bypass Through User-Controlled Key | [cwe-639-authorization-bypass-user-controlled-key.md](cwe-639-authorization-bypass-user-controlled-key.md) |
| 25 | CWE-770 | Allocation of Resources Without Limits or Throttling | [cwe-770-allocation-without-limits.md](cwe-770-allocation-without-limits.md) |

*Part 2 is taken from the MITRE CWE List, version 5.0 (2026-10-28), https://cwe.mitre.org. Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation. Used under the CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html). Part 1 was written for the Providus Bank Secure Coding programme by Training Heights.*
