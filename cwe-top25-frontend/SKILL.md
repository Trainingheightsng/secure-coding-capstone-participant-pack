---
name: cwe-top25-frontend
description: Review React and Next.js code for the 2025 CWE Top 25 weaknesses. Use for code reviews, pull-request reviews, security checks, or "is this code safe?"
---

# Providus Bank frontend security review (CWE Top 25)

## Purpose

This skill turns on whenever a Providus Bank developer asks for a code review, a pull-request review, a security check, or any variant of "is this code safe?". It checks React and Next.js code (including Node.js API routes) against every weakness on the 2025 MITRE CWE Top 25 list and reports each finding with the information needed to fix it. The 25 reference files in `references/` are the authoritative source for what each weakness looks like in our stack.

## How to review code

Follow these steps for every review, without exception:

1. **Identify the language and framework** of each file (React component, Next.js page, Next.js API route, plain Node.js module, WebAssembly wrapper, etc.).
2. **Open `checklist.md`**. Work through **all 25 questions**, one by one, for every file. Do not stop after finding the first problem; a file can have several weaknesses.
3. **For anything that might be a problem**, open the matching file in `references/` (see the index below). Read **Part 1** first. Compare the suspicious code with the "How to spot it" and "Not this weakness" sections for React / Node.js. Read Part 2 only if you are still unsure after reading Part 1.
4. **Report each confirmed finding** in the format below.
5. **If you find nothing**, say so clearly and list every checklist item you checked. Never invent a finding.

## How to report a finding

For each finding, include all five fields:

- **CWE:** number and name (e.g. CWE-79 Cross-site Scripting)
- **Where:** file name and exact line number(s)
- **Severity:** critical, high, medium, or low — use the "Severity guide (Providus)" section of the matching reference file
- **Why it's dangerous:** one or two plain-English sentences explaining the real-world risk for Providus Bank
- **Fix:** corrected code that removes the weakness — prefer the fix shown in the reference file

After all individual findings, add a **summary table**:

| File | CWE | Lines | Severity |
|------|-----|-------|----------|

## Rules

- Never report a finding without a line number. If the weakness spans multiple lines, give the range.
- If you find nothing suspicious, say "No findings" and list all 25 checks made. Do not leave the reader wondering whether you checked.
- Prefer the fix shown in the matching reference file; adapt it to Providus naming and style.
- Treat AI-generated code with extra care — pay close attention to authentication, authorisation, input limits, and output encoding.
- For CWE-120, CWE-121, CWE-122, CWE-416, and CWE-787 in React/Next.js: flag only WebAssembly modules, native Node add-ons, or code that calls `Buffer.allocUnsafe`. Ordinary JavaScript arrays and `Buffer.alloc` are managed and safe.
- When the same code has two weaknesses (e.g. CWE-862 and CWE-200), report both.
- Severity is a Providus judgement, not just MITRE's score. Stored XSS in banking screens is critical; the same flaw in an internal admin tool may be high.

## Index of the 25 weaknesses

| CWE | Name | Reference file |
|-----|------|----------------|
| 79  | Cross-site Scripting | references/cwe-79-xss.md |
| 89  | SQL Injection | references/cwe-89-sql-injection.md |
| 78  | OS Command Injection | references/cwe-78-os-command-injection.md |
| 77  | Command Injection | references/cwe-77-command-injection.md |
| 94  | Code Injection | references/cwe-94-code-injection.md |
| 862 | Missing Authorization | references/cwe-862-missing-authorization.md |
| 863 | Incorrect Authorization | references/cwe-863-incorrect-authorization.md |
| 284 | Improper Access Control | references/cwe-284-improper-access-control.md |
| 639 | Authorization Bypass Through User-Controlled Key (IDOR) | references/cwe-639-authorization-bypass-user-controlled-key.md |
| 306 | Missing Authentication for Critical Function | references/cwe-306-missing-authentication.md |
| 20  | Improper Input Validation | references/cwe-20-improper-input-validation.md |
| 22  | Path Traversal | references/cwe-22-path-traversal.md |
| 434 | Unrestricted Upload of Dangerous File Type | references/cwe-434-unrestricted-upload.md |
| 918 | Server-Side Request Forgery (SSRF) | references/cwe-918-ssrf.md |
| 352 | Cross-Site Request Forgery (CSRF) | references/cwe-352-csrf.md |
| 787 | Out-of-bounds Write | references/cwe-787-out-of-bounds-write.md |
| 125 | Out-of-bounds Read | references/cwe-125-out-of-bounds-read.md |
| 120 | Classic Buffer Overflow | references/cwe-120-classic-buffer-overflow.md |
| 121 | Stack-based Buffer Overflow | references/cwe-121-stack-buffer-overflow.md |
| 122 | Heap-based Buffer Overflow | references/cwe-122-heap-buffer-overflow.md |
| 416 | Use After Free | references/cwe-416-use-after-free.md |
| 476 | NULL Pointer Dereference | references/cwe-476-null-pointer-dereference.md |
| 502 | Deserialization of Untrusted Data | references/cwe-502-deserialization.md |
| 200 | Sensitive Information Exposure | references/cwe-200-sensitive-information-exposure.md |
| 770 | Allocation of Resources Without Limits or Throttling | references/cwe-770-allocation-without-limits.md |
