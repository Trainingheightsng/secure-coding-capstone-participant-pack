---
name: [cwe-top25-backend or cwe-top25-frontend — must match your folder name exactly]
description: [Under 200 characters. Say WHEN to use the skill, using words developers type. Example: "Review Java or C# code for the 2025 CWE Top 25 weaknesses. Use for code reviews, pull requests, security checks or 'is this code safe?'"]
---

# [Skill title, for example: Providus backend security review (CWE Top 25)]

## Purpose

[One short paragraph: what this skill does, for whom (Providus developers), and which languages and frameworks it covers.]

## How to review code

Follow these steps for every review:

1. Identify the language and framework of each file.
2. Read `checklist.md`. Go through **all 25 questions** for every file, even after finding a problem.
3. For anything that might be a problem, open the matching file in `references/` (see the index below). Read **Part 1** first: compare the code with "How to spot it" and "Not this weakness". Read Part 2 only if you are still unsure.
4. Report each finding in the format below.
5. If you find nothing, say so clearly and list the checks you made. Never invent a finding.

## How to report a finding

For each finding:

- **CWE:** number and name
- **Where:** file name and line number(s)
- **Severity:** critical, high, medium or low (use the severity guide in the reference file)
- **Why it's dangerous:** one or two sentences, in plain words
- **Fix:** the corrected code

At the end, add a summary table: file, CWE, lines, severity.

## Rules

- [Add your team's rules. Examples: never report a finding without a line number; prefer the fix shown in the reference file; treat AI-generated code with extra care for authentication, limits and input checks.]

## Index of the 25 weaknesses

| CWE | Name | Reference file |
|---|---|---|
| 79 | Cross-site scripting | references/cwe-79-xss.md |
| [Fill in the other 24 rows. Copy the file names exactly from the references folder.] | | |
