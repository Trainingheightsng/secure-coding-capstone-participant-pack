# CWE-863: Incorrect Authorization

> **2025 CWE Top 25:** rank 17 · score 4.14 · CVEs in CISA KEV: 4 · change since 2024: +1

## Part 1: Review guide

### What it is, in plain words

An authorisation check exists, but it is wrong or incomplete: it checks the wrong thing, misses a condition, or can be bypassed.

### How to spot it

**Java**
- `hasRole` checks without business rules (limits, maker-checker, status)
- Checks using data from the request (`role` field, header) instead of the session
- Path matchers that miss variants (`/admin` vs `/admin/`)

**C#**
- Policies that check role but not amount limits or ownership
- `User.IsInRole` with case or claim-type mistakes
- Middleware order putting authorisation before authentication

**React / Node.js**
- Server checks trusting `req.body.role` or a client-supplied header
- Approval routes that don't stop users approving their own requests

### Not this weakness (safe look-alikes)

- Centralised policies that check role, ownership and business rules together, using server-side identity.

### How to tell it apart from related weaknesses

A check that exists but is wrong is CWE-863. No check is CWE-862. Record ownership from a user-chosen key is CWE-639. Broader design-level access problems are CWE-284.

### Vulnerable and secure examples

#### Java

Vulnerable:

```java
@PreAuthorize("hasRole('APPROVER')")
void approve(long id) {
  Transfer t = repo.findById(id).orElseThrow();
  t.setStatus(APPROVED);
}
```

Why: Right role, but no check of maker, limit or status.

Secure:

```java
@PreAuthorize("hasRole('APPROVER')")
void approve(long id, User me) {
  Transfer t = repo.findById(id).orElseThrow();
  if (t.getCreatedBy().equals(me.getId())
    || t.getAmount().compareTo(me.getLimit()) > 0
    || t.getStatus() != PENDING) throw denied();
  t.setStatus(APPROVED);
}
```

Why it works: Maker isn’t checker, within limit, still pending.

#### C#

Vulnerable:

```csharp
[Authorize(Roles = "Approver")]
[HttpPost("{id}/approve")]
public async Task<IActionResult> Approve(long id) {
  var t = await db.Transfers.FindAsync(id);
  t.Status = Status.Approved;
```

Why: The same gap: the role is checked, the business rule isn’t.

Secure:

```csharp
var t = await db.Transfers.FindAsync(id);
if (t is null || t.CreatedBy == me.Id
    || t.Amount > me.ApprovalLimit
    || t.Status != Status.Pending)
  return Forbid();
t.Status = Status.Approved;
```

Why it works: All four conditions, on the server.

#### React / Node.js

*Context:* The UI decides what to show. The API must repeat every check, because anyone can call it directly.

Vulnerable:

```jsx
const canApprove = user.role === "APPROVER";
// own transfers and limits not considered
{canApprove && (
  <button onClick={() => approve(t.id)}>
    Approve</button>)}
```

Why: The screen offers Approve on the approver’s own transfer.

Secure:

```jsx
const canApprove = user.role === "APPROVER"
  && t.createdBy !== user.id
  && t.amount <= user.approvalLimit
  && t.status === "PENDING";
{canApprove && <ApproveButton id={t.id} />}
```

Why it works: The screen reflects the whole rule. The API enforces it.

### Fix guidance

**Primary defences**

1. **Check the rule, not just the role.** Maker isn’t checker, limits, status, entity.
2. **One central policy.** In the service layer, used by every entry point.
3. **Deny by default.** Every condition must pass.

**Defence in depth**

- Same-user and two-user tests
- Limits stored server-side
- Verify role claims in tokens
- Alert on denied approvals

**In each stack**

- Java: @PreAuthorize + service checks
- C#: IAuthorizationService handlers
- React / Node.js: Hide actions for UX only

**Don't rely on**

- Role checks alone
- Limits enforced in the UI
- Unverified role claims

### How to verify the fix

The maker gets 403 when approving their own transfer.

### Severity guide (Providus)

Critical for approvals, limits and maker-checker in payments; high otherwise.

---

## Part 2: MITRE CWE entry (complete)

**Abstraction:** Class · **Structure:** Simple · **Status:** Incomplete  
**MITRE page:** https://cwe.mitre.org/data/definitions/863.html
  
**MITRE diagram:** https://cwe.mitre.org/data/images/CWE-863-Diagram.png

### Description

The product performs an authorization check when an actor attempts to access a resource or perform an action, but it does not correctly perform the check.

### Alternate terms

- **AuthZ**: "AuthZ" is typically used as an abbreviation of "authorization" within the web application security community. It is distinct from "AuthN" (or, sometimes, "AuthC") which is an abbreviation of "authentication." The use of "Auth" as an abbreviation is discouraged, since it could be used for either authentication or authorization.

### Background details

An access control list (ACL) represents who/what has permissions to a given object. Different operating systems implement (ACLs) in different ways. In UNIX, there are three types of permissions: read, write, and execute. Users are divided into three classes for file access: owner, group owner, and all other users where each class has a separate set of rights. In Windows NT, there are four basic types of permissions for files: "No access", "Read access", "Change access", and "Full control". Windows NT extends the concept of three types of users in UNIX to include a list of users and groups along with their associated permissions. A user can create an object (file) and assign specified permissions to that object.

### Common consequences

| Scope | Impact | Likelihood | Note |
|---|---|---|---|
| Confidentiality | Read Application Data, Read Files or Directories |  | An attacker could bypass intended access restrictions to read sensitive data, either by reading the data directly from a data store that is not correctly restricted, or by accessing insufficiently-protected, privileged functionality to read the data. |
| Integrity | Modify Application Data, Modify Files or Directories |  | An attacker could bypass intended access restrictions to modify sensitive data, either by writing the data directly to a data store that is not correctly restricted, or by accessing insufficiently-protected, privileged functionality to write the data. |
| Access Control | Gain Privileges or Assume Identity, Bypass Protection Mechanism |  | An attacker could bypass intended access restrictions to gain privileges by modifying or reading critical data directly, or by accessing privileged functionality. |
| Confidentiality, Integrity, Availability | Execute Unauthorized Code or Commands |  | An attacker could use elevated privileges to execute unauthorized commands or code. |
| Availability | DoS: Crash, Exit, or Restart, DoS: Resource Consumption (CPU), DoS: Resource Consumption (Memory), DoS: Resource Consumption (Other) |  | An attacker could gain unauthorized access to resources on the system and excessively consume those resources, leading to a denial of service. |

### Likelihood of exploit

High

### Modes of introduction

- **Architecture and Design**: Authorization weaknesses may arise when a single-user application is ported to a multi-user environment.
- **Implementation**: REALIZATION: This weakness is caused during implementation of an architectural security tactic.

A developer may introduce authorization weaknesses because of a lack of understanding about the underlying technologies. For example, a developer may assume that attackers cannot modify certain inputs such as headers or cookies.
- **Operation**

### Applicable platforms

- Language: Class: Not Language-Specific (Undetermined)
- Language: Go (Undetermined)
- Technology: Web Server (Often)
- Technology: Database Server (Often)
- Technology: Class: Not Technology-Specific (Undetermined)

### Weakness ordinalities

- **Primary**
- **Resultant**

### Potential mitigations

**1. Phase: Architecture and Design**

Divide the product into anonymous, normal, privileged, and administrative areas. Reduce the attack surface by carefully mapping roles with data and functionality. Use role-based access control (RBAC) [REF-229] to enforce the roles at the appropriate boundaries.

Note that this approach may not protect against horizontal authorization, i.e., it will not protect a user from attacking others with the same role.

**2. Phase: Architecture and Design**

Ensure that access control checks are performed related to the business logic. These checks may be different than the access control checks that are applied to more generic resources such as files, connections, processes, memory, and database records. For example, a database may restrict access for medical records to a specific database user, but each record might only be intended to be accessible to the patient and the patient's doctor [REF-7].

**3. Phase: Architecture and Design** · Strategy: Libraries or Frameworks · ID: MIT-4.4

Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.

For example, consider using authorization frameworks such as the JAAS Authorization Framework [REF-233] and the OWASP ESAPI Access Control feature [REF-45].

**4. Phase: Architecture and Design**

For web applications, make sure that the access control mechanism is enforced correctly at the server side on every page. Users should not be able to access any unauthorized functionality or information by simply requesting direct access to that page.

One way to do this is to ensure that all pages containing sensitive information are not cached, and that all such pages restrict access to requests that are accompanied by an active and authenticated session token associated with a user who has the required permissions to access that page.

**5. Phase: System Configuration, Installation**

Use the access control capabilities of your operating system and server environment and define your access control lists accordingly. Use a "default deny" policy when defining these ACLs.

### Detection methods

**Automated Static Analysis** (effectiveness: Limited)

Automated static analysis is useful for detecting commonly-used idioms for authorization. A tool may be able to analyze related configuration files, such as .htaccess in Apache web servers, or detect the usage of commonly-used authorization libraries.

Generally, automated static analysis tools have difficulty detecting custom authorization schemes. Even if they can be customized to recognize these schemes, they might not be able to tell whether the scheme correctly performs the authorization in a way that cannot be bypassed or subverted by an attacker.

**Automated Dynamic Analysis**

Automated dynamic analysis may not be able to find interfaces that are protected by authorization checks, even if those checks contain weaknesses.

**Manual Analysis** (effectiveness: Moderate)

This weakness can be detected using tools and techniques that require manual (human) analysis, such as penetration testing, threat modeling, and interactive tools that allow the tester to record and modify an active session.

Specifically, manual static analysis is useful for evaluating the correctness of custom authorization mechanisms.

*These may be more effective than strictly automated techniques. This is especially the case with weaknesses that are related to design and business rules. However, manual efforts might not achieve desired code coverage within limited time constraints.*

**Manual Static Analysis - Binary or Bytecode** (effectiveness: SOAR Partial)

According to SOAR [REF-1479], the following detection techniques may be useful:

Cost effective for partial coverage:
- Binary / Bytecode disassembler - then use manual analysis for vulnerabilities & anomalies

**Dynamic Analysis with Automated Results Interpretation** (effectiveness: SOAR Partial)

According to SOAR [REF-1479], the following detection techniques may be useful:

Cost effective for partial coverage:
- Web Application Scanner
- Web Services Scanner
- Database Scanners

**Dynamic Analysis with Manual Results Interpretation** (effectiveness: SOAR Partial)

According to SOAR [REF-1479], the following detection techniques may be useful:

Cost effective for partial coverage:
- Host Application Interface Scanner
- Fuzz Tester
- Framework-based Fuzzer
- Forced Path Execution
- Monitored Virtual Environment - run potentially malicious code in sandbox / wrapper / virtual machine, see if it does anything suspicious

**Manual Static Analysis - Source Code** (effectiveness: SOAR Partial)

According to SOAR [REF-1479], the following detection techniques may be useful:

Cost effective for partial coverage:
- Focused Manual Spotcheck - Focused manual analysis of source
- Manual Source Code Review (not inspections)

**Automated Static Analysis - Source Code** (effectiveness: SOAR Partial)

According to SOAR [REF-1479], the following detection techniques may be useful:

Cost effective for partial coverage:
- Context-configured Source Code Weakness Analyzer

**Architecture or Design Review** (effectiveness: High)

According to SOAR [REF-1479], the following detection techniques may be useful:

Highly cost effective:
- Formal Methods / Correct-By-Construction

Cost effective for partial coverage:
- Inspection (IEEE 1028 standard) (can apply to requirements, design, source code, etc.)

### Demonstrative examples

**Example 1**

The following code could be for a medical records application. It displays a record to already authenticated users, confirming the user's authorization using a value stored in a cookie.

*Bad code (PHP):*

```php
$role = $_COOKIES['role'];
if (!$role) {
    $role = getRole('user');
    if ($role) {
        // save the cookie to send out in future responses
        setcookie("role", $role, time()+60*60*2);
    }
    else{
        ShowLoginScreen();
        die("\n");
    }
}
if ($role == 'Reader') {
    DisplayMedicalHistory($_POST['patient_ID']);
}
else{
    die("You are not Authorized to view this record\n");
}
```

The programmer expects that the cookie will only be set when getRole() succeeds. The programmer even diligently specifies a 2-hour expiration for the cookie. However, the attacker can easily set the "role" cookie to the value "Reader". As a result, the $role variable is "Reader", and getRole() is never invoked. The attacker has bypassed the authorization system.

### Observed examples (real vulnerabilities)

| Reference | Description |
|---|---|
| [CVE-2025-24839](https://www.cve.org/CVERecord?id=CVE-2025-24839) | collaboration platform allows attacker to access an AI bot by using a plugin to set a critical property |
| [CVE-2025-32796](https://www.cve.org/CVERecord?id=CVE-2025-32796) | LLM application development platform allows non-admin users to enable or disable apps using certain API endpoints |
| [CVE-2021-39155](https://www.cve.org/CVERecord?id=CVE-2021-39155) | Chain: A microservice integration and management platform compares the hostname in the HTTP Host header in a case-sensitive way (CWE-178, CWE-1289), allowing bypass of the authorization policy (CWE-863) using a hostname with mixed case or other variations. |
| [CVE-2019-15900](https://www.cve.org/CVERecord?id=CVE-2019-15900) | Chain: sscanf() call is used to check if a username and group exists, but the return value of sscanf() call is not checked (CWE-252), causing an uninitialized variable to be checked (CWE-457), returning success to allow authorization bypass for executing a privileged (CWE-863). |
| [CVE-2009-2213](https://www.cve.org/CVERecord?id=CVE-2009-2213) | Gateway uses default "Allow" configuration for its authorization settings. |
| [CVE-2009-0034](https://www.cve.org/CVERecord?id=CVE-2009-0034) | Chain: product does not properly interpret a configuration option for a system group, allowing users to gain privileges. |
| [CVE-2008-6123](https://www.cve.org/CVERecord?id=CVE-2008-6123) | Chain: SNMP product does not properly parse a configuration option for which hosts are allowed to connect, allowing unauthorized IP addresses to connect. |
| [CVE-2008-7109](https://www.cve.org/CVERecord?id=CVE-2008-7109) | Chain: reliance on client-side security (CWE-602) allows attackers to bypass authorization using a custom client. |
| [CVE-2008-3424](https://www.cve.org/CVERecord?id=CVE-2008-3424) | Chain: product does not properly handle wildcards in an authorization policy list, allowing unintended access. |
| [CVE-2008-4577](https://www.cve.org/CVERecord?id=CVE-2008-4577) | ACL-based protection mechanism treats negative access rights as if they are positive, allowing bypass of intended restrictions. |
| [CVE-2006-6679](https://www.cve.org/CVERecord?id=CVE-2006-6679) | Product relies on the X-Forwarded-For HTTP header for authorization, allowing unintended access by spoofing the header. |
| [CVE-2005-2801](https://www.cve.org/CVERecord?id=CVE-2005-2801) | Chain: file-system code performs an incorrect comparison (CWE-697), preventing default ACLs from being properly applied. |
| [CVE-2001-1155](https://www.cve.org/CVERecord?id=CVE-2001-1155) | Chain: product does not properly check the result of a reverse DNS lookup because of operator precedence (CWE-783), allowing bypass of DNS-based access restrictions. |

### Relationships

Includes relationships recorded on this entry and those recorded on other entries that point to it (as MITRE's page shows them).

| Nature | CWE | Name | View | Recorded on |
|---|---|---|---|---|
| ChildOf (primary) | CWE-285 | Improper Authorization | 1000 Complete Weakness Hierarchy | this entry |
| ChildOf (primary) | CWE-284 | Improper Access Control | 1340 CISQ Data Protection Measures | this entry |
| ParentOf | CWE-551 | Incorrect Behavior Order: Authorization Before Parsing and Canonicalization | 1000 Complete Weakness Hierarchy | CWE-551 |
| ParentOf | CWE-639 | Authorization Bypass Through User-Controlled Key | 1000 Complete Weakness Hierarchy | CWE-639 |
| ParentOf | CWE-647 | Use of Non-Canonical URL Paths for Authorization Decisions | 1000 Complete Weakness Hierarchy | CWE-647 |
| ParentOf | CWE-804 | Guessable CAPTCHA | 1000 Complete Weakness Hierarchy | CWE-804 |
| ParentOf | CWE-942 | Permissive Cross-domain Security Policy with Untrusted Domains | 1000 Complete Weakness Hierarchy | CWE-942 |
| ParentOf | CWE-1244 | Internal Asset Exposed to Unsafe Debug Access Level or State | 1000 Complete Weakness Hierarchy | CWE-1244 |
| ParentOf | CWE-639 | Authorization Bypass Through User-Controlled Key | 1003 Weaknesses for Simplified Mapping of Published Vulnerabilities | CWE-639 |
| CanFollow | CWE-41 | Improper Resolution of Path Equivalence | 1000 Complete Weakness Hierarchy | CWE-41 |

### Taxonomy mappings

| Taxonomy | Entry ID | Entry name | Fit |
|---|---|---|---|
| ISA/IEC 62443 | Part 4-1 | Req SD-4 |  |
| ISA/IEC 62443 | Part 4-2 | Req CR 2.1 |  |
| ISA/IEC 62443 | Part 4-2 | Req CR 2.2 |  |
| ISA/IEC 62443 | Part 3-3 | Req SR 2.1 |  |
| ISA/IEC 62443 | Part 3-3 | Req SR 2.2 |  |
| ISA/IEC 62443 | Part 4-1 | Req SVV-1 |  |
| ISA/IEC 62443 | Part 4-1 | Req SVV-4 |  |
| ISA/IEC 62443 | Part 4-1 | Req SD-1 |  |
| OWASP Golang Secure Coding Practices Guide |  | Access Control |  |

### Vulnerability mapping notes

**Usage:** Allowed-with-Review

**Rationale:** This CWE entry is a Class and might have Base-level children that would be more appropriate

**Comments:** Examine children of this entry to see if there is a better fit

**Reasons:** Abstraction

### Notes

**Terminology:** Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-control specifications that apply to the resource.

### Dimensions

Behavior-Property: Incorrect; Behavior-Type: Authorization

### Memberships

Categories and views this entry belongs to (for example OWASP Top Ten and earlier CWE Top 25 lists).

| Type | ID | Name |
|---|---|---|
| Category | 813 | OWASP Top Ten 2010 Category A4 - Insecure Direct Object References |
| Category | 817 | OWASP Top Ten 2010 Category A8 - Failure to Restrict URL Access |
| Category | 866 | 2011 Top 25 - Porous Defenses |
| View | 884 | CWE Cross-section |
| View | 1003 | Weaknesses for Simplified Mapping of Published Vulnerabilities |
| Category | 1011 | Authorize Actors |
| Category | 1345 | OWASP Top Ten 2021 Category A01:2021 - Broken Access Control |
| Category | 1396 | Comprehensive Categorization: Access Control |
| View | 1425 | Weaknesses in the 2023 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1430 | Weaknesses in the 2024 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1435 | Weaknesses in the 2025 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1436 | OWASP Top Ten 2025 Category A01:2025 - Broken Access Control |
| View | 1468 | Weaknesses Addressed by the OWASP Golang Secure Coding Practices Guide |

### References

- [REF-229] NIST. "Role Based Access Control and Role Based Security". https://csrc.nist.gov/projects/role-based-access-control
- [REF-7] Michael Howard, David LeBlanc. "Writing Secure Code", 2002, Chapter 4, "Authorization" Page 114; Chapter 6, "Determining
                  Appropriate Access Control" Page 171. https://www.microsoftpressstore.com/store/writing-secure-code-9780735617223
- [REF-231] Frank Kim. "Top 25 Series - Rank 5 - Improper Access Control (Authorization)", 2010. https://www.sans.org/blog/top-25-series-rank-5-improper-access-control-authorization
- [REF-233] Rahul Bhattacharjee. "Authentication using JAAS". https://javaranch.com/journal/2008/04/authentication-using-JAAS.html
- [REF-45] OWASP. "OWASP Enterprise Security API (ESAPI) Project". https://owasp.org/www-project-enterprise-security-api/
- [REF-62] Mark Dowd, John McDonald, Justin Schuh. "The Art of Software Security Assessment", 2006, Chapter 2, "Common Vulnerabilities of Authorization", Page 39
- [REF-1479] Gregory Larsen, E. Kenneth Hong Fong, David A. Wheeler, Rama S. Moorthy. "State-of-the-Art Resources (SOAR) for Software Vulnerability Detection, Test, and Evaluation", 2014. https://www.ida.org/-/media/feature/publications/s/st/stateoftheart-resources-soar-for-software-vulnerability-detection-test-and-evaluation/p-5061.ashx
- [REF-1566] OWASP. "Golang Secure Coding Practices guide", 2024, Access Control, page 31. https://github.com/OWASP/Go-SCP

### Content history (summary)

- Submitted: 2011-05-24 by MITRE
- Modified 25 times; latest: 2026-10-28
- Full history: https://cwe.mitre.org/data/definitions/863.html#Content_History

---

*Part 2 is taken from the MITRE CWE List, version 5.0 (2026-10-28), https://cwe.mitre.org. Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation. Used under the CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html). Part 1 was written for the Providus Bank Secure Coding programme by Training Heights.*
