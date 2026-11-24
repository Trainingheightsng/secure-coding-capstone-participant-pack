# CWE-862: Missing Authorization

> **2025 CWE Top 25:** rank 4 · score 13.28 · CVEs in CISA KEV: 0 · change since 2024: +5

## Part 1: Review guide

### What it is, in plain words

The code checks who the user is but never checks whether they are allowed to perform this action or see this data.

### How to spot it

**Java**
- Controller methods with no `@PreAuthorize`/`@Secured`/`@RolesAllowed` while siblings have one
- `authorizeHttpRequests` with `anyRequest().authenticated()` only, for admin or approval endpoints
- Service methods that act on a role-restricted resource without any role or permission check

**C#**
- Actions or controllers with `[Authorize]` but no policy or role where the action is privileged
- `[AllowAnonymous]` on actions that change data
- Minimal API endpoints with no `.RequireAuthorization("Policy")`

**React / Node.js**
- Hiding buttons or routes in React (`{isAdmin && <Button/>}`) with no matching server check
- Express/Next.js API routes that check `req.user` exists but not its role
- Admin features protected only by an unguessable URL

### Not this weakness (safe look-alikes)

- Endpoints that are meant for every logged-in customer and only touch the caller's own data (e.g., `/me`).
- A role check done centrally (method security, policy, middleware) that covers the endpoint.

### How to tell it apart from related weaknesses

No permission check at all is CWE-862. A check that exists but is wrong or incomplete is CWE-863. A check on the wrong record (an ID the user picks) is CWE-639. No login at all is CWE-306.

### Vulnerable and secure examples

#### Java

Vulnerable:

```java
@DeleteMapping("/admin/users/{id}")
public void deleteUser(@PathVariable long id) {   // any logged-in user
    users.deleteById(id);
}
```

Why: Logged in is enough to delete any user.

Secure:

```java
@PreAuthorize("hasRole('USER_ADMIN')")
@DeleteMapping("/admin/users/{id}")
public void deleteUser(@PathVariable long id) { users.deleteById(id); }
```

Why it works: Method security requires the admin role.

#### C#

Vulnerable:

```csharp
[Authorize]
[HttpPost("limits/{accountId}")]
public IActionResult RaiseLimit(long accountId, decimal limit) { ... }
```

Why: `[Authorize]` only checks login, not permission.

Secure:

```csharp
[Authorize(Policy = "CanChangeLimits")]
[HttpPost("limits/{accountId}")]
public IActionResult RaiseLimit(long accountId, decimal limit) { ... }
```

Why it works: A policy requires the right permission.

#### React / Node.js

Vulnerable:

```jsx
{user.isAdmin && <Button onClick={freezeAccount}>Freeze</Button>}
// server: app.post("/api/freeze", requireLogin, freeze)
```

Why: The button is hidden, but the API accepts anyone logged in.

Secure:

```jsx
app.post("/api/freeze", requireLogin, requireRole("ops-admin"), freeze);
```

Why it works: The server enforces the role; the UI just reflects it.

### Fix guidance

**Primary defences**

1. Deny by default: every endpoint needs an explicit permission
2. Enforce permissions on the server, in one central place
3. Test every privileged endpoint with a low-privilege user

**Defence in depth**

- Global fallback policies
- Automated tests per role
- Log and alert on denied privileged actions

### How to verify the fix

A normal customer or teller account calling an admin or approval endpoint gets 403.

### Severity guide (Providus)

Critical if it reaches payments, approvals, limits or staff functions; high otherwise.

---

## Part 2: MITRE CWE entry (complete)

**Abstraction:** Class · **Structure:** Simple · **Status:** Incomplete  
**MITRE page:** https://cwe.mitre.org/data/definitions/862.html
  
**MITRE diagram:** https://cwe.mitre.org/data/images/CWE-862-Diagram.png

### Description

The product does not perform an authorization check when an actor attempts to access a resource or perform an action.

### Alternate terms

- **AuthZ**: "AuthZ" is typically used as an abbreviation of "authorization" within the web application security community. It is distinct from "AuthN" (or, sometimes, "AuthC") which is an abbreviation of "authentication." The use of "Auth" as an abbreviation is discouraged, since it could be used for either authentication or authorization.

### Background details

An access control list (ACL) represents who/what has permissions to a given object. Different operating systems implement (ACLs) in different ways. In UNIX, there are three types of permissions: read, write, and execute. Users are divided into three classes for file access: owner, group owner, and all other users where each class has a separate set of rights. In Windows NT, there are four basic types of permissions for files: "No access", "Read access", "Change access", and "Full control". Windows NT extends the concept of three types of users in UNIX to include a list of users and groups along with their associated permissions. A user can create an object (file) and assign specified permissions to that object.

### Common consequences

| Scope | Impact | Likelihood | Note |
|---|---|---|---|
| Confidentiality | Read Application Data, Read Files or Directories |  | An attacker could read sensitive data, either by reading the data directly from a data store that is not restricted, or by accessing insufficiently-protected, privileged functionality to read the data. |
| Integrity | Modify Application Data, Modify Files or Directories |  | An attacker could modify sensitive data, either by writing the data directly to a data store that is not restricted, or by accessing insufficiently-protected, privileged functionality to write the data. |
| Access Control | Gain Privileges or Assume Identity, Bypass Protection Mechanism |  | An attacker could gain privileges by modifying or reading critical data directly, or by accessing privileged functionality. |
| Availability | DoS: Crash, Exit, or Restart, DoS: Resource Consumption (CPU), DoS: Resource Consumption (Memory), DoS: Resource Consumption (Other) |  | An attacker could gain unauthorized access to resources on the system and excessively consume those resources, leading to a denial of service. |

### Likelihood of exploit

High

### Modes of introduction

- **Architecture and Design**: OMISSION: This weakness is caused by missing a security tactic during the architecture and design phase.

Authorization weaknesses may arise when a single-user application is ported to a multi-user environment.
- **Implementation**: A developer may introduce authorization weaknesses because of a lack of understanding about the underlying technologies. For example, a developer may assume that attackers cannot modify certain inputs such as headers or cookies.
- **Operation**

### Applicable platforms

- Language: Class: Not Language-Specific (Undetermined)
- Language: Go (Undetermined)
- Technology: AI/ML (Often)
- Technology: Web Server (Often)
- Technology: Database Server (Often)
- Technology: Class: Not Technology-Specific (Undetermined)

### Weakness ordinalities

- **Primary**

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

Generally, automated static analysis tools have difficulty detecting custom authorization schemes. In addition, the software's design may include some functionality that is accessible to any user and does not require an authorization check; an automated technique that detects the absence of authorization may report false positives.

**Automated Dynamic Analysis**

Automated dynamic analysis may find many or all possible interfaces that do not require authorization, but manual analysis is required to determine if the lack of authorization violates business logic.

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

**Manual Static Analysis - Source Code** (effectiveness: SOAR Partial)

According to SOAR [REF-1479], the following detection techniques may be useful:

Cost effective for partial coverage:
- Focused Manual Spotcheck - Focused manual analysis of source
- Manual Source Code Review (not inspections)

**Automated Static Analysis - Source Code** (effectiveness: SOAR Partial)

According to SOAR [REF-1479], the following detection techniques may be useful:

Cost effective for partial coverage:
- Source code Weakness Analyzer
- Context-configured Source Code Weakness Analyzer

**Architecture or Design Review** (effectiveness: High)

According to SOAR [REF-1479], the following detection techniques may be useful:

Highly cost effective:
- Inspection (IEEE 1028 standard) (can apply to requirements, design, source code, etc.)
- Formal Methods / Correct-By-Construction

### Demonstrative examples

**Example 1**

This function runs an arbitrary SQL query on a given database, returning the result of the query.

*Bad code (PHP):*

```php
function runEmployeeQuery($dbName, $name){
    mysql_select_db($dbName,$globalDbHandle) or die("Could not open Database".$dbName);
    //Use a prepared statement to avoid CWE-89
    $preparedStatement = $globalDbHandle->prepare('SELECT * FROM employees WHERE name = :name');
    $preparedStatement->execute(array(':name' => $name));
    return $preparedStatement->fetchAll();
}
/.../
$employeeRecord = runEmployeeQuery('EmployeeDB',$_GET['EmployeeName']);
```

While this code is careful to avoid SQL Injection, the function does not confirm the user sending the query is authorized to do so. An attacker may be able to obtain sensitive employee information from the database.

**Example 2**

The following program could be part of a bulletin board system that allows users to send private messages to each other. This program intends to authenticate the user before deciding whether a private message should be displayed. Assume that LookupMessageObject() ensures that the $id argument is numeric, constructs a filename based on that id, and reads the message details from that file. Also assume that the program stores all private messages for all users in the same directory.

*Bad code (Perl):*

```perl
sub DisplayPrivateMessage {
    my($id) = @_;
    my $Message = LookupMessageObject($id);
    print "From: " . encodeHTML($Message->{from}) . "<br>\n";
    print "Subject: " . encodeHTML($Message->{subject}) . "\n";
    print "<hr>\n";
    print "Body: " . encodeHTML($Message->{body}) . "\n";
}
my $q = new CGI;
# For purposes of this example, assume that CWE-309 and
# CWE-523 do not apply.
if (! AuthenticateUser($q->param('username'), $q->param('password'))) {
    ExitError("invalid username or password");
}
my $id = $q->param('id');
DisplayPrivateMessage($id);
```

While the program properly exits if authentication fails, it does not ensure that the message is addressed to the user. As a result, an authenticated attacker could provide any arbitrary identifier and read private messages that were intended for other users.

One way to avoid this problem would be to ensure that the "to" field in the message object matches the username of the authenticated user.

### Observed examples (real vulnerabilities)

| Reference | Description |
|---|---|
| [CVE-2026-32228](https://www.cve.org/CVERecord?id=CVE-2026-32228) | workflow management product does not check authorization for running a workflow, allowing UI and API users to trigger workflow objects for which they have no access |
| [CVE-2024-6845](https://www.cve.org/CVERecord?id=CVE-2024-6845) | chatbot Wordpress plugin does not perform authorization on a REST endpoint, allowing retrieval of an API key |
| [CVE-2025-2224](https://www.cve.org/CVERecord?id=CVE-2025-2224) | AI-enabled WordPress plugin has a missing capability check for a particular function, allowing changing public status of posts |
| [CVE-2022-24730](https://www.cve.org/CVERecord?id=CVE-2022-24730) | Go-based continuous deployment product does not check that a user has certain privileges to update or create an app, allowing adversaries to read sensitive repository information |
| [CVE-2009-3168](https://www.cve.org/CVERecord?id=CVE-2009-3168) | Web application does not restrict access to admin scripts, allowing authenticated users to reset administrative passwords. |
| [CVE-2009-3597](https://www.cve.org/CVERecord?id=CVE-2009-3597) | Web application stores database file under the web root with insufficient access control (CWE-219), allowing direct request. |
| [CVE-2009-2282](https://www.cve.org/CVERecord?id=CVE-2009-2282) | Terminal server does not check authorization for guest access. |
| [CVE-2008-5027](https://www.cve.org/CVERecord?id=CVE-2008-5027) | System monitoring software allows users to bypass authorization by creating custom forms. |
| [CVE-2009-3781](https://www.cve.org/CVERecord?id=CVE-2009-3781) | Content management system does not check access permissions for private files, allowing others to view those files. |
| [CVE-2008-6548](https://www.cve.org/CVERecord?id=CVE-2008-6548) | Product does not check the ACL of a page accessed using an "include" directive, allowing attackers to read unauthorized files. |
| [CVE-2009-2960](https://www.cve.org/CVERecord?id=CVE-2009-2960) | Web application does not restrict access to admin scripts, allowing authenticated users to modify passwords of other users. |
| [CVE-2009-3230](https://www.cve.org/CVERecord?id=CVE-2009-3230) | Database server does not use appropriate privileges for certain sensitive operations. |
| [CVE-2009-2213](https://www.cve.org/CVERecord?id=CVE-2009-2213) | Gateway uses default "Allow" configuration for its authorization settings. |
| [CVE-2009-0034](https://www.cve.org/CVERecord?id=CVE-2009-0034) | Chain: product does not properly interpret a configuration option for a system group, allowing users to gain privileges. |
| [CVE-2008-6123](https://www.cve.org/CVERecord?id=CVE-2008-6123) | Chain: SNMP product does not properly parse a configuration option for which hosts are allowed to connect, allowing unauthorized IP addresses to connect. |
| [CVE-2008-7109](https://www.cve.org/CVERecord?id=CVE-2008-7109) | Chain: reliance on client-side security (CWE-602) allows attackers to bypass authorization using a custom client. |
| [CVE-2008-3424](https://www.cve.org/CVERecord?id=CVE-2008-3424) | Chain: product does not properly handle wildcards in an authorization policy list, allowing unintended access. |
| [CVE-2005-1036](https://www.cve.org/CVERecord?id=CVE-2005-1036) | Chain: Bypass of access restrictions due to improper authorization (CWE-862) of a user results from an improperly initialized (CWE-909) I/O permission bitmap |
| [CVE-2008-4577](https://www.cve.org/CVERecord?id=CVE-2008-4577) | ACL-based protection mechanism treats negative access rights as if they are positive, allowing bypass of intended restrictions. |
| [CVE-2007-2925](https://www.cve.org/CVERecord?id=CVE-2007-2925) | Default ACL list for a DNS server does not set certain ACLs, allowing unauthorized DNS queries. |
| [CVE-2006-6679](https://www.cve.org/CVERecord?id=CVE-2006-6679) | Product relies on the X-Forwarded-For HTTP header for authorization, allowing unintended access by spoofing the header. |
| [CVE-2005-3623](https://www.cve.org/CVERecord?id=CVE-2005-3623) | OS kernel does not check for a certain privilege before setting ACLs for files. |
| [CVE-2005-2801](https://www.cve.org/CVERecord?id=CVE-2005-2801) | Chain: file-system code performs an incorrect comparison (CWE-697), preventing default ACLs from being properly applied. |
| [CVE-2001-1155](https://www.cve.org/CVERecord?id=CVE-2001-1155) | Chain: product does not properly check the result of a reverse DNS lookup because of operator precedence (CWE-783), allowing bypass of DNS-based access restrictions. |
| [CVE-2020-17533](https://www.cve.org/CVERecord?id=CVE-2020-17533) | Chain: unchecked return value (CWE-252) of some functions for policy enforcement leads to authorization bypass (CWE-862) |

### Relationships

Includes relationships recorded on this entry and those recorded on other entries that point to it (as MITRE's page shows them).

| Nature | CWE | Name | View | Recorded on |
|---|---|---|---|---|
| ChildOf (primary) | CWE-285 | Improper Authorization | 1000 Complete Weakness Hierarchy | this entry |
| ChildOf (primary) | CWE-284 | Improper Access Control | 1340 CISQ Data Protection Measures | this entry |
| ParentOf | CWE-425 | Direct Request | 1000 Complete Weakness Hierarchy | CWE-425 |
| ParentOf | CWE-638 | Not Using Complete Mediation | 1000 Complete Weakness Hierarchy | CWE-638 |
| ParentOf | CWE-939 | Improper Authorization in Handler for Custom URL Scheme | 1000 Complete Weakness Hierarchy | CWE-939 |
| ParentOf | CWE-1314 | Missing Write Protection for Parametric Data Values | 1000 Complete Weakness Hierarchy | CWE-1314 |
| ParentOf | CWE-425 | Direct Request | 1003 Weaknesses for Simplified Mapping of Published Vulnerabilities | CWE-425 |

### Related attack patterns (CAPEC)

[CAPEC-665](https://capec.mitre.org/data/definitions/665.html)

### Taxonomy mappings

| Taxonomy | Entry ID | Entry name | Fit |
|---|---|---|---|
| ISA/IEC 62443 | Part 2-1 | Req 4.3.3.7 |  |
| ISA/IEC 62443 | Part 3-3 | Req SR 2.1 |  |
| ISA/IEC 62443 | Part 4-2 | Req CR 2.1 |  |
| OWASP Golang Secure Coding Practices Guide |  | Access Control |  |

### Vulnerability mapping notes

**Usage:** Allowed-with-Review

**Rationale:** This CWE entry is a Class and might have Base-level children that would be more appropriate

**Comments:** Examine children of this entry to see if there is a better fit

**Reasons:** Abstraction

### Notes

**Terminology:** Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-control specifications that apply to the resource.

### Dimensions

Behavior-Property: Missing; Behavior-Type: Authorization

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
| View | 1337 | Weaknesses in the 2021 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1345 | OWASP Top Ten 2021 Category A01:2021 - Broken Access Control |
| View | 1350 | Weaknesses in the 2020 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1387 | Weaknesses in the 2022 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1396 | Comprehensive Categorization: Access Control |
| View | 1425 | Weaknesses in the 2023 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1430 | Weaknesses in the 2024 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1435 | Weaknesses in the 2025 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1436 | OWASP Top Ten 2025 Category A01:2025 - Broken Access Control |
| Category | 1447 | General Software Weaknesses that Appear in Products that Use or Support AI/ML Technology |
| View | 1468 | Weaknesses Addressed by the OWASP Golang Secure Coding Practices Guide |

### References

- [REF-229] NIST. "Role Based Access Control and Role Based Security". https://csrc.nist.gov/projects/role-based-access-control
- [REF-7] Michael Howard, David LeBlanc. "Writing Secure Code", 2002, Chapter 4, "Authorization" Page 114; Chapter 6, "Determining
                  Appropriate Access Control" Page 171. https://www.microsoftpressstore.com/store/writing-secure-code-9780735617223
- [REF-231] Frank Kim. "Top 25 Series - Rank 5 - Improper Access Control (Authorization)", 2010. https://www.sans.org/blog/top-25-series-rank-5-improper-access-control-authorization
- [REF-45] OWASP. "OWASP Enterprise Security API (ESAPI) Project". https://owasp.org/www-project-enterprise-security-api/
- [REF-233] Rahul Bhattacharjee. "Authentication using JAAS". https://javaranch.com/journal/2008/04/authentication-using-JAAS.html
- [REF-62] Mark Dowd, John McDonald, Justin Schuh. "The Art of Software Security Assessment", 2006, Chapter 2, "Common Vulnerabilities of Authorization", Page 39
- [REF-1479] Gregory Larsen, E. Kenneth Hong Fong, David A. Wheeler, Rama S. Moorthy. "State-of-the-Art Resources (SOAR) for Software Vulnerability Detection, Test, and Evaluation", 2014. https://www.ida.org/-/media/feature/publications/s/st/stateoftheart-resources-soar-for-software-vulnerability-detection-test-and-evaluation/p-5061.ashx
- [REF-1566] OWASP. "Golang Secure Coding Practices guide", 2024, Access Control, page 31. https://github.com/OWASP/Go-SCP

### Content history (summary)

- Submitted: 2011-05-24 by MITRE
- Modified 26 times; latest: 2026-10-28
- Full history: https://cwe.mitre.org/data/definitions/862.html#Content_History

---

*Part 2 is taken from the MITRE CWE List, version 5.0 (2026-10-28), https://cwe.mitre.org. Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation. Used under the CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html). Part 1 was written for the Providus Bank Secure Coding programme by Training Heights.*
