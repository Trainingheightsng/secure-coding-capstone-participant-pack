# CWE-306: Missing Authentication for Critical Function

> **2025 CWE Top 25:** rank 21 · score 3.47 · CVEs in CISA KEV: 11 · change since 2024: +4
>  
> **Name in MITRE CWE v5.0:** Missing Authentication for Critical Functionality

## Part 1: Review guide

### What it is, in plain words

A function that needs authentication (transfers, admin actions, configuration, data export) can be called without logging in.

### How to spot it

**Java**
- `permitAll()` or missing matchers for sensitive paths
- Internal endpoints assumed safe because they are "only on the internal network"
- Actuator `/env`, `/shutdown` exposed

**C#**
- Missing `[Authorize]` on controllers with no global fallback policy
- `MapPost` endpoints without `.RequireAuthorization()`
- Hangfire/Swagger dashboards without auth

**React / Node.js**
- Next.js API routes that never check the session
- Webhook endpoints with no signature check

### Not this weakness (safe look-alikes)

- Intentionally public endpoints (login, public rates, health) that change nothing sensitive.
- A global "require authenticated user" fallback policy covering the endpoint.

### How to tell it apart from related weaknesses

No login required is CWE-306. Logged in but no permission check is CWE-862.

### Vulnerable and secure examples

#### Java

Vulnerable:

```java
# application.properties
management.endpoints.web.exposure.include=*
// SecurityConfig
.requestMatchers("/internal/**").permitAll()
```

Why: /actuator/heapdump and /internal are open to anyone who can reach them.

Secure:

```java
management.endpoints.web.exposure.include=
  health,info
// SecurityConfig
.requestMatchers("/actuator/health").permitAll()
.anyRequest().authenticated()
```

Why it works: Deny by default: only named endpoints are public.

#### C#

Vulnerable:

```csharp
app.MapPost("/internal/jobs/run-end-of-day",
  RunEndOfDay);
// no [Authorize], no RequireAuthorization()
```

Why: A critical job anyone can start.

Secure:

```csharp
builder.Services.AddAuthorization(o =>
  o.FallbackPolicy =
    new AuthorizationPolicyBuilder()
    .RequireAuthenticatedUser().Build());
app.MapPost("/internal/jobs/run-end-of-day",
  RunEndOfDay).RequireAuthorization("OpsAdmin");
```

Why it works: The fallback policy locks every endpoint unless marked otherwise.

#### React / Node.js

Vulnerable:

```jsx
// "internal" ops screen
fetch(`${OPS_API}/jobs/run-end-of-day`,
  { method: "POST" });
// works because the API asks for no login
```

Why: If the API answers this, it answers anyone on the network.

Secure:

```jsx
const token = await auth.getAccessToken();
fetch(`${OPS_API}/jobs/run-end-of-day`, {
  method: "POST",
  headers: { Authorization: `Bearer ${token}` } });
// the API rejects calls without a valid token
```

Why it works: Every call carries a token, and the API requires one.

### Fix guidance

**Primary defences**

1. **Deny by default.** Fallback policy, or anyRequest().authenticated().
2. **Expose only what’s needed.** Actuator: health and info only.
3. **Authenticate service calls.** mTLS or client credentials between services.

**Defence in depth**

- Keep an inventory of all endpoints
- Unauthenticated DAST scans
- Remove Swagger UI in production
- Alert on admin path access

**In each stack**

- Java: anyRequest().authenticated()
- C#: FallbackPolicy, RequireAuthorization
- React / Node.js: Attach tokens; handle 401

**Don't rely on**

- “It’s internal”
- Hidden or unlisted URLs
- IP allow-lists alone

### How to verify the fix

Every non-public endpoint returns 401 without a token.

### Severity guide (Providus)

Critical for any money movement, admin or data export; high otherwise.

---

## Part 2: MITRE CWE entry (complete)

**Abstraction:** Base · **Structure:** Simple · **Status:** Draft  
**MITRE page:** https://cwe.mitre.org/data/definitions/306.html
  
**MITRE diagram:** https://cwe.mitre.org/data/images/CWE-306-Diagram.png

### Description

The product does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources.

### Common consequences

| Scope | Impact | Likelihood | Note |
|---|---|---|---|
| Access Control, Other | Gain Privileges or Assume Identity, Varies by Context |  | Exposing critical functionality essentially provides an attacker with the privilege level of that functionality. The consequences will depend on the associated functionality, but they can range from reading or modifying sensitive data, accessing administrative or other privileged functionality, or possibly even executing arbitrary code. |

### Likelihood of exploit

High

### Modes of introduction

- **Architecture and Design**: OMISSION: This weakness is caused by missing a security tactic during the architecture and design phase.
- **Architecture and Design**: Developers sometimes perform authentication at the primary channel, but open up a secondary channel that is assumed to be private. For example, a login mechanism may be listening on one network port, but after successful authentication, it may open up a second port where it waits for the connection, but avoids authentication because it assumes that only the authenticated party will connect to the port.
- **Operation**: When migrating data to the cloud (e.g., S3 buckets, Azure blobs, Google Cloud Storage, etc.), there is a risk of losing the protections that were originally provided by hosting on internal networks. If access does not require authentication, it can be easier for attackers to access the data from anywhere on the Internet.

### Applicable platforms

- Language: Class: Not Language-Specific (Undetermined)
- Language: Go (Undetermined)
- Technology: Class: Cloud Computing (Undetermined)
- Technology: Class: ICS/OT (Often)
- Technology: AI/ML (Often)

### Weakness ordinalities

- **Primary**

### Potential mitigations

**1. Phase: Architecture and Design**

Divide the software into anonymous, normal, privileged, and administrative areas. Identify which of these areas require a proven user identity, and use a centralized authentication capability.

Identify all potential communication channels, or other means of interaction with the software, to ensure that all channels are appropriately protected, including those channels that are assumed to be accessible only by authorized parties. Developers sometimes perform authentication at the primary channel, but open up a secondary channel that is assumed to be private. For example, a login mechanism may be listening on one network port, but after successful authentication, it may open up a second port where it waits for the connection, but avoids authentication because it assumes that only the authenticated party will connect to the port.

In general, if the software or protocol allows a single session or user state to persist across multiple connections or channels, authentication and appropriate credential management need to be used throughout.

**2. Phase: Architecture and Design** · ID: MIT-15

For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side, in order to avoid CWE-602. Attackers can bypass the client-side checks by modifying values after the checks have been performed, or by changing the client to remove the client-side checks entirely. Then, these modified values would be submitted to the server.

**3. Phase: Architecture and Design**

Where possible, avoid implementing custom, "grow-your-own" authentication routines and consider using authentication capabilities as provided by the surrounding framework, operating system, or environment. These capabilities may avoid common weaknesses that are unique to authentication; support automatic auditing and tracking; and make it easier to provide a clear separation between authentication tasks and authorization tasks.

In environments such as the World Wide Web, the line between authentication and authorization is sometimes blurred. If custom authentication routines are required instead of those provided by the server, then these routines must be applied to every single page, since these pages could be requested directly.

**4. Phase: Architecture and Design** · Strategy: Libraries or Frameworks · ID: MIT-4.5

Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.

For example, consider using libraries with authentication capabilities such as OpenSSL or the ESAPI Authenticator [REF-45].

**5. Phase: Implementation, System Configuration, Operation**

When storing data in the cloud (e.g., S3 buckets, Azure blobs, Google Cloud Storage, etc.), use the provider's controls to require strong authentication for users who should be allowed to access the data [REF-1297] [REF-1298] [REF-1302].

### Detection methods

**Manual Analysis**

This weakness can be detected using tools and techniques that require manual (human) analysis, such as penetration testing, threat modeling, and interactive tools that allow the tester to record and modify an active session.

Specifically, manual static analysis is useful for evaluating the correctness of custom authentication mechanisms.

*These may be more effective than strictly automated techniques. This is especially the case with weaknesses that are related to design and business rules.*

**Automated Static Analysis** (effectiveness: Limited)

Automated static analysis is useful for detecting commonly-used idioms for authentication. A tool may be able to analyze related configuration files, such as .htaccess in Apache web servers, or detect the usage of commonly-used authentication libraries.

Generally, automated static analysis tools have difficulty detecting custom authentication schemes. In addition, the software's design may include some functionality that is accessible to any user and does not require an established identity; an automated technique that detects the absence of authentication may report false positives.

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

Cost effective for partial coverage:
- Attack Modeling

### Demonstrative examples

**Example 1**

In the following Java example the method createBankAccount is used to create a BankAccount object for a bank management application.

*Bad code (Java):*

```java
public BankAccount createBankAccount(String accountNumber, String accountType,
String accountName, String accountSSN, double balance) {
    BankAccount account = new BankAccount();
    account.setAccountNumber(accountNumber);
    account.setAccountType(accountType);
    account.setAccountOwnerName(accountName);
    account.setAccountOwnerSSN(accountSSN);
    account.setBalance(balance);
    return account;
}
```

However, there is no authentication mechanism to ensure that the user creating this bank account object has the authority to create new bank accounts. Some authentication mechanisms should be used to verify that the user has the authority to create bank account objects.

The following Java code includes a boolean variable and method for authenticating a user. If the user has not been authenticated then the createBankAccount will not create the bank account object.

*Good code (Java):*

```java
private boolean isUserAuthentic = false;
// authenticate user,
// if user is authenticated then set variable to true
// otherwise set variable to false
public boolean authenticateUser(String username, String password) {
    ...
}
public BankAccount createNewBankAccount(String accountNumber, String accountType,
String accountName, String accountSSN, double balance) {
    BankAccount account = null;
    if (isUserAuthentic) {
        account = new BankAccount();
        account.setAccountNumber(accountNumber);
        account.setAccountType(accountType);
        account.setAccountOwnerName(accountName);
        account.setAccountOwnerSSN(accountSSN);
        account.setBalance(balance);
    }
    return account;
}
```

**Example 2**

In 2022, the OT:ICEFALL study examined products by 10 different Operational Technology (OT) vendors. The researchers reported 56 vulnerabilities and said that the products were "insecure by design" [REF-1283]. If exploited, these vulnerabilities often allowed adversaries to change how the products operated, ranging from denial of service to changing the code that the products executed. Since these products were often used in industries such as power, electrical, water, and others, there could even be safety implications.

Multiple vendors did not use any authentication for critical functionality in their OT products.

**Example 3**

In 2021, a web site operated by PeopleGIS stored data of US municipalities in Amazon Web Service (AWS) Simple Storage Service (S3) buckets.

*Bad code (Other):*

```
A security researcher found 86 S3 buckets that could be accessed without authentication (CWE-306) and stored data unencrypted (CWE-312). These buckets exposed over 1000 GB of data and 1.6 million files including physical addresses, phone numbers, tax documents, pictures of driver's license IDs, etc. [REF-1296] [REF-1295]
```

While it was not publicly disclosed how the data was protected after discovery, multiple options could have been considered.

*Good code (Other):*

```
The sensitive information could have been protected by ensuring that the buckets did not have public read access, e.g., by enabling the s3-account-level-public-access-blocks-periodic rule to Block Public Access. In addition, the data could have been encrypted at rest using the appropriate S3 settings, e.g., by enabling server-side encryption using the s3-bucket-server-side-encryption-enabled setting. Other settings are available to further prevent bucket data from being leaked. [REF-1297]
```

### Observed examples (real vulnerabilities)

| Reference | Description |
|---|---|
| [CVE-2024-11680](https://www.cve.org/CVERecord?id=CVE-2024-11680) | File-sharing PHP product does not check if user is logged in during requests for PHP library files under an includes/ directory, allowing configuration changes, code execution, and other impacts. |
| [CVE-2022-31260](https://www.cve.org/CVERecord?id=CVE-2022-31260) | Chain: a digital asset management program has an undisclosed backdoor in the legacy version of a PHP script (CWE-912) that could allow an unauthenticated user to export metadata (CWE-306) |
| [CVE-2022-29951](https://www.cve.org/CVERecord?id=CVE-2022-29951) | TCP-based protocol in Programmable Logic Controller (PLC) has no authentication. |
| [CVE-2022-29952](https://www.cve.org/CVERecord?id=CVE-2022-29952) | Condition Monitor firmware uses a protocol that does not require authentication. |
| [CVE-2022-30276](https://www.cve.org/CVERecord?id=CVE-2022-30276) | SCADA-based protocol for bridging WAN and LAN traffic has no authentication. |
| [CVE-2022-30313](https://www.cve.org/CVERecord?id=CVE-2022-30313) | Safety Instrumented System uses proprietary TCP protocols with no authentication. |
| [CVE-2022-30317](https://www.cve.org/CVERecord?id=CVE-2022-30317) | Distributed Control System (DCS) uses a protocol that has no authentication. |
| [CVE-2021-21972](https://www.cve.org/CVERecord?id=CVE-2021-21972) | Chain: Cloud computing virtualization platform does not require authentication for upload of a tar format file (CWE-306), then uses .. path traversal sequences (CWE-23) in the file to access unexpected files, as exploited in the wild per CISA KEV. |
| [CVE-2020-10263](https://www.cve.org/CVERecord?id=CVE-2020-10263) | Bluetooth speaker does not require authentication for the debug functionality on the UART port, allowing root shell access |
| [CVE-2021-23147](https://www.cve.org/CVERecord?id=CVE-2021-23147) | WiFi router does not require authentication for its UART port, allowing adversaries with physical access to execute commands as root |
| [CVE-2021-37415](https://www.cve.org/CVERecord?id=CVE-2021-37415) | IT management product does not perform authentication for some REST API requests, as exploited in the wild per CISA KEV. |
| [CVE-2020-13927](https://www.cve.org/CVERecord?id=CVE-2020-13927) | Default setting in workflow management product allows all API requests without authentication, as exploited in the wild per CISA KEV. |
| [CVE-2002-1810](https://www.cve.org/CVERecord?id=CVE-2002-1810) | MFV. Access TFTP server without authentication and obtain configuration file with sensitive plaintext information. |
| [CVE-2008-6827](https://www.cve.org/CVERecord?id=CVE-2008-6827) | Agent software running at privileges does not authenticate incoming requests over an unprotected channel, allowing a Shatter" attack. |
| [CVE-2004-0213](https://www.cve.org/CVERecord?id=CVE-2004-0213) | Product enforces restrictions through a GUI but not through privileged APIs. |
| [CVE-2020-15483](https://www.cve.org/CVERecord?id=CVE-2020-15483) | monitor device allows access to physical UART debug port without authentication |
| [CVE-2019-9201](https://www.cve.org/CVERecord?id=CVE-2019-9201) | Programmable Logic Controller (PLC) does not have an authentication feature on its communication protocols. |

### Relationships

Includes relationships recorded on this entry and those recorded on other entries that point to it (as MITRE's page shows them).

| Nature | CWE | Name | View | Recorded on |
|---|---|---|---|---|
| ChildOf (primary) | CWE-287 | Improper Authentication | 1000 Complete Weakness Hierarchy | this entry |
| ChildOf (primary) | CWE-287 | Improper Authentication | 1003 Weaknesses for Simplified Mapping of Published Vulnerabilities | this entry |
| ParentOf | CWE-288 | Authentication Bypass Using an Alternate Path or Channel | 1000 Complete Weakness Hierarchy | CWE-288 |
| ParentOf | CWE-322 | Key Exchange without Entity Authentication | 1000 Complete Weakness Hierarchy | CWE-322 |

### Related attack patterns (CAPEC)

[CAPEC-12](https://capec.mitre.org/data/definitions/12.html), [CAPEC-166](https://capec.mitre.org/data/definitions/166.html), [CAPEC-216](https://capec.mitre.org/data/definitions/216.html), [CAPEC-36](https://capec.mitre.org/data/definitions/36.html), [CAPEC-62](https://capec.mitre.org/data/definitions/62.html)

### Taxonomy mappings

| Taxonomy | Entry ID | Entry name | Fit |
|---|---|---|---|
| PLOVER |  | No Authentication for Critical Function |  |
| Software Fault Patterns | SFP31 | Missing authentication |  |
| OWASP Golang Secure Coding Practices Guide |  | Authentication and Password Management |  |
| ISA/IEC 62443 | Part 4-2 | Req CR 1.1 |  |
| ISA/IEC 62443 | Part 4-2 | Req CR 1.2 |  |
| ISA/IEC 62443 | Part 4-2 | Req CR 2.1 |  |
| ISA/IEC 62443 | Part 4-1 | Req SR-2 |  |
| ISA/IEC 62443 | Part 4-1 | Req SVV-3 |  |

### Vulnerability mapping notes

**Usage:** Allowed

**Rationale:** This CWE entry is at the Base level of abstraction, which is a preferred level of abstraction for mapping to the root causes of vulnerabilities.

**Comments:** Carefully read both the name and description to ensure that this mapping is an appropriate fit. Do not try to 'force' a mapping to a lower-level Base/Variant simply to comply with this preferred level of abstraction.

**Reasons:** Acceptable-Use

### Memberships

Categories and views this entry belongs to (for example OWASP Top Ten and earlier CWE Top 25 lists).

| Type | ID | Name |
|---|---|---|
| Category | 803 | 2010 Top 25 - Porous Defenses |
| Category | 812 | OWASP Top Ten 2010 Category A3 - Broken Authentication and Session Management |
| Category | 866 | 2011 Top 25 - Porous Defenses |
| View | 884 | CWE Cross-section |
| Category | 952 | SFP Secondary Cluster: Missing Authentication |
| Category | 1010 | Authenticate Actors |
| Category | 1211 | Authentication Errors |
| View | 1337 | Weaknesses in the 2021 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1350 | Weaknesses in the 2020 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1353 | OWASP Top Ten 2021 Category A07:2021 - Identification and Authentication Failures |
| Category | 1364 | ICS Communications: Zone Boundary Failures |
| Category | 1365 | ICS Communications: Unreliability |
| Category | 1366 | ICS Communications: Frail Security in Protocols |
| Category | 1368 | ICS Dependencies (& Architecture): External Digital Systems |
| View | 1387 | Weaknesses in the 2022 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1396 | Comprehensive Categorization: Access Control |
| View | 1425 | Weaknesses in the 2023 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1430 | Weaknesses in the 2024 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1435 | Weaknesses in the 2025 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1442 | OWASP Top Ten 2025 Category A07:2025 - Authentication Failures |
| Category | 1447 | General Software Weaknesses that Appear in Products that Use or Support AI/ML Technology |
| View | 1468 | Weaknesses Addressed by the OWASP Golang Secure Coding Practices Guide |

### References

- [REF-62] Mark Dowd, John McDonald, Justin Schuh. "The Art of Software Security Assessment", 2006, Chapter 2, "Common Vulnerabilities of Authentication," Page 36
- [REF-257] Frank Kim. "Top 25 Series - Rank 19 - Missing Authentication for Critical Function", 2010. https://www.sans.org/blog/top-25-series-rank-19-missing-authentication-for-critical-function/
- [REF-45] OWASP. "OWASP Enterprise Security API (ESAPI) Project". https://owasp.org/www-project-enterprise-security-api/
- [REF-1283] Forescout Vedere Labs. "OT:ICEFALL: The legacy of "insecure by design" and its implications for certifications and risk management", 2022. https://www.forescout.com/resources/ot-icefall-report/
- [REF-1295] WizCase. "Over 80 US Municipalities' Sensitive Information, Including Resident's Personal Data, Left Vulnerable in Massive Data Breach", 2021. https://www.wizcase.com/blog/us-municipality-breach-report/
- [REF-1296] Jonathan Greig. "1,000 GB of local government data exposed by Massachusetts software company", 2021. https://www.zdnet.com/article/1000-gb-of-local-government-data-exposed-by-massachusetts-software-company/
- [REF-1297] Amazon. "AWS Foundational Security Best Practices controls", 2022. https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-controls-reference.html
- [REF-1298] Microsoft. "Authentication and authorization in Azure App Service and Azure Functions", 2021. https://learn.microsoft.com/en-us/azure/app-service/overview-authentication-authorization
- [REF-1302] Google Cloud. "Authentication and authorization use cases", 2022. https://cloud.google.com/docs/authentication/use-cases
- [REF-1479] Gregory Larsen, E. Kenneth Hong Fong, David A. Wheeler, Rama S. Moorthy. "State-of-the-Art Resources (SOAR) for Software Vulnerability Detection, Test, and Evaluation", 2014. https://www.ida.org/-/media/feature/publications/s/st/stateoftheart-resources-soar-for-software-vulnerability-detection-test-and-evaluation/p-5061.ashx
- [REF-1566] OWASP. "Golang Secure Coding Practices guide", 2024, Authentication and Password Management, page 20. https://github.com/OWASP/Go-SCP

### Content history (summary)

- Submitted: 2006-07-19 by PLOVER
- Modified 31 times; latest: 2026-10-28
- Previous names: "No Authentication for Critical Function" (until 2010-02-16); "Missing Authentication for Critical Function" (until 2026-10-28)
- Full history: https://cwe.mitre.org/data/definitions/306.html#Content_History

---

*Part 2 is taken from the MITRE CWE List, version 5.0 (2026-10-28), https://cwe.mitre.org. Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation. Used under the CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html). Part 1 was written for the Providus Bank Secure Coding programme by Training Heights.*
