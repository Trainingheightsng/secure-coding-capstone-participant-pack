# CWE-284: Improper Access Control

> **2025 CWE Top 25:** rank 19 · score 4.07 · CVEs in CISA KEV: 1 · change since 2024: new

## Part 1: Review guide

### What it is, in plain words

Access to a resource isn't properly restricted at all: default credentials, public buckets, open admin consoles, or permissive configuration.

### How to spot it

**Java**
- `permitAll()` on management or admin paths; Actuator exposed
- Default or hard-coded admin accounts
- Storage clients creating public containers

**C#**
- `[AllowAnonymous]` on admin areas; Swagger exposed in production
- Blob containers with public access
- Default seeded admin users

**React / Node.js**
- Admin panels reachable without server-side checks
- Firebase/S3 rules allowing public read/write
- Open CORS with credentials

### Not this weakness (safe look-alikes)

- Health and info endpoints deliberately public with no sensitive data.

### How to tell it apart from related weaknesses

CWE-284 is the broad class for access control left open by design or configuration. Use 862 (no check), 863 (wrong check), 639 (user-controlled key) or 306 (no login) when one fits more precisely.

### Vulnerable and secure examples

#### Java

Vulnerable:

```java
s3.putBucketAcl(b -> b.bucket("providus-kyc")
  .acl(BucketCannedACL.PUBLIC_READ));
// or in application.properties:
// spring.security.user.password=admin
```

Why: A public bucket, and a default password left in config.

Secure:

```java
s3.putPublicAccessBlock(b -> b
  .bucket("providus-kyc")
  .publicAccessBlockConfiguration(c -> c
    .blockPublicAcls(true).ignorePublicAcls(true)
    .blockPublicPolicy(true)
    .restrictPublicBuckets(true)));
```

Why it works: Block public access, then hand out presigned URLs after an ownership check.

#### C#

Vulnerable:

```csharp
await container.CreateIfNotExistsAsync(
  PublicAccessType.Blob);
// anyone with a file's URL can read it
```

Why: The container is created public.

Secure:

```csharp
await container.CreateIfNotExistsAsync(
  PublicAccessType.None);
// after checking the customer owns the file:
Uri link = blob.GenerateSasUri(
  BlobSasPermissions.Read,
  DateTimeOffset.UtcNow.AddMinutes(5));
```

Why it works: Private by default, with a five-minute read-only link.

#### React / Node.js

Vulnerable:

```jsx
// KYC images loaded from public storage
<img src={`${KYC_BUCKET}/${customer.id}
  /passport.jpg`} />
// change the ID, see another passport
```

Why: The storage is public, so access control is only “knowing the URL”.

Secure:

```jsx
const { data } = useQuery(["doc", docId], () =>
  api.get(`/documents/${docId}/link`));
// the API checks ownership, returns a
// signed URL that expires in 5 minutes
<img src={data?.url} />
```

Why it works: Private storage, and short-lived links issued after an ownership check.

### Fix guidance

**Primary defences**

1. **Private by default.** Block public access at account level.
2. **Access through the API.** Ownership check, then a short-lived link.
3. **No default credentials.** Change every default password before go-live.

**Defence in depth**

- Least-privilege cloud roles
- Scan infrastructure code (Checkov, tfsec)
- Regular access reviews
- Alert on policy changes

**In each stack**

- Java: S3 Block Public Access
- C#: PublicAccessType.None + SAS
- React / Node.js: Signed links from the API

**Don't rely on**

- Unguessable URLs
- Hiding links in the UI
- “Temporary” public access

### How to verify the fix

Anonymous requests for any KYC file return 403 or 404.

### Severity guide (Providus)

Critical if it exposes data stores, admin functions or credentials.

---

## Part 2: MITRE CWE entry (complete)

**Abstraction:** Pillar · **Structure:** Simple · **Status:** Incomplete  
**MITRE page:** https://cwe.mitre.org/data/definitions/284.html

### Description

The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

### Technical nuance

Access control involves the use of several protection mechanisms such as:

- Authentication (proving the identity of an actor)
- Authorization (ensuring that a given actor can access a resource), and
- Accountability (tracking of activities that were performed)

There are two distinct behaviors that can introduce access control weaknesses:

- Specification: incorrect privileges, permissions, ownership, etc. are explicitly specified for either the user or the resource (for example, setting a password file to be world-writable, or giving administrator capabilities to a guest user). This action could be performed by the program or the administrator.
- Enforcement: the mechanism contains errors that prevent it from properly enforcing the specified access control requirements (e.g., allowing the user to specify their own privileges, or allowing a syntactically-incorrect ACL to produce insecure settings). This problem occurs within the program itself, in that it does not actually enforce the intended security policy that the administrator specifies.

### Alternate terms

- **Authorization**: The terms "access control" and "authorization" are often used interchangeably, although many people have distinct definitions. The CWE usage of "access control" is intended as a general term for the various mechanisms that restrict which users can access which resources, and "authorization" is more narrowly defined. It is unlikely that there will be community consensus on the use of these terms.

### Common consequences

| Scope | Impact | Likelihood | Note |
|---|---|---|---|
| Other | Varies by Context, Gain Privileges or Assume Identity |  | When any mechanism is not applied or otherwise fails, attackers can compromise the security of the product by gaining privileges, reading sensitive information, executing commands, evading detection, etc. |

### Modes of introduction

- **Architecture and Design**
- **Implementation**: REALIZATION: This weakness is caused during implementation of an architectural security tactic.
- **Operation**

### Applicable platforms

- Language: Class: Not Language-Specific (Often)
- Technology: Class: Not Technology-Specific (Often)
- Technology: Class: ICS/OT (Often)
- Technology: Class: Web Based (Often)

### Weakness ordinalities

- **Primary**

### Affected resources

- File or Directory

### Potential mitigations

**1. Phase: Architecture and Design, Operation** · ID: MIT-1

Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software.

**2. Phase: Architecture and Design** · Strategy: Separation of Privilege · ID: MIT-46

Compartmentalize the system to have "safe" areas where trust boundaries can be unambiguously drawn. Do not allow sensitive data to go outside of the trust boundary and always be careful when interfacing with a compartment outside of the safe area.

Ensure that appropriate compartmentalization is built into the system design, and the compartmentalization allows for and reinforces privilege separation functionality. Architects and designers should rely on the principle of least privilege to decide the appropriate time to use privileges and the time to drop privileges.

### Demonstrative examples

**Example 1**

This code temporarily raises the program's privileges to allow creation of a new user folder.

*Bad code (Python):*

```python
def makeNewUserDir(username):
    if invalidUsername(username):
        #avoid CWE-22 and CWE-78
        print('Usernames cannot contain invalid characters')
        return False
    try:
        raisePrivileges()
        os.mkdir('/home/' + username)
        lowerPrivileges()
    except OSError:
        print('Unable to create new user directory for user:' + username)
        return False
    return True
```

While the program only raises its privilege level to create the folder and immediately lowers it again, if the call to os.mkdir() throws an exception, the call to lowerPrivileges() will not occur. As a result, the program is indefinitely operating in a raised privilege state, possibly allowing further exploitation to occur.

**Example 2**

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

**Example 3**

In 2022, the OT:ICEFALL study examined products by 10 different Operational Technology (OT) vendors. The researchers reported 56 vulnerabilities and said that the products were "insecure by design" [REF-1283]. If exploited, these vulnerabilities often allowed adversaries to change how the products operated, ranging from denial of service to changing the code that the products executed. Since these products were often used in industries such as power, electrical, water, and others, there could even be safety implications.

Multiple vendors did not use any authentication or used client-side authentication for critical functionality in their OT products.

### Observed examples (real vulnerabilities)

| Reference | Description |
|---|---|
| [CVE-2023-26463](https://www.cve.org/CVERecord?id=CVE-2023-26463) | Chain: IPSec VPN product uses the same variable for multiple purposes in the same function (CWE-1109), leading to incorrect access control (CWE-284) and expired pointer dereference (CWE-825) |
| [CVE-2022-24985](https://www.cve.org/CVERecord?id=CVE-2022-24985) | A form hosting website only checks the session authentication status for a single form, making it possible to bypass authentication when there are multiple forms |
| [CVE-2022-29238](https://www.cve.org/CVERecord?id=CVE-2022-29238) | Access-control setting in web-based document collaboration tool is not properly implemented by the code, which prevents listing hidden directories but does not prevent direct requests to files in those directories. |
| [CVE-2022-23607](https://www.cve.org/CVERecord?id=CVE-2022-23607) | Python-based HTTP library did not scope cookies to a particular domain such that "supercookies" could be sent to any domain on redirect |
| [CVE-2021-21972](https://www.cve.org/CVERecord?id=CVE-2021-21972) | Chain: Cloud computing virtualization platform does not require authentication for upload of a tar format file (CWE-306), then uses .. path traversal sequences (CWE-23) in the file to access unexpected files, as exploited in the wild per CISA KEV. |
| [CVE-2021-37415](https://www.cve.org/CVERecord?id=CVE-2021-37415) | IT management product does not perform authentication for some REST API requests, as exploited in the wild per CISA KEV. |
| [CVE-2021-35033](https://www.cve.org/CVERecord?id=CVE-2021-35033) | Firmware for a WiFi router uses a hard-coded password for a BusyBox shell, allowing bypass of authentication through the UART port |
| [CVE-2020-10263](https://www.cve.org/CVERecord?id=CVE-2020-10263) | Bluetooth speaker does not require authentication for the debug functionality on the UART port, allowing root shell access |
| [CVE-2020-13927](https://www.cve.org/CVERecord?id=CVE-2020-13927) | Default setting in workflow management product allows all API requests without authentication, as exploited in the wild per CISA KEV. |
| [CVE-2010-4624](https://www.cve.org/CVERecord?id=CVE-2010-4624) | Bulletin board applies restrictions on number of images during post creation, but does not enforce this on editing. |

### Relationships

Includes relationships recorded on this entry and those recorded on other entries that point to it (as MITRE's page shows them).

| Nature | CWE | Name | View | Recorded on |
|---|---|---|---|---|
| ParentOf | CWE-269 | Improper Privilege Management | 1000 Complete Weakness Hierarchy | CWE-269 |
| ParentOf | CWE-282 | Improper Ownership Management | 1000 Complete Weakness Hierarchy | CWE-282 |
| ParentOf | CWE-285 | Improper Authorization | 1000 Complete Weakness Hierarchy | CWE-285 |
| ParentOf | CWE-286 | Incorrect User Management | 1000 Complete Weakness Hierarchy | CWE-286 |
| ParentOf | CWE-287 | Improper Authentication | 1000 Complete Weakness Hierarchy | CWE-287 |
| ParentOf | CWE-346 | Origin Validation Error | 1000 Complete Weakness Hierarchy | CWE-346 |
| ParentOf | CWE-749 | Exposed Dangerous Method or Function | 1000 Complete Weakness Hierarchy | CWE-749 |
| ParentOf | CWE-923 | Improper Restriction of Communication Channel to Intended Endpoints | 1000 Complete Weakness Hierarchy | CWE-923 |
| ParentOf | CWE-1191 | On-Chip Debug and Test Interface With Improper Access Control | 1000 Complete Weakness Hierarchy | CWE-1191 |
| ParentOf | CWE-1220 | Insufficient Granularity of Access Control | 1000 Complete Weakness Hierarchy | CWE-1220 |
| ParentOf | CWE-1224 | Improper Restriction of Write-Once Bit Fields | 1000 Complete Weakness Hierarchy | CWE-1224 |
| ParentOf | CWE-1231 | Improper Prevention of Lock Bit Modification | 1000 Complete Weakness Hierarchy | CWE-1231 |
| ParentOf | CWE-1233 | Security-Sensitive Hardware Controls with Missing Lock Bit Protection | 1000 Complete Weakness Hierarchy | CWE-1233 |
| ParentOf | CWE-1252 | CPU Hardware Not Configured to Support Exclusivity of Write and Execute Operations | 1000 Complete Weakness Hierarchy | CWE-1252 |
| ParentOf | CWE-1257 | Improper Access Control Applied to Mirrored or Aliased Memory Regions | 1000 Complete Weakness Hierarchy | CWE-1257 |
| ParentOf | CWE-1260 | Improper Handling of Overlap Between Protected Memory Ranges | 1000 Complete Weakness Hierarchy | CWE-1260 |
| ParentOf | CWE-1262 | Improper Access Control for Register Interface | 1000 Complete Weakness Hierarchy | CWE-1262 |
| ParentOf | CWE-1263 | Improper Physical Access Control | 1000 Complete Weakness Hierarchy | CWE-1263 |
| ParentOf | CWE-1267 | Policy Uses Obsolete Encoding | 1000 Complete Weakness Hierarchy | CWE-1267 |
| ParentOf | CWE-1274 | Improper Access Control for Volatile Memory Containing Boot Code | 1000 Complete Weakness Hierarchy | CWE-1274 |
| ParentOf | CWE-1276 | Hardware Child Block Incorrectly Connected to Parent System | 1000 Complete Weakness Hierarchy | CWE-1276 |
| ParentOf | CWE-1280 | Access Control Check Implemented After Asset is Accessed | 1000 Complete Weakness Hierarchy | CWE-1280 |
| ParentOf | CWE-1283 | Mutable Attestation or Measurement Reporting Data | 1000 Complete Weakness Hierarchy | CWE-1283 |
| ParentOf | CWE-1294 | Insecure Security Identifier Mechanism | 1000 Complete Weakness Hierarchy | CWE-1294 |
| ParentOf | CWE-1296 | Incorrect Chaining or Granularity of Debug Components | 1000 Complete Weakness Hierarchy | CWE-1296 |
| ParentOf | CWE-1304 | Improperly Preserved Integrity of Hardware Configuration State During a Power Save/Restore Operation | 1000 Complete Weakness Hierarchy | CWE-1304 |
| ParentOf | CWE-1311 | Improper Translation of Security Attributes by Fabric Bridge | 1000 Complete Weakness Hierarchy | CWE-1311 |
| ParentOf | CWE-1312 | Missing Protection for Mirrored Regions in On-Chip Fabric Firewall | 1000 Complete Weakness Hierarchy | CWE-1312 |
| ParentOf | CWE-1313 | Hardware Allows Activation of Test or Debug Logic at Runtime | 1000 Complete Weakness Hierarchy | CWE-1313 |
| ParentOf | CWE-1315 | Improper Setting of Bus Controlling Capability in Fabric End-point | 1000 Complete Weakness Hierarchy | CWE-1315 |
| ParentOf | CWE-1316 | Fabric-Address Map Allows Programming of Unwarranted Overlaps of Protected and Unprotected Ranges | 1000 Complete Weakness Hierarchy | CWE-1316 |
| ParentOf | CWE-1317 | Improper Access Control in Fabric Bridge | 1000 Complete Weakness Hierarchy | CWE-1317 |
| ParentOf | CWE-1320 | Improper Protection for Outbound Error Messages and Alert Signals | 1000 Complete Weakness Hierarchy | CWE-1320 |
| ParentOf | CWE-1323 | Improper Management of Sensitive Trace Data | 1000 Complete Weakness Hierarchy | CWE-1323 |
| ParentOf | CWE-1334 | Unauthorized Error Injection Can Degrade Hardware Redundancy | 1000 Complete Weakness Hierarchy | CWE-1334 |
| ParentOf | CWE-1462 | Improper Session Management | 1000 Complete Weakness Hierarchy | CWE-1462 |
| ParentOf | CWE-1469 | Improper Check for Credential Expiration | 1000 Complete Weakness Hierarchy | CWE-1469 |
| ParentOf | CWE-1472 | Generation of Credential with Long Expiration | 1000 Complete Weakness Hierarchy | CWE-1472 |
| ParentOf | CWE-285 | Improper Authorization | 1340 CISQ Data Protection Measures | CWE-285 |
| ParentOf | CWE-287 | Improper Authentication | 1340 CISQ Data Protection Measures | CWE-287 |
| ParentOf | CWE-288 | Authentication Bypass Using an Alternate Path or Channel | 1340 CISQ Data Protection Measures | CWE-288 |
| ParentOf | CWE-639 | Authorization Bypass Through User-Controlled Key | 1340 CISQ Data Protection Measures | CWE-639 |
| ParentOf | CWE-862 | Missing Authorization | 1340 CISQ Data Protection Measures | CWE-862 |
| ParentOf | CWE-863 | Incorrect Authorization | 1340 CISQ Data Protection Measures | CWE-863 |

### Related attack patterns (CAPEC)

[CAPEC-19](https://capec.mitre.org/data/definitions/19.html), [CAPEC-441](https://capec.mitre.org/data/definitions/441.html), [CAPEC-478](https://capec.mitre.org/data/definitions/478.html), [CAPEC-479](https://capec.mitre.org/data/definitions/479.html), [CAPEC-502](https://capec.mitre.org/data/definitions/502.html), [CAPEC-503](https://capec.mitre.org/data/definitions/503.html), [CAPEC-536](https://capec.mitre.org/data/definitions/536.html), [CAPEC-546](https://capec.mitre.org/data/definitions/546.html), [CAPEC-550](https://capec.mitre.org/data/definitions/550.html), [CAPEC-551](https://capec.mitre.org/data/definitions/551.html), [CAPEC-552](https://capec.mitre.org/data/definitions/552.html), [CAPEC-556](https://capec.mitre.org/data/definitions/556.html), [CAPEC-558](https://capec.mitre.org/data/definitions/558.html), [CAPEC-562](https://capec.mitre.org/data/definitions/562.html), [CAPEC-563](https://capec.mitre.org/data/definitions/563.html), [CAPEC-564](https://capec.mitre.org/data/definitions/564.html), [CAPEC-578](https://capec.mitre.org/data/definitions/578.html)

### Taxonomy mappings

| Taxonomy | Entry ID | Entry name | Fit |
|---|---|---|---|
| PLOVER |  | Access Control List (ACL) errors |  |
| WASC | 2 | Insufficient Authorization |  |
| 7 Pernicious Kingdoms |  | Missing Access Control |  |

### Vulnerability mapping notes

**Usage:** Discouraged

**Rationale:** CWE-284 is extremely high-level, a Pillar. Its name, "Improper Access Control," is often misused in low-information vulnerability reports [REF-1287] or by active use of the OWASP Top Ten, such as "A01:2021-Broken Access Control". It is not useful for trend analysis.

**Comments:** Consider using descendants-284 that are more specific to the kind of access control involved.

**Reasons:** Frequent Misuse, Frequent Misinterpretation, Abstraction

**Suggestions:**
- CWE-862 Missing Authorization: Missing Authorization
- CWE-863 Incorrect Authorization: Incorrect Authorization
- CWE-732 Incorrect Permission Assignment for Critical Resource: Incorrect Permission Assignment for Critical Resource
- CWE-306 Missing Authentication for Critical Functionality: Missing Authentication
- CWE-1390 Weak Authentication: Weak Authentication
- CWE-286 Incorrect User Management: Incorrect User Management
- CWE-923 Improper Restriction of Communication Channel to Intended Endpoints: Improper Restriction of Communication Channel to Intended Endpoints

### Notes

**Maintenance:** This entry needs more work. Possible sub-categories include:

- Trusted group includes undesired entities (partially covered by CWE-286)
- Group can perform undesired actions
- ACL parse error does not fail closed

### Dimensions

Behavior-Property: Improper; Behavior-Type: Access Control

### Memberships

Categories and views this entry belongs to (for example OWASP Top Ten and earlier CWE Top 25 lists).

| Type | ID | Name |
|---|---|---|
| Category | 254 | 7PK - Security Features |
| Category | 723 | OWASP Top Ten 2004 Category A2 - Broken Access Control |
| Category | 944 | SFP Secondary Cluster: Access Management |
| View | 1000 | Complete Weakness Hierarchy |
| Category | 1011 | Authorize Actors |
| Category | 1031 | OWASP Top Ten 2017 Category A5 - Broken Access Control |
| View | 1340 | CISQ Data Protection Measures |
| Category | 1345 | OWASP Top Ten 2021 Category A01:2021 - Broken Access Control |
| Category | 1369 | ICS Supply Chain: IT/OT Convergence/Expansion |
| Category | 1372 | ICS Supply Chain: OT Counterfeit and Malicious Corruption |
| Category | 1396 | Comprehensive Categorization: Access Control |
| View | 1435 | Weaknesses in the 2025 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1436 | OWASP Top Ten 2025 Category A01:2025 - Broken Access Control |

### References

- [REF-7] Michael Howard, David LeBlanc. "Writing Secure Code", 2002, Chapter 6, "Determining Appropriate Access Control" Page 171. https://www.microsoftpressstore.com/store/writing-secure-code-9780735617223
- [REF-44] Michael Howard, David LeBlanc, John Viega. "24 Deadly Sins of Software Security", 2010, "Sin 17: Failure to Protect Stored Data." Page 253
- [REF-1287] MITRE. "Supplemental Details - 2022 CWE Top 25", 2022, Details of Problematic Mappings. https://cwe.mitre.org/top25/archive/2022/2022_cwe_top25_supplemental.html#problematicMappingDetails
- [REF-1283] Forescout Vedere Labs. "OT:ICEFALL: The legacy of "insecure by design" and its implications for certifications and risk management", 2022. https://www.forescout.com/resources/ot-icefall-report/

### Content history (summary)

- Submitted: 2006-07-19 by PLOVER
- Modified 41 times; latest: 2026-10-28
- Previous names: "Access Control Issues" (until 2008-09-09); "Access Control (Authorization) Issues" (until 2011-03-29)
- Full history: https://cwe.mitre.org/data/definitions/284.html#Content_History

---

*Part 2 is taken from the MITRE CWE List, version 5.0 (2026-10-28), https://cwe.mitre.org. Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation. Used under the CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html). Part 1 was written for the Providus Bank Secure Coding programme by Training Heights.*
