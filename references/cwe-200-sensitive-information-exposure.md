# CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

> **2025 CWE Top 25:** rank 20 · score 4.01 · CVEs in CISA KEV: 1 · change since 2024: -3

## Part 1: Review guide

### What it is, in plain words

Information that should be private (customer data, secrets, internal details) is shown to someone not entitled to it: in responses, errors, logs or headers.

### How to spot it

**Java**
- Returning JPA entities directly from controllers (exposes `passwordHash`, BVN, internal flags)
- `server.error.include-stacktrace=always` or `include-message=always`; exception messages returned to clients
- Actuator endpoints (`/env`, `/heapdump`, `/configprops`) exposed
- Logging full PAN, BVN, tokens or passwords

**C#**
- `app.UseDeveloperExceptionPage()` outside Development; `ex.ToString()` in responses
- Returning EF entities instead of DTOs
- `Server`/`X-Powered-By` headers; detailed `ProblemDetails` in production

**React / Node.js**
- `res.json(user)` with the full database object
- Secrets in client bundles (`NEXT_PUBLIC_`/`VITE_` variables holding keys)
- Source maps published in production; verbose errors shown in the UI

### Not this weakness (safe look-alikes)

- DTOs or projections that return only the fields the caller needs.
- Generic error messages to clients with details kept in protected logs.
- Masked values (last four digits) in responses and logs.

### How to tell it apart from related weaknesses

Data shown to the wrong person because of a missing or wrong access check is reported as the access-control CWE (862, 863, 639) with 200 as the impact. CWE-200 on its own is for data that leaks through responses, errors, logs or metadata.

### Vulnerable and secure examples

#### Java

Vulnerable:

```java
@GetMapping("/customers/{id}")
public Customer get(@PathVariable long id) { return repo.findById(id).orElseThrow(); }
// returns passwordHash, bvn, internal risk flags
```

Why: The whole entity is serialised.

Secure:

```java
public record CustomerView(String name, String maskedPhone) {}
@GetMapping("/me")
public CustomerView me(Principal p) { return mapper.toView(repo.byLogin(p.getName())); }
```

Why it works: A DTO returns only what the screen needs.

#### C#

Vulnerable:

```csharp
if (true) app.UseDeveloperExceptionPage();   // also in production
catch (Exception ex) { return Problem(ex.ToString()); }
```

Why: Stack traces, SQL and paths go to the client.

Secure:

```csharp
if (app.Environment.IsDevelopment()) app.UseDeveloperExceptionPage();
else app.UseExceptionHandler("/error");   // generic ProblemDetails
catch (Exception ex) { _log.LogError(ex, "Transfer failed"); return Problem("Transfer failed"); }
```

Why it works: Details go to the log; the client gets a generic message.

#### React / Node.js

Vulnerable:

```jsx
res.json(await db.user.findUnique({ where: { id } }));
// NEXT_PUBLIC_PAYSTACK_SECRET=sk_live_... in .env
```

Why: Full record returned; a secret key exposed in the bundle.

Secure:

```jsx
const u = await db.user.findUnique({ where: { id },
  select: { name: true, email: true } });
res.json(u);   // secret keys only in server-side env vars
```

Why it works: Select only needed fields; keep secrets server-side.

### Fix guidance

**Primary defences**

1. Return DTOs with only the fields needed
2. Show generic errors to clients; keep details in protected logs
3. Mask sensitive values in responses and logs

**Defence in depth**

- Disable debug pages, stack traces and verbose headers in production
- Lock down Actuator/Swagger
- Secret scanning on bundles and repos

### How to verify the fix

Responses, error pages and logs contain no passwords, keys, full PAN/BVN or stack traces.

### Severity guide (Providus)

Critical for card data, BVN/NIN, credentials or keys; high for personal data; low for version banners.

---

## Part 2: MITRE CWE entry (complete)

**Abstraction:** Class · **Structure:** Simple · **Status:** Draft  
**MITRE page:** https://cwe.mitre.org/data/definitions/200.html

### Description

The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

### Technical nuance

There are many different kinds of mistakes that introduce information exposures. The severity of the error can range widely, depending on the context in which the product operates, the type of sensitive information that is revealed, and the benefits it may provide to an attacker. Some kinds of sensitive information include:

- private, personal information, such as personal messages, financial data, health records, geographic location, or contact details
- system status and environment, such as the operating system and installed packages
- business secrets and intellectual property
- network status and configuration
- the product's own code or internal state
- metadata, e.g. logging of connections or message headers
- indirect information, such as a discrepancy between two internal operations that can be observed by an outsider

Information might be sensitive to different parties, each of which may have their own expectations for whether the information should be protected. These parties include:

- the product's own users
- people or organizations whose information is created or used by the product, even if they are not direct product users
- the product's administrators, including the admins of the system(s) and/or networks on which the product operates
- the developer

Information exposures can occur in different ways:

- the code
   explicitly inserts
   sensitive information into resources or messages that are intentionally made accessible to unauthorized actors, but should not contain the information - i.e., the information should have been "scrubbed" or "sanitized"
- a different weakness or mistake
   indirectly inserts
   the sensitive information into resources, such as a web script error revealing the full system path of the program.
- the code manages resources that intentionally contain sensitive information, but the resources are
   unintentionally made accessible
   to unauthorized actors. In this case, the information exposure is resultant - i.e., a different weakness enabled the access to the information in the first place.

### Alternate terms

- **Information Disclosure**: This term is frequently used in vulnerability advisories to describe a consequence or technical impact, for any vulnerability that has a loss of confidentiality. Often, CWE-200 can be misused to represent the loss of confidentiality, even when the mistake - i.e., the weakness - is not directly related to the mishandling of the information itself, such as an out-of-bounds read that accesses sensitive memory contents; here, the out-of-bounds read is the primary weakness, not the disclosure of the memory. In addition, this phrase is also used frequently in policies and legal documents, but it does not refer to any disclosure of security-relevant information.
- **Information Leak**: This is a frequently used term, however the "leak" term has multiple uses within security. In some cases it deals with the accidental exposure of information from a different weakness, but in other cases (such as "memory leak"), this deals with improper control of resources (with a different root-cause weakness), which can lead to exhaustion. As a result, CWE is actively avoiding usage of the "leak" term.

### Common consequences

| Scope | Impact | Likelihood | Note |
|---|---|---|---|
| Confidentiality | Read Application Data |  |  |

### Likelihood of exploit

High

### Modes of introduction

- **Architecture and Design**
- **Implementation**

### Applicable platforms

- Language: Class: Not Language-Specific (Undetermined)
- Technology: Class: Not Technology-Specific (Undetermined)
- Technology: Class: Web Based (Undetermined)
- Technology: Class: Mobile (Undetermined)

### Weakness ordinalities

- **Primary**: Developers may insert sensitive information that they do not believe, or they might forget to remove the sensitive information after it has been processed
- **Resultant**: Separate mistakes or weaknesses could inadvertently make the sensitive information available to an attacker, such as in a detailed error message that can be read by an unauthorized party

### Potential mitigations

**1. Phase: Architecture and Design** · Strategy: Separation of Privilege · ID: MIT-46

Compartmentalize the system to have "safe" areas where trust boundaries can be unambiguously drawn. Do not allow sensitive data to go outside of the trust boundary and always be careful when interfacing with a compartment outside of the safe area.

Ensure that appropriate compartmentalization is built into the system design, and the compartmentalization allows for and reinforces privilege separation functionality. Architects and designers should rely on the principle of least privilege to decide the appropriate time to use privileges and the time to drop privileges.

### Detection methods

**Automated Static Analysis - Binary or Bytecode** (effectiveness: SOAR Partial)

According to SOAR [REF-1479], the following detection techniques may be useful:

Cost effective for partial coverage:
- Bytecode Weakness Analysis - including disassembler + source code weakness analysis
- Inter-application Flow Analysis

**Dynamic Analysis with Automated Results Interpretation** (effectiveness: High)

According to SOAR [REF-1479], the following detection techniques may be useful:

Highly cost effective:
- Web Application Scanner
- Web Services Scanner
- Database Scanners

**Dynamic Analysis with Manual Results Interpretation** (effectiveness: SOAR Partial)

According to SOAR [REF-1479], the following detection techniques may be useful:

Cost effective for partial coverage:
- Fuzz Tester
- Framework-based Fuzzer
- Automated Monitored Execution
- Monitored Virtual Environment - run potentially malicious code in sandbox / wrapper / virtual machine, see if it does anything suspicious

**Manual Static Analysis - Source Code** (effectiveness: High)

According to SOAR [REF-1479], the following detection techniques may be useful:

Highly cost effective:
- Manual Source Code Review (not inspections)

**Automated Static Analysis - Source Code** (effectiveness: High)

According to SOAR [REF-1479], the following detection techniques may be useful:

Highly cost effective:
- Context-configured Source Code Weakness Analyzer

Cost effective for partial coverage:
- Source code Weakness Analyzer

**Architecture or Design Review** (effectiveness: High)

According to SOAR [REF-1479], the following detection techniques may be useful:

Highly cost effective:
- Formal Methods / Correct-By-Construction

Cost effective for partial coverage:
- Attack Modeling
- Inspection (IEEE 1028 standard) (can apply to requirements, design, source code, etc.)

### Demonstrative examples

**Example 1**

The following code checks validity of the supplied username and password and notifies the user of a successful or failed login.

*Bad code (Perl):*

```perl
my $username=param('username');
my $password=param('password');
if (IsValidUsername($username) == 1)
{
    if (IsValidPassword($username, $password) == 1)
    {
        print "Login Successful";
    }
    else
    {
        print "Login Failed - incorrect password";
    }
}
else
{
    print "Login Failed - unknown username";
}
```

In the above code, there are different messages for when an incorrect username is supplied, versus when the username is correct but the password is wrong. This difference enables a potential attacker to understand the state of the login function, and could allow an attacker to discover a valid username by trying different values until the incorrect password message is returned. In essence, this makes it easier for an attacker to obtain half of the necessary authentication credentials.

While this type of information may be helpful to a user, it is also useful to a potential attacker. In the above example, the message for both failed cases should be the same, such as:

*Result code:*

```
"Login Failed - incorrect username or password"
```

**Example 2**

This code tries to open a database connection, and prints any exceptions that occur.

*Bad code (PHP):*

```php
try {
    openDbConnection();
}
//print exception message that includes exception message and configuration file location
catch (Exception $e) {
    echo 'Caught exception: ', $e->getMessage(), '\n';
    echo 'Check credentials in config file at: ', $Mysql_config_location, '\n';
}
```

If an exception occurs, the printed message exposes the location of the configuration file the script is using. An attacker can use this information to target the configuration file (perhaps exploiting a Path Traversal weakness). If the file can be read, the attacker could gain credentials for accessing the database. The attacker may also be able to replace the file with a malicious one, causing the application to use an arbitrary database.

**Example 3**

In the example below, the method getUserBankAccount retrieves a bank account object from a database using the supplied username and account number to query the database. If an SQLException is raised when querying the database, an error message is created and output to a log file.

*Bad code (Java):*

```java
public BankAccount getUserBankAccount(String username, String accountNumber) {
    BankAccount userAccount = null;
    String query = null;
    try {
        if (isAuthorizedUser(username)) {
            query = "SELECT * FROM accounts WHERE owner = "
            + username + " AND accountID = " + accountNumber;
            DatabaseManager dbManager = new DatabaseManager();
            Connection conn = dbManager.getConnection();
            Statement stmt = conn.createStatement();
            ResultSet queryResult = stmt.executeQuery(query);
            userAccount = (BankAccount)queryResult.getObject(accountNumber);
        }
    } catch (SQLException ex) {
        String logMessage = "Unable to retrieve account information from database,\nquery: " + query;
        Logger.getLogger(BankManager.class.getName()).log(Level.SEVERE, logMessage, ex);
    }
    return userAccount;
}
```

The error message that is created includes information about the database query that may contain sensitive information about the database or query logic. In this case, the error message will expose the table name and column names used in the database. This data could be used to simplify other attacks, such as SQL injection (CWE-89) to directly access the database.

**Example 4**

This code stores location information about the current user:

*Bad code (Java):*

```java
locationClient = new LocationClient(this, this, this);
locationClient.connect();
currentUser.setLocation(locationClient.getLastLocation());
...
catch (Exception e) {
    AlertDialog.Builder builder = new AlertDialog.Builder(this);
    builder.setMessage("Sorry, this application has experienced an error.");
    AlertDialog alert = builder.create();
    alert.show();
    Log.e("ExampleActivity", "Caught exception: " + e + " While on User:" + User.toString());
}
```

When the application encounters an exception it will write the user object to the log. Because the user object contains location information, the user's location is also written to the log.

**Example 5**

The following is an actual MySQL error statement:

*Result code (SQL):*

```sql
Warning: mysql_pconnect(): Access denied for user: 'root@localhost' (Using password: N1nj4) in /usr/local/www/wi-data/includes/database.inc on line 4
```

The error clearly exposes the database credentials.

**Example 6**

This code displays some information on a web page.

*Bad code (JSP):*

```jsp
Social Security Number: <%= ssn %></br>Credit Card Number: <%= ccn %>
```

The code displays a user's credit card and social security numbers, even though they aren't absolutely necessary.

**Example 7**

The following program changes its behavior based on a debug flag.

*Bad code (JSP):*

```jsp
<% if (Boolean.getBoolean("debugEnabled")) {
    %>
    User account number: <%= acctNo %>
    <%
    } %>
```

The code writes sensitive debug information to the client browser if the "debugEnabled" flag is set to true .

**Example 8**

This code uses location to determine the user's current US State location.

First the application must declare that it requires the ACCESS_FINE_LOCATION permission in the application's manifest.xml:

*Bad code (XML):*

```
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
```

During execution, a call to getLastLocation() will return a location based on the application's location permissions. In this case the application has permission for the most accurate location possible:

*Bad code (Java):*

```java
locationClient = new LocationClient(this, this, this);
locationClient.connect();
Location userCurrLocation;
userCurrLocation = locationClient.getLastLocation();
deriveStateFromCoords(userCurrLocation);
```

While the application needs this information, it does not need to use the ACCESS_FINE_LOCATION permission, as the ACCESS_COARSE_LOCATION permission will be sufficient to identify which US state the user is in.

### Observed examples (real vulnerabilities)

| Reference | Description |
|---|---|
| [CVE-2022-31162](https://www.cve.org/CVERecord?id=CVE-2022-31162) | Rust library leaks Oauth client details in application debug logs |
| [CVE-2021-25476](https://www.cve.org/CVERecord?id=CVE-2021-25476) | Digital Rights Management (DRM) capability for mobile platform leaks pointer information, simplifying ASLR bypass |
| [CVE-2001-1483](https://www.cve.org/CVERecord?id=CVE-2001-1483) | Enumeration of valid usernames based on inconsistent responses |
| [CVE-2001-1528](https://www.cve.org/CVERecord?id=CVE-2001-1528) | Account number enumeration via inconsistent responses. |
| [CVE-2004-2150](https://www.cve.org/CVERecord?id=CVE-2004-2150) | User enumeration via discrepancies in error messages. |
| [CVE-2005-1205](https://www.cve.org/CVERecord?id=CVE-2005-1205) | Telnet protocol allows servers to obtain sensitive environment information from clients. |
| [CVE-2002-1725](https://www.cve.org/CVERecord?id=CVE-2002-1725) | Script calls phpinfo(), revealing system configuration to web user |
| [CVE-2002-0515](https://www.cve.org/CVERecord?id=CVE-2002-0515) | Product sets a different TTL when a port is being filtered than when it is not being filtered, which allows remote attackers to identify filtered ports by comparing TTLs. |
| [CVE-2004-0778](https://www.cve.org/CVERecord?id=CVE-2004-0778) | Version control system allows remote attackers to determine the existence of arbitrary files and directories via the -X command for an alternate history file, which causes different error messages to be returned. |
| [CVE-2000-1117](https://www.cve.org/CVERecord?id=CVE-2000-1117) | Virtual machine allows malicious web site operators to determine the existence of files on the client by measuring delays in the execution of the getSystemResource method. |
| [CVE-2003-0190](https://www.cve.org/CVERecord?id=CVE-2003-0190) | Product immediately sends an error message when a user does not exist, which allows remote attackers to determine valid usernames via a timing attack. |
| [CVE-2008-2049](https://www.cve.org/CVERecord?id=CVE-2008-2049) | POP3 server reveals a password in an error message after multiple APOP commands are sent. Might be resultant from another weakness. |
| [CVE-2007-5172](https://www.cve.org/CVERecord?id=CVE-2007-5172) | Program reveals password in error message if attacker can trigger certain database errors. |
| [CVE-2008-4638](https://www.cve.org/CVERecord?id=CVE-2008-4638) | Composite: application running with high privileges (CWE-250) allows user to specify a restricted file to process, which generates a parsing error that leaks the contents of the file (CWE-209). |
| [CVE-2007-1409](https://www.cve.org/CVERecord?id=CVE-2007-1409) | Direct request to library file in web application triggers pathname leak in error message. |
| [CVE-2005-0603](https://www.cve.org/CVERecord?id=CVE-2005-0603) | Malformed regexp syntax leads to information exposure in error message. |
| [CVE-2004-2268](https://www.cve.org/CVERecord?id=CVE-2004-2268) | Password exposed in debug information. |
| [CVE-2003-1078](https://www.cve.org/CVERecord?id=CVE-2003-1078) | FTP client with debug option enabled shows password to the screen. |
| [CVE-2022-0708](https://www.cve.org/CVERecord?id=CVE-2022-0708) | Collaboration platform does not clear team emails in a response, allowing leak of email addresses |

### Relationships

Includes relationships recorded on this entry and those recorded on other entries that point to it (as MITRE's page shows them).

| Nature | CWE | Name | View | Recorded on |
|---|---|---|---|---|
| ChildOf (primary) | CWE-668 | Exposure of Resource to Wrong Sphere | 1000 Complete Weakness Hierarchy | this entry |
| ParentOf | CWE-201 | Insertion of Sensitive Information Into Sent Data | 1000 Complete Weakness Hierarchy | CWE-201 |
| ParentOf | CWE-203 | Observable Discrepancy | 1000 Complete Weakness Hierarchy | CWE-203 |
| ParentOf | CWE-209 | Generation of Error Message Containing Sensitive Information | 1000 Complete Weakness Hierarchy | CWE-209 |
| ParentOf | CWE-213 | Exposure of Sensitive Information Due to Incompatible Policies | 1000 Complete Weakness Hierarchy | CWE-213 |
| ParentOf | CWE-215 | Insertion of Sensitive Information Into Debugging Code | 1000 Complete Weakness Hierarchy | CWE-215 |
| ParentOf | CWE-359 | Exposure of Private Personal Information to an Unauthorized Actor | 1000 Complete Weakness Hierarchy | CWE-359 |
| ParentOf | CWE-497 | Exposure of Sensitive System Information to an Unauthorized Control Sphere | 1000 Complete Weakness Hierarchy | CWE-497 |
| ParentOf | CWE-538 | Insertion of Sensitive Information into Externally-Accessible File or Directory | 1000 Complete Weakness Hierarchy | CWE-538 |
| ParentOf | CWE-1273 | Device Unlock Credential Sharing | 1000 Complete Weakness Hierarchy | CWE-1273 |
| ParentOf | CWE-203 | Observable Discrepancy | 1003 Weaknesses for Simplified Mapping of Published Vulnerabilities | CWE-203 |
| ParentOf | CWE-209 | Generation of Error Message Containing Sensitive Information | 1003 Weaknesses for Simplified Mapping of Published Vulnerabilities | CWE-209 |
| ParentOf | CWE-532 | Insertion of Sensitive Information into Log File | 1003 Weaknesses for Simplified Mapping of Published Vulnerabilities | CWE-532 |
| CanFollow | CWE-498 | Cloneable Class Containing Sensitive Information | 1000 Complete Weakness Hierarchy | CWE-498 |
| CanFollow | CWE-499 | Serializable Class Containing Sensitive Data | 1000 Complete Weakness Hierarchy | CWE-499 |
| CanFollow | CWE-1272 | Sensitive Information Uncleared Before Debug/Power State Transition | 1000 Complete Weakness Hierarchy | CWE-1272 |

### Related attack patterns (CAPEC)

[CAPEC-116](https://capec.mitre.org/data/definitions/116.html), [CAPEC-13](https://capec.mitre.org/data/definitions/13.html), [CAPEC-169](https://capec.mitre.org/data/definitions/169.html), [CAPEC-22](https://capec.mitre.org/data/definitions/22.html), [CAPEC-224](https://capec.mitre.org/data/definitions/224.html), [CAPEC-285](https://capec.mitre.org/data/definitions/285.html), [CAPEC-287](https://capec.mitre.org/data/definitions/287.html), [CAPEC-290](https://capec.mitre.org/data/definitions/290.html), [CAPEC-291](https://capec.mitre.org/data/definitions/291.html), [CAPEC-292](https://capec.mitre.org/data/definitions/292.html), [CAPEC-293](https://capec.mitre.org/data/definitions/293.html), [CAPEC-294](https://capec.mitre.org/data/definitions/294.html), [CAPEC-295](https://capec.mitre.org/data/definitions/295.html), [CAPEC-296](https://capec.mitre.org/data/definitions/296.html), [CAPEC-297](https://capec.mitre.org/data/definitions/297.html), [CAPEC-298](https://capec.mitre.org/data/definitions/298.html), [CAPEC-299](https://capec.mitre.org/data/definitions/299.html), [CAPEC-300](https://capec.mitre.org/data/definitions/300.html), [CAPEC-301](https://capec.mitre.org/data/definitions/301.html), [CAPEC-302](https://capec.mitre.org/data/definitions/302.html), [CAPEC-303](https://capec.mitre.org/data/definitions/303.html), [CAPEC-304](https://capec.mitre.org/data/definitions/304.html), [CAPEC-305](https://capec.mitre.org/data/definitions/305.html), [CAPEC-306](https://capec.mitre.org/data/definitions/306.html), [CAPEC-307](https://capec.mitre.org/data/definitions/307.html), [CAPEC-308](https://capec.mitre.org/data/definitions/308.html), [CAPEC-309](https://capec.mitre.org/data/definitions/309.html), [CAPEC-310](https://capec.mitre.org/data/definitions/310.html), [CAPEC-312](https://capec.mitre.org/data/definitions/312.html), [CAPEC-313](https://capec.mitre.org/data/definitions/313.html), [CAPEC-317](https://capec.mitre.org/data/definitions/317.html), [CAPEC-318](https://capec.mitre.org/data/definitions/318.html), [CAPEC-319](https://capec.mitre.org/data/definitions/319.html), [CAPEC-320](https://capec.mitre.org/data/definitions/320.html), [CAPEC-321](https://capec.mitre.org/data/definitions/321.html), [CAPEC-322](https://capec.mitre.org/data/definitions/322.html), [CAPEC-323](https://capec.mitre.org/data/definitions/323.html), [CAPEC-324](https://capec.mitre.org/data/definitions/324.html), [CAPEC-325](https://capec.mitre.org/data/definitions/325.html), [CAPEC-326](https://capec.mitre.org/data/definitions/326.html), [CAPEC-327](https://capec.mitre.org/data/definitions/327.html), [CAPEC-328](https://capec.mitre.org/data/definitions/328.html), [CAPEC-329](https://capec.mitre.org/data/definitions/329.html), [CAPEC-330](https://capec.mitre.org/data/definitions/330.html), [CAPEC-472](https://capec.mitre.org/data/definitions/472.html), [CAPEC-497](https://capec.mitre.org/data/definitions/497.html), [CAPEC-508](https://capec.mitre.org/data/definitions/508.html), [CAPEC-573](https://capec.mitre.org/data/definitions/573.html), [CAPEC-574](https://capec.mitre.org/data/definitions/574.html), [CAPEC-575](https://capec.mitre.org/data/definitions/575.html), [CAPEC-576](https://capec.mitre.org/data/definitions/576.html), [CAPEC-577](https://capec.mitre.org/data/definitions/577.html), [CAPEC-59](https://capec.mitre.org/data/definitions/59.html), [CAPEC-60](https://capec.mitre.org/data/definitions/60.html), [CAPEC-616](https://capec.mitre.org/data/definitions/616.html), [CAPEC-643](https://capec.mitre.org/data/definitions/643.html), [CAPEC-646](https://capec.mitre.org/data/definitions/646.html), [CAPEC-651](https://capec.mitre.org/data/definitions/651.html), [CAPEC-79](https://capec.mitre.org/data/definitions/79.html)

### Taxonomy mappings

| Taxonomy | Entry ID | Entry name | Fit |
|---|---|---|---|
| PLOVER |  | Information Leak (information disclosure) |  |
| OWASP Top Ten 2007 | A6 | Information Leakage and Improper Error Handling | CWE More Specific |
| WASC | 13 | Information Leakage |  |

### Vulnerability mapping notes

**Usage:** Discouraged

**Rationale:** CWE-200 and its lower-level descendants are intended to cover the mistakes that occur in behaviors that explicitly manage, store, transfer, or cleanse sensitive information. Unfortunately, CWE-200 is commonly misused to represent the loss of confidentiality in a vulnerability. From the CWE perspective, loss of confidentiality is a technical impact, not a root cause error. Loss of confidentiality can arize from many different weaknesses, such as insecure file permissions or out-of-bounds read. As of CWE 4.20, over 400 CWE entries can lead to a loss of confidentiality. Other options are often available. [REF-1287].

**Comments:** If an error or mistake causes information to be disclosed, then use the CWE ID for that error.

**Reasons:** Frequent Misuse, Frequent Misinterpretation, Abstraction

**Suggestions:**
- CWE-201 Insertion of Sensitive Information Into Sent Data: inserting sensitive info into sent data
- CWE-203 Observable Discrepancy: ability to observe discrepancies in behavior or messages
- CWE-538 Insertion of Sensitive Information into Externally-Accessible File or Directory: inserting sensitive info into files/directories
- CWE-285 Improper Authorization: improper authorization allowing sensitive info (see descendants)
- CWE-732 Incorrect Permission Assignment for Critical Resource: insecure permissions allowing sensitive info (see descendants)
- CWE-287 Improper Authentication: improper authentication allowing sensitive info (see descendants)

### Memberships

Categories and views this entry belongs to (for example OWASP Top Ten and earlier CWE Top 25 lists).

| Type | ID | Name |
|---|---|---|
| View | 635 | Weaknesses Originally Used by NVD from 2008 to 2016 |
| Category | 717 | OWASP Top Ten 2007 Category A6 - Information Leakage and Improper Error Handling |
| Category | 963 | SFP Secondary Cluster: Exposed Data |
| View | 1003 | Weaknesses for Simplified Mapping of Published Vulnerabilities |
| View | 1200 | Weaknesses in the 2019 CWE Top 25 Most Dangerous Software Errors |
| View | 1337 | Weaknesses in the 2021 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1345 | OWASP Top Ten 2021 Category A01:2021 - Broken Access Control |
| View | 1350 | Weaknesses in the 2020 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1417 | Comprehensive Categorization: Sensitive Information Exposure |
| View | 1430 | Weaknesses in the 2024 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1435 | Weaknesses in the 2025 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1436 | OWASP Top Ten 2025 Category A01:2025 - Broken Access Control |

### References

- [REF-172] Chris Wysopal. "Mobile App Top 10 List", 2010. https://www.veracode.com/blog/2010/12/mobile-app-top-10-list
- [REF-1287] MITRE. "Supplemental Details - 2022 CWE Top 25", 2022, Details of Problematic Mappings. https://cwe.mitre.org/top25/archive/2022/2022_cwe_top25_supplemental.html#problematicMappingDetails
- [REF-1479] Gregory Larsen, E. Kenneth Hong Fong, David A. Wheeler, Rama S. Moorthy. "State-of-the-Art Resources (SOAR) for Software Vulnerability Detection, Test, and Evaluation", 2014. https://www.ida.org/-/media/feature/publications/s/st/stateoftheart-resources-soar-for-software-vulnerability-detection-test-and-evaluation/p-5061.ashx

### Content history (summary)

- Submitted: 2006-07-19 by PLOVER
- Modified 35 times; latest: 2026-10-28
- Previous names: "Information Leak (Information Disclosure)" (until 2009-12-28); "Information Exposure" (until 2020-02-24)
- Full history: https://cwe.mitre.org/data/definitions/200.html#Content_History

---

*Part 2 is taken from the MITRE CWE List, version 5.0 (2026-10-28), https://cwe.mitre.org. Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation. Used under the CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html). Part 1 was written for the Providus Bank Secure Coding programme by Training Heights.*
