# CWE-476: NULL Pointer Dereference

> **2025 CWE Top 25:** rank 13 · score 6.41 · CVEs in CISA KEV: 0 · change since 2024: +8

## Part 1: Review guide

### What it is, in plain words

The code uses a reference that is null (or undefined), causing a crash, or worse, a code path that "fails open".

### How to spot it

**Java**
- `Optional.get()` without check; method chains on values that can be null (`user.getProfile().getRole()`)
- Catch blocks that treat a `NullPointerException` as success

**C#**
- `!` (null-forgiving) on values that can be null; nullable warnings suppressed
- `FirstOrDefault()` result used without check

**React / Node.js**
- `obj.prop.sub` on data from APIs without optional chaining or checks
- Checks like `if (user.role !== "blocked")` that pass when `role` is undefined
- Unhandled promise rejections crashing Node

### Not this weakness (safe look-alikes)

- Values guaranteed non-null by the type system (C# nullable enabled with no warnings; validated DTOs).

### How to tell it apart from related weaknesses

A null reference is CWE-476. A missing permission check is CWE-862 even if it happens because of a null; report both if the null makes the check fail open.

### Vulnerable and secure examples

#### Java

Vulnerable:

```java
try {
  return amt.compareTo(
    u.getProfile().getDailyLimit()) <= 0;
} catch (Exception e) {
  return true;  // "don't block customers"
}
```

Why: No profile means a NullPointerException, and the catch lets the transfer through.

Secure:

```java
var limit = Optional.ofNullable(u.getProfile())
  .map(Profile::getDailyLimit)
  .orElseThrow(LimitUnavailable::new);
return amt.compareTo(limit) <= 0;
```

Why it works: Fail closed: if the limit can’t be read, the transfer is refused.

#### C#

Vulnerable:

```csharp
try {
  return amount <= user.Profile.DailyLimit;
} catch (NullReferenceException) {
  return true;
}
```

Why: The same fail-open catch block.

Secure:

```csharp
// <Nullable>enable</Nullable> in the .csproj
if (user.Profile?.DailyLimit is not decimal limit)
  return false;  // fail closed
return amount <= limit;
```

Why it works: Nullable reference types flag the risk at compile time.

#### React / Node.js

Vulnerable:

```jsx
function Limit({ customer }) {
  return <p>Daily limit:
    {customer.profile.dailyLimit}</p>;
}
// profile is null for new customers
```

Why: The component throws and the payment screen goes blank.

Secure:

```jsx
function Limit({ customer }) {
  const limit = customer?.profile?.dailyLimit;
  if (limit == null)
    return <p>Limit unavailable</p>;
  return <p>Daily limit: {limit}</p>;
}
```

Why it works: Handle missing data, and turn on TypeScript’s strictNullChecks. The API enforces the limit.

### Fix guidance

**Primary defences**

1. **Fail closed.** If a security check can’t complete, deny.
2. **Make null visible.** Optional, nullable reference types, strictNullChecks.
3. **No catch-all in checks.** Catch specific errors, then refuse.

**Defence in depth**

- Validate required data at the boundary
- Tests for missing records
- Review every catch block in checks
- Alert on repeated exceptions

**In each stack**

- Java: Optional, specific exceptions
- C#: <Nullable>enable</Nullable>
- React / Node.js: strictNullChecks, empty states

**Don't rely on**

- catch (Exception) { return true; }
- Logging and carrying on
- Front-end limit checks

### How to verify the fix

A customer with no profile is refused, with no NullPointerException.

### Severity guide (Providus)

High if a request can crash the service repeatedly or bypass a check; medium otherwise.

---

## Part 2: MITRE CWE entry (complete)

**Abstraction:** Base · **Structure:** Simple · **Status:** Stable  
**MITRE page:** https://cwe.mitre.org/data/definitions/476.html
  
**MITRE diagram:** https://cwe.mitre.org/data/images/CWE-476-Diagram.png

### Description

The product dereferences a pointer that it expects to be valid but is NULL.

### Alternate terms

- **NPD**: Common abbreviation for Null Pointer Dereference
- **null deref**: Common abbreviation for Null Pointer Dereference
- **NPE**: Common abbreviation for Null Pointer Exception
- **nil pointer dereference**: used for access of nil in Go programs

### Common consequences

| Scope | Impact | Likelihood | Note |
|---|---|---|---|
| Availability | DoS: Crash, Exit, or Restart |  | NULL pointer dereferences usually result in the failure of the process unless exception handling (on some platforms) is available and implemented. Even when exception handling is being used, it can still be very difficult to return the software to a safe state of operation. |
| Integrity, Confidentiality | Execute Unauthorized Code or Commands, Read Memory, Modify Memory |  | In rare circumstances, when NULL is equivalent to the 0x0 memory address and privileged code can access it, then writing or reading memory is possible, which may lead to code execution. |

### Likelihood of exploit

Medium

### Modes of introduction

- **Implementation**

### Applicable platforms

- Language: C (Undetermined)
- Language: C++ (Undetermined)
- Language: Java (Undetermined)
- Language: C# (Undetermined)
- Language: Go (Undetermined)
- Language: Python (Undetermined)

### Weakness ordinalities

- **Resultant**: NULL pointer dereferences are frequently resultant from rarely encountered error conditions and race conditions, since these are most likely to escape detection during the testing phases.

### Potential mitigations

**1. Phase: Implementation** · ID: MIT-56

For any pointers that could have been modified or provided from a function that can return NULL, check the pointer for NULL before use. When working with a multithreaded or otherwise asynchronous environment, ensure that proper locking APIs are used to lock before the check, and unlock when it has finished [REF-1484].

**2. Phase: Requirements**

Select a programming language that is not susceptible to these issues.

**3. Phase: Implementation**

Check the results of all functions that return a value and verify that the value is non-null before acting upon it.

*Effectiveness: Moderate*. Checking the return value of the function will typically be sufficient, however beware of race conditions (CWE-362) in a concurrent environment. This solution does not handle the use of improperly initialized variables (CWE-665).

**4. Phase: Architecture and Design**

Identify all variables and data stores that receive information from external sources, and apply input validation to make sure that they are only initialized to expected values.

**5. Phase: Implementation**

Explicitly initialize all variables and other data stores, either during declaration or just before the first usage.

### Detection methods

**Automated Dynamic Analysis** (effectiveness: Moderate)

This weakness can be detected using dynamic tools and techniques that interact with the software using large test suites with many diverse inputs, such as fuzz testing (fuzzing), robustness testing, and fault injection. The software's operation may slow down, but it should not become unstable, crash, or generate incorrect results.

**Manual Dynamic Analysis**

Identify error conditions that are not likely to occur during normal usage and trigger them. For example, run the program under low memory conditions, run with insufficient privileges or permissions, interrupt a transaction before it is completed, or disable connectivity to basic network services such as DNS. Monitor the software for any unexpected behavior. If you trigger an unhandled exception or similar error that was discovered and handled by the application's environment, it may still indicate unexpected conditions that were not handled by the application itself.

**Automated Static Analysis** (effectiveness: High)

Automated static analysis, commonly referred to as Static Application Security Testing (SAST), can find some instances of this weakness by analyzing source code (or binary/compiled code) without having to execute it. Typically, this is done by building a model of data flow and control flow, then searching for potentially-vulnerable patterns that connect "sources" (origins of input) with "sinks" (destinations where the data interacts with external components, a lower layer such as the OS, etc.)

**Automated Dynamic Analysis** (effectiveness: Moderate)

Use tools that are integrated during compilation to insert runtime error-checking mechanisms related to memory safety errors, such as AddressSanitizer (ASan) for C/C++ [REF-1518].

*Crafted inputs are necessary to reach the code containing the error, such as generated by fuzzers. Also, these tools may reduce performance, and they only report the error condition - not the original mistake that led to the error.*

### Demonstrative examples

**Example 1**

This example takes an IP address from a user, verifies that it is well formed and then looks up the hostname and copies it into a buffer.

*Bad code (C):*

```c
void host_lookup(char *user_supplied_addr){
    struct hostent *hp;
    in_addr_t *addr;
    char hostname[64];
    in_addr_t inet_addr(const char *cp);
    /*routine that ensures user_supplied_addr is in the right format for conversion */
    validate_addr_form(user_supplied_addr);
    addr = inet_addr(user_supplied_addr);
    hp = gethostbyaddr( addr, sizeof(struct in_addr), AF_INET);
    strcpy(hostname, hp->h_name);
}
```

If an attacker provides an address that appears to be well-formed, but the address does not resolve to a hostname, then the call to gethostbyaddr() will return NULL. Since the code does not check the return value from gethostbyaddr (CWE-252), a NULL pointer dereference (CWE-476) would then occur in the call to strcpy().

Note that this code is also vulnerable to a buffer overflow (CWE-119).

**Example 2**

In the following code, the programmer assumes that the system always has a property named "cmd" defined. If an attacker can control the program's environment so that "cmd" is not defined, the program throws a NULL pointer exception when it attempts to call the trim() method.

*Bad code (Java):*

```java
String cmd = System.getProperty("cmd");
cmd = cmd.trim();
```

**Example 3**

This Android application has registered to handle a URL when sent an intent:

*Bad code (Java):*

```java
...
IntentFilter filter = new IntentFilter("com.example.URLHandler.openURL");
MyReceiver receiver = new MyReceiver();
registerReceiver(receiver, filter);
...
public class UrlHandlerReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if("com.example.URLHandler.openURL".equals(intent.getAction())) {
            String URL = intent.getStringExtra("URLToOpen");
            int length = URL.length();
        ...
        }
    }
}
```

The application assumes the URL will always be included in the intent. When the URL is not present, the call to getStringExtra() will return null, thus causing a null pointer exception when length() is called.

**Example 4**

Consider the following example of a typical client server exchange. The HandleRequest function is intended to perform a request and use a defer to close the connection whenever the function returns.

*Bad code (Go):*

```go
func HandleRequest(client http.Client, request *http.Request) (*http.Response, error) {
    response, err := client.Do(request)
    defer response.Body.Close()
    if err != nil {
        return nil, err
    }
    ...
}
```

If a user supplies a malformed request or violates the client policy, the Do method can return a nil response and a non-nil err.

This HandleRequest Function evaluates the close before checking the error. A deferred call's arguments are evaluated immediately, so the defer statement panics due to a nil response.

### Observed examples (real vulnerabilities)

| Reference | Description |
|---|---|
| [CVE-2024-41130](https://www.cve.org/CVERecord?id=CVE-2024-41130) | C++ library for LLM inference has NULL pointer dereference if a read operation fails |
| [CVE-2005-3274](https://www.cve.org/CVERecord?id=CVE-2005-3274) | race condition causes a table to be corrupted if a timer activates while it is being modified, leading to resultant NULL dereference; also involves locking. |
| [CVE-2002-1912](https://www.cve.org/CVERecord?id=CVE-2002-1912) | large number of packets leads to NULL dereference |
| [CVE-2005-0772](https://www.cve.org/CVERecord?id=CVE-2005-0772) | packet with invalid error status value triggers NULL dereference |
| [CVE-2009-4895](https://www.cve.org/CVERecord?id=CVE-2009-4895) | Chain: race condition for an argument value, possibly resulting in NULL dereference |
| [CVE-2020-29652](https://www.cve.org/CVERecord?id=CVE-2020-29652) | ssh component for Go allows clients to cause a denial of service (nil pointer dereference) against SSH servers. |
| [CVE-2009-2692](https://www.cve.org/CVERecord?id=CVE-2009-2692) | Chain: Use of an unimplemented network socket operation pointing to an uninitialized handler function (CWE-456) causes a crash because of a null pointer dereference (CWE-476). |
| [CVE-2009-3547](https://www.cve.org/CVERecord?id=CVE-2009-3547) | Chain: race condition (CWE-362) might allow resource to be released before operating on it, leading to NULL dereference (CWE-476) |
| [CVE-2009-3620](https://www.cve.org/CVERecord?id=CVE-2009-3620) | Chain: some unprivileged ioctls do not verify that a structure has been initialized before invocation, leading to NULL dereference |
| [CVE-2009-2698](https://www.cve.org/CVERecord?id=CVE-2009-2698) | Chain: IP and UDP layers each track the same value with different mechanisms that can get out of sync, possibly resulting in a NULL dereference |
| [CVE-2009-0949](https://www.cve.org/CVERecord?id=CVE-2009-0949) | Chain: improper initialization of memory can lead to NULL dereference |
| [CVE-2008-3597](https://www.cve.org/CVERecord?id=CVE-2008-3597) | Chain: game server can access player data structures before initialization has happened leading to NULL dereference |
| [CVE-2020-6078](https://www.cve.org/CVERecord?id=CVE-2020-6078) | Chain: The return value of a function returning a pointer is not checked for success (CWE-252) resulting in the later use of an uninitialized variable (CWE-456) and a null pointer dereference (CWE-476) |
| [CVE-2008-0062](https://www.cve.org/CVERecord?id=CVE-2008-0062) | Chain: a message having an unknown message type may cause a reference to uninitialized memory resulting in a null pointer dereference (CWE-476) or dangling pointer (CWE-825), possibly crashing the system or causing heap corruption. |
| [CVE-2008-5183](https://www.cve.org/CVERecord?id=CVE-2008-5183) | Chain: unchecked return value can lead to NULL dereference |
| [CVE-2004-0079](https://www.cve.org/CVERecord?id=CVE-2004-0079) | SSL software allows remote attackers to cause a denial of service (crash) via a crafted SSL/TLS handshake that triggers a null dereference. |
| [CVE-2004-0365](https://www.cve.org/CVERecord?id=CVE-2004-0365) | Network monitor allows remote attackers to cause a denial of service (crash) via a malformed RADIUS packet that triggers a null dereference. |
| [CVE-2003-1013](https://www.cve.org/CVERecord?id=CVE-2003-1013) | Network monitor allows remote attackers to cause a denial of service (crash) via a malformed Q.931, which triggers a null dereference. |
| [CVE-2003-1000](https://www.cve.org/CVERecord?id=CVE-2003-1000) | Chat client allows remote attackers to cause a denial of service (crash) via a passive DCC request with an invalid ID number, which causes a null dereference. |
| [CVE-2004-0389](https://www.cve.org/CVERecord?id=CVE-2004-0389) | Server allows remote attackers to cause a denial of service (crash) via malformed requests that trigger a null dereference. |
| [CVE-2004-0119](https://www.cve.org/CVERecord?id=CVE-2004-0119) | OS allows remote attackers to cause a denial of service (crash from null dereference) or execute arbitrary code via a crafted request during authentication protocol selection. |
| [CVE-2004-0458](https://www.cve.org/CVERecord?id=CVE-2004-0458) | Game allows remote attackers to cause a denial of service (server crash) via a missing argument, which triggers a null pointer dereference. |
| [CVE-2002-0401](https://www.cve.org/CVERecord?id=CVE-2002-0401) | Network monitor allows remote attackers to cause a denial of service (crash) or execute arbitrary code via malformed packets that cause a NULL pointer dereference. |
| [CVE-2001-1559](https://www.cve.org/CVERecord?id=CVE-2001-1559) | Chain: System call returns wrong value (CWE-393), leading to a resultant NULL dereference (CWE-476). |

### Relationships

Includes relationships recorded on this entry and those recorded on other entries that point to it (as MITRE's page shows them).

| Nature | CWE | Name | View | Recorded on |
|---|---|---|---|---|
| ChildOf (primary) | CWE-710 | Improper Adherence to Coding Standards | 1000 Complete Weakness Hierarchy | this entry |
| ChildOf | CWE-754 | Improper Check for Unusual or Exceptional Conditions | 1000 Complete Weakness Hierarchy | this entry |
| ChildOf (primary) | CWE-754 | Improper Check for Unusual or Exceptional Conditions | 1003 Weaknesses for Simplified Mapping of Published Vulnerabilities | this entry |
| CanFollow | CWE-252 | Unchecked Return Value | 1000 Complete Weakness Hierarchy | CWE-252 |
| CanFollow | CWE-362 | Concurrent Execution using Shared Resource with Improper Synchronization | 1000 Complete Weakness Hierarchy | CWE-362 |
| CanFollow | CWE-789 | Memory Allocation with Excessive Size Value | 1000 Complete Weakness Hierarchy | CWE-789 |
| CanFollow | CWE-1325 | Improperly Controlled Sequential Memory Allocation | 1000 Complete Weakness Hierarchy | CWE-1325 |

### Taxonomy mappings

| Taxonomy | Entry ID | Entry name | Fit |
|---|---|---|---|
| 7 Pernicious Kingdoms |  | Null Dereference |  |
| CLASP |  | Null-pointer dereference |  |
| PLOVER |  | Null Dereference (Null Pointer Dereference) |  |
| OWASP Top Ten 2004 | A9 | Denial of Service | CWE More Specific |
| CERT C Secure Coding | EXP34-C | Do not dereference null pointers | Exact |
| Software Fault Patterns | SFP7 | Faulty Pointer Use |  |
| OpenSSF Secure Coding Guide for Python | pyscg-0034 | Check for None Values |  |

### Vulnerability mapping notes

**Usage:** Allowed

**Rationale:** This CWE entry is at the Base level of abstraction, which is a preferred level of abstraction for mapping to the root causes of vulnerabilities.

**Comments:** Carefully read both the name and description to ensure that this mapping is an appropriate fit. Do not try to 'force' a mapping to a lower-level Base/Variant simply to comply with this preferred level of abstraction.

**Reasons:** Acceptable-Use

### Dimensions

Behavior-Type: Dereferenc; Resource-Type: Pointer; Resource-Property: NULL

### Memberships

Categories and views this entry belongs to (for example OWASP Top Ten and earlier CWE Top 25 lists).

| Type | ID | Name |
|---|---|---|
| Category | 398 | 7PK - Code Quality |
| Category | 465 | Pointer Issues |
| Category | 730 | OWASP Top Ten 2004 Category A9 - Denial of Service |
| Category | 737 | CERT C Secure Coding Standard (2008) Chapter 4 - Expressions (EXP) |
| Category | 742 | CERT C Secure Coding Standard (2008) Chapter 9 - Memory Management (MEM) |
| Category | 808 | 2010 Top 25 - Weaknesses On the Cusp |
| Category | 867 | 2011 Top 25 - Weaknesses On the Cusp |
| Category | 871 | CERT C++ Secure Coding Section 03 - Expressions (EXP) |
| Category | 876 | CERT C++ Secure Coding Section 08 - Memory Management (MEM) |
| View | 884 | CWE Cross-section |
| Category | 971 | SFP Secondary Cluster: Faulty Pointer Use |
| Category | 1136 | SEI CERT Oracle Secure Coding Standard for Java - Guidelines 02. Expressions (EXP) |
| Category | 1157 | SEI CERT C Coding Standard - Guidelines 03. Expressions (EXP) |
| View | 1200 | Weaknesses in the 2019 CWE Top 25 Most Dangerous Software Errors |
| Category | 1306 | CISQ Quality Measures - Reliability |
| View | 1337 | Weaknesses in the 2021 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1350 | Weaknesses in the 2020 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1387 | Weaknesses in the 2022 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1412 | Comprehensive Categorization: Poor Coding Practices |
| View | 1425 | Weaknesses in the 2023 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1430 | Weaknesses in the 2024 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1435 | Weaknesses in the 2025 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1445 | OWASP Top Ten 2025 Category A10:2025 - Mishandling of Exceptional Conditions |
| Category | 1458 | OpenSSF Secure Coding Guide for Python (2026) - 08 Coding Standards |

### References

- [REF-6] Katrina Tsipenyuk, Brian Chess, Gary McGraw. "Seven Pernicious Kingdoms: A Taxonomy of Software Security Errors", 2005. https://cwe.mitre.org/documents/sources/SevenPerniciousKingdoms.pdf
- [REF-18] Secure Software, Inc.. "The CLASP Application Security Process", 2005. https://cwe.mitre.org/documents/sources/TheCLASPApplicationSecurityProcess.pdf
- [REF-1031] "Null pointer / Null dereferencing", 2019. https://en.wikipedia.org/wiki/Null_pointer#Null_dereferencing
- [REF-1032] "Null Reference Creation and Null Pointer Dereference". https://developer.apple.com/documentation/xcode/null-reference-creation-and-null-pointer-dereference
- [REF-1033] "NULL Pointer Dereference [CWE-476]", 2012. https://www.immuniweb.com/vulnerability/null-pointer-dereference.html
- [REF-1484] D3FEND. "D3FEND: D3-NPC Null Pointer Checking". https://d3fend.mitre.org/technique/d3f:NullPointerChecking//
- [REF-1518] "AddressSanitizer". https://clang.llvm.org/docs/AddressSanitizer.html
- [REF-1534] OMG. "Automated Technical Debt Measure, Version 2", 2024. https://www.omg.org/spec/ATDM2/1.0/PDF
- [REF-1541] OpenSSF. "Secure Coding Guide for Python", 08 Coding Standards. https://best.openssf.org/Secure-Coding-Guide-for-Python/

### Content history (summary)

- Submitted: 2006-07-19 by 7 Pernicious Kingdoms
- Modified 41 times; latest: 2026-10-28
- Full history: https://cwe.mitre.org/data/definitions/476.html#Content_History

---

*Part 2 is taken from the MITRE CWE List, version 5.0 (2026-10-28), https://cwe.mitre.org. Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation. Used under the CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html). Part 1 was written for the Providus Bank Secure Coding programme by Training Heights.*
