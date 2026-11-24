# CWE-770: Allocation of Resources Without Limits or Throttling

> **2025 CWE Top 25:** rank 25 · score 2.54 · CVEs in CISA KEV: 0 · change since 2024: +1

## Part 1: Review guide

### What it is, in plain words

The code allocates memory, threads, connections or work based on input with no upper limit or rate limit, so one request can exhaust the service.

### How to spot it

**Java**
- `pageSize`, `rows` or `limit` parameters without maximum
- Reading entire uploads or request bodies into memory
- No rate limiting on OTP, login or export endpoints

**C#**
- `Take(count)` with unchecked input
- `ReadToEndAsync` on unbounded streams; no `RequestSizeLimit`
- Unbounded `Task.Run`/parallel loops per request

**React / Node.js**
- `express.json()` with no `limit`
- Unbounded `Promise.all` over user-supplied lists
- No rate limit on API routes

### Not this weakness (safe look-alikes)

- Limits enforced on the server (max page size, body size, rate limits) even if the client also limits.

### How to tell it apart from related weaknesses

No limit on resources is CWE-770. A loop with no exit is CWE-835; regex catastrophic backtracking is CWE-1333 (neither in the Top 25).

### Vulnerable and secure examples

#### Java

Vulnerable:

```java
@GetMapping("/transactions")
Page<Tx> list(@RequestParam int page,
              @RequestParam int size) {
  return repo.findAll(PageRequest.of(page, size));
}  // size=10000000
```

Why: One request loads years of history into memory.

Secure:

```java
int capped = Math.min(Math.max(size, 1), 100);
return repo.findAll(PageRequest.of(page, capped));
// OTP: Bucket4j, 3 per phone per 10 minutes
Bucket b = Bucket.builder().addLimit(l -> l
  .capacity(3).refillIntervally(3, ofMinutes(10)))
  .build();
```

Why it works: Cap sizes on the server, and rate-limit expensive actions.

#### C#

Vulnerable:

```csharp
app.MapPost("/otp/send", SendOtp);  // unlimited
app.MapGet("/transactions", (int size) =>
  db.Transactions.Take(size));
```

Why: No rate limit and no page cap.

Secure:

```csharp
builder.Services.AddRateLimiter(o =>
  o.AddFixedWindowLimiter("otp", l => {
    l.PermitLimit = 3;
    l.Window = TimeSpan.FromMinutes(10); }));
app.MapPost("/otp/send", SendOtp)
  .RequireRateLimiting("otp");
// and Take(Math.Clamp(size, 1, 100))
```

Why it works: Built-in ASP.NET Core rate limiting (.NET 7+).

#### React / Node.js

*Context:* The UI can slow people down, but only the server can enforce a limit.

Vulnerable:

```jsx
// "Resend code" works as fast as you can click
<button onClick={sendOtp}>Resend code</button>
// and a script can call /otp/send directly
```

Why: Every click is a paid SMS.

Secure:

```jsx
<button disabled={wait > 0}
  onClick={async () => { await sendOtp();
    setWait(60); }}>
  {wait ? `Resend in ${wait}s` : "Resend code"}
</button>
// countdown effect not shown
```

Why it works: A cool-down in the UI, backed by a rate limit on the server.

### Fix guidance

**Primary defences**

1. **Rate-limit expensive actions.** Per user, phone number and IP.
2. **Cap every size.** Pages, uploads, exports, request bodies.
3. **Timeouts everywhere.** Database, HTTP calls, background jobs.

**Defence in depth**

- Large exports as background jobs
- CAPTCHA after repeated OTPs
- Spending alerts on the SMS gateway
- Load tests with abusive patterns

**In each stack**

- Java: Bucket4j; capped Pageable
- C#: AddRateLimiter; Math.Clamp
- React / Node.js: Cool-down buttons for UX

**Don't rely on**

- Front-end limits
- IP-only limits
- “Nobody would do that”

### How to verify the fix

The 4th OTP in 10 minutes returns 429; size=1000000 returns 100 rows.

### Severity guide (Providus)

High for core banking and payment services (availability); medium elsewhere.

---

## Part 2: MITRE CWE entry (complete)

**Abstraction:** Base · **Structure:** Simple · **Status:** Incomplete  
**MITRE page:** https://cwe.mitre.org/data/definitions/770.html
  
**MITRE diagram:** https://cwe.mitre.org/data/images/CWE-770-Diagram.png

### Description

The product allocates a reusable resource or group of resources on behalf of an actor without imposing any intended restrictions on the size or number of resources that can be allocated.

### Common consequences

| Scope | Impact | Likelihood | Note |
|---|---|---|---|
| Availability | DoS: Resource Consumption (CPU), DoS: Resource Consumption (Memory), DoS: Resource Consumption (Other) |  | When allocating resources without limits, an attacker could prevent other systems, applications, or processes from accessing the same type of resource. It can be easy for an attacker to consume many resources by rapidly making many requests or causing larger resources to be used than is needed. |

### Likelihood of exploit

High

### Modes of introduction

- **Architecture and Design**: OMISSION: This weakness is caused by missing a security tactic during the architecture and design phase.
- **Implementation**
- **Operation**
- **System Configuration**

### Applicable platforms

- Language: Class: Not Language-Specific (Often)
- Technology: Class: Not Technology-Specific (Undetermined)

### Weakness ordinalities

- **Primary**

### Potential mitigations

**1. Phase: Requirements**

Clearly specify the minimum and maximum expectations for capabilities, and dictate which behaviors are acceptable when resource allocation reaches limits.

**2. Phase: Architecture and Design**

Limit the amount of resources that are accessible to unprivileged users. Set per-user limits for resources. Allow the system administrator to define these limits. Be careful to avoid CWE-410.

**3. Phase: Architecture and Design**

Design throttling mechanisms into the system architecture. The best protection is to limit the amount of resources that an unauthorized user can cause to be expended. A strong authentication and access control model will help prevent such attacks from occurring in the first place, and it will help the administrator to identify who is committing the abuse. The login application should be protected against DoS attacks as much as possible. Limiting the database access, perhaps by caching result sets, can help minimize the resources expended. To further limit the potential for a DoS attack, consider tracking the rate of requests received from users and blocking requests that exceed a defined rate threshold.

**4. Phase: Implementation** · Strategy: Input Validation · ID: MIT-5

Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., use a list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications, or transform it into something that does.

When performing input validation, consider all potentially relevant properties, including length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to business rules. As an example of business rule logic, "boat" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if the input is only expected to contain colors such as "red" or "blue."

Do not rely exclusively on looking for malicious or malformed inputs. This is likely to miss at least one undesirable input, especially if the code's environment changes. This can give attackers enough room to bypass the intended validation. However, denylists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright.

**5. Phase: Architecture and Design** · ID: MIT-15

For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side, in order to avoid CWE-602. Attackers can bypass the client-side checks by modifying values after the checks have been performed, or by changing the client to remove the client-side checks entirely. Then, these modified values would be submitted to the server.

**6. Phase: Architecture and Design**

Mitigation of resource exhaustion attacks requires that the target system either:

- recognizes the attack and denies that user further access for a given amount of time, typically by using increasing time delays
- uniformly throttles all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

The first of these solutions is an issue in itself though, since it may allow attackers to prevent the use of the system by a particular valid user. If the attacker impersonates the valid user, they may be able to prevent the user from accessing the server in question.

The second solution can be difficult to effectively institute -- and even when properly done, it does not provide a full solution. It simply requires more resources on the part of the attacker.

**7. Phase: Architecture and Design**

Ensure that protocols have specific limits of scale placed on them.

**8. Phase: Architecture and Design, Implementation** · ID: MIT-38.1

If the program must fail, ensure that it fails gracefully (fails closed). There may be a temptation to simply let the program fail poorly in cases such as low memory conditions, but an attacker may be able to assert control before the software has fully exited. Alternately, an uncontrolled failure could cause cascading problems with other downstream components; for example, the program could send a signal to a downstream process so the process immediately knows that a problem has occurred and has a better chance of recovery.

Ensure that all failures in resource allocation place the system into a safe posture.

**9. Phase: Operation, Architecture and Design** · Strategy: Resource Limitation · ID: MIT-47

Use quotas or other resource-limiting settings provided by the operating system or environment. For example, when managing system resources in POSIX, setrlimit() can be used to set limits for certain types of resources, and getrlimit() can determine how many resources are available. However, these functions are not available on all operating systems.

When the current levels get close to the maximum that is defined for the application (see CWE-770), then limit the allocation of further resources to privileged users; alternately, begin releasing resources for less-privileged users. While this mitigation may protect the system from attack, it will not necessarily stop attackers from adversely impacting other users.

Ensure that the application performs the appropriate error checks and error handling in case resources become unavailable (CWE-703).

### Detection methods

**Manual Static Analysis**

Manual static analysis can be useful for finding this weakness, but it might not achieve desired code coverage within limited time constraints. If denial-of-service is not considered a significant risk, or if there is strong emphasis on consequences such as code execution, then manual analysis may not focus on this weakness at all.

**Fuzzing** (effectiveness: Opportunistic)

While fuzzing is typically geared toward finding low-level implementation bugs, it can inadvertently find uncontrolled resource allocation problems. This can occur when the fuzzer generates a large number of test cases but does not restart the targeted product in between test cases. If an individual test case produces a crash, but it does not do so reliably, then an inability to limit resource allocation may be the cause.

When the allocation is directly affected by numeric inputs, then fuzzing may produce indications of this weakness.

**Automated Dynamic Analysis**

Certain automated dynamic analysis techniques may be effective in producing side effects of uncontrolled resource allocation problems, especially with resources such as processes, memory, and connections. The technique may involve generating a large number of requests to the product within a short time frame. Manual analysis is likely required to interpret the results.

**Automated Static Analysis**

Specialized configuration or tuning may be required to train automated tools to recognize this weakness.

Automated static analysis typically has limited utility in recognizing unlimited allocation problems, except for the missing release of program-independent system resources such as files, sockets, and processes, or unchecked arguments to memory. For system resources, automated static analysis may be able to detect circumstances in which resources are not released after they have expired, or if too much of a resource is requested at once, as can occur with memory. Automated analysis of configuration files may be able to detect settings that do not specify a maximum value.

Automated static analysis tools will not be appropriate for detecting exhaustion of custom resources, such as an intended security policy in which a bulletin board user is only allowed to make a limited number of posts per day.

### Demonstrative examples

**Example 1**

This code allocates a socket and forks each time it receives a new connection.

*Bad code (C):*

```c
sock=socket(AF_INET, SOCK_STREAM, 0);
while (1) {
    newsock=accept(sock, ...);
    printf("A connection has been accepted\n");
    pid = fork();
}
```

The program does not track how many connections have been made, and it does not limit the number of connections. Because forking is a relatively expensive operation, an attacker would be able to cause the system to run out of CPU, processes, or memory by making a large number of connections. Alternatively, an attacker could consume all available connections, preventing others from accessing the system remotely.

**Example 2**

In the following example a server socket connection is used to accept a request to store data on the local file system using a specified filename. The method openSocketConnection establishes a server socket to accept requests from a client. When a client establishes a connection to this service the getNextMessage method is first used to retrieve from the socket the name of the file to store the data, the openFileToWrite method will validate the filename and open a file to write to on the local file system. The getNextMessage is then used within a while loop to continuously read data from the socket and output the data to the file until there is no longer any data from the socket.

*Bad code (C):*

```c
int writeDataFromSocketToFile(char *host, int port)
{
    char filename[FILENAME_SIZE];
    char buffer[BUFFER_SIZE];
    int socket = openSocketConnection(host, port);
    if (socket < 0) {
        printf("Unable to open socket connection");
        return(FAIL);
    }
    if (getNextMessage(socket, filename, FILENAME_SIZE) > 0) {
        if (openFileToWrite(filename) > 0) {
            while (getNextMessage(socket, buffer, BUFFER_SIZE) > 0){
                if (!(writeToFile(buffer) > 0))
                    break;
            }
        }
        closeFile();
    }
    closeSocket(socket);
}
```

This example creates a situation where data can be dumped to a file on the local file system without any limits on the size of the file. This could potentially exhaust file or disk resources and/or limit other clients' ability to access the service.

**Example 3**

In the following example, the processMessage method receives a two dimensional character array containing the message to be processed. The two-dimensional character array contains the length of the message in the first character array and the message body in the second character array. The getMessageLength method retrieves the integer value of the length from the first character array. After validating that the message length is greater than zero, the body character array pointer points to the start of the second character array of the two-dimensional character array and memory is allocated for the new body character array.

*Bad code (C):*

```c
/* process message accepts a two-dimensional character array of the form [length][body] containing the message to be processed */
int processMessage(char **message)
{
    char *body;
    int length = getMessageLength(message[0]);
    if (length > 0) {
        body = &message[1][0];
        processMessageBody(body);
        return(SUCCESS);
    }
    else {
        printf("Unable to process message; invalid message length");
        return(FAIL);
    }
}
```

This example creates a situation where the length of the body character array can be very large and will consume excessive memory, exhausting system resources. This can be avoided by restricting the length of the second character array with a maximum length check

Also, consider changing the type from 'int' to 'unsigned int', so that you are always guaranteed that the number is positive. This might not be possible if the protocol specifically requires allowing negative values, or if you cannot control the return value from getMessageLength(), but it could simplify the check to ensure the input is positive, and eliminate other errors such as signed-to-unsigned conversion errors (CWE-195) that may occur elsewhere in the code.

*Good code (C):*

```c
unsigned int length = getMessageLength(message[0]);
if ((length > 0) && (length < MAX_LENGTH)) {...}
```

**Example 4**

In the following example, a server object creates a server socket and accepts client connections to the socket. For every client connection to the socket a separate thread object is generated using the ClientSocketThread class that handles request made by the client through the socket.

*Bad code (Java):*

```java
public void acceptConnections() {
    try {
        ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
        int counter = 0;
        boolean hasConnections = true;
        while (hasConnections) {
            Socket client = serverSocket.accept();
            Thread t = new Thread(new ClientSocketThread(client));
            t.setName(client.getInetAddress().getHostName() + ":" + counter++);
            t.start();
        }
        serverSocket.close();
    } catch (IOException ex) {...}
}
```

In this example there is no limit to the number of client connections and client threads that are created. Allowing an unlimited number of client connections and threads could potentially overwhelm the system and system resources.

The server should limit the number of client connections and the client threads that are created. This can be easily done by creating a thread pool object that limits the number of threads that are generated.

*Good code (Java):*

```java
public static final int SERVER_PORT = 4444;
public static final int MAX_CONNECTIONS = 10;
...
public void acceptConnections() {
    try {
        ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
        int counter = 0;
        boolean hasConnections = true;
        while (hasConnections) {
            hasConnections = checkForMoreConnections();
            Socket client = serverSocket.accept();
            Thread t = new Thread(new ClientSocketThread(client));
            t.setName(client.getInetAddress().getHostName() + ":" + counter++);
            ExecutorService pool = Executors.newFixedThreadPool(MAX_CONNECTIONS);
            pool.execute(t);
        }
        serverSocket.close();
    } catch (IOException ex) {...}
}
```

**Example 5**

An unnamed web site allowed a user to purchase tickets for an event. A menu option allowed the user to purchase up to 10 tickets, but the back end did not restrict the actual number of tickets that could be purchased [REF-667].

**Example 6**

Here the problem is that every time a connection is made, more memory is allocated. So if one just opened up more and more connections, eventually the machine would run out of memory.

*Bad code (C):*

```c
bar connection() {
    foo = malloc(1024);
    return foo;
}
endConnection(bar foo) {
    free(foo);
}
int main() {
    while(1) {
        foo=connection();
    }
    endConnection(foo)
}
```

### Observed examples (real vulnerabilities)

| Reference | Description |
|---|---|
| [CVE-2019-19911](https://www.cve.org/CVERecord?id=CVE-2019-19911) | Chain: Python library does not limit the resources used to process images that specify a very large number of bands (CWE-1284), leading to excessive memory consumption (CWE-789) or an integer overflow (CWE-190). |
| [CVE-2009-4017](https://www.cve.org/CVERecord?id=CVE-2009-4017) | Language interpreter does not restrict the number of temporary files being created when handling a MIME request with a large number of parts.. |
| [CVE-2009-2726](https://www.cve.org/CVERecord?id=CVE-2009-2726) | Driver does not use a maximum width when invoking sscanf style functions, causing stack consumption. |
| [CVE-2009-2540](https://www.cve.org/CVERecord?id=CVE-2009-2540) | Large integer value for a length property in an object causes a large amount of memory allocation. |
| [CVE-2009-2054](https://www.cve.org/CVERecord?id=CVE-2009-2054) | Product allows exhaustion of file descriptors when processing a large number of TCP packets. |
| [CVE-2008-5180](https://www.cve.org/CVERecord?id=CVE-2008-5180) | Communication product allows memory consumption with a large number of SIP requests, which cause many sessions to be created. |
| [CVE-2008-1700](https://www.cve.org/CVERecord?id=CVE-2008-1700) | Product allows attackers to cause a denial of service via a large number of directives, each of which opens a separate window. |
| [CVE-2005-4650](https://www.cve.org/CVERecord?id=CVE-2005-4650) | CMS does not restrict the number of searches that can occur simultaneously, leading to resource exhaustion. |
| [CVE-2020-15100](https://www.cve.org/CVERecord?id=CVE-2020-15100) | web application scanner attempts to read an excessively large file created by a user, causing process termination |
| [CVE-2020-7218](https://www.cve.org/CVERecord?id=CVE-2020-7218) | Go-based workload orchestrator does not limit resource usage with unauthenticated connections, allowing a DoS by flooding the service |

### Relationships

Includes relationships recorded on this entry and those recorded on other entries that point to it (as MITRE's page shows them).

| Nature | CWE | Name | View | Recorded on |
|---|---|---|---|---|
| ChildOf (primary) | CWE-400 | Uncontrolled Resource Consumption | 1000 Complete Weakness Hierarchy | this entry |
| ChildOf | CWE-665 | Improper Initialization | 1000 Complete Weakness Hierarchy | this entry |
| ChildOf (primary) | CWE-400 | Uncontrolled Resource Consumption | 1003 Weaknesses for Simplified Mapping of Published Vulnerabilities | this entry |
| ParentOf | CWE-774 | Allocation of File Descriptors or Handles Without Limits or Throttling | 1000 Complete Weakness Hierarchy | CWE-774 |
| ParentOf | CWE-789 | Memory Allocation with Excessive Size Value | 1000 Complete Weakness Hierarchy | CWE-789 |
| ParentOf | CWE-1325 | Improperly Controlled Sequential Memory Allocation | 1000 Complete Weakness Hierarchy | CWE-1325 |
| CanFollow | CWE-20 | Improper Input Validation | 1000 Complete Weakness Hierarchy | CWE-20 |

### Related attack patterns (CAPEC)

[CAPEC-125](https://capec.mitre.org/data/definitions/125.html), [CAPEC-130](https://capec.mitre.org/data/definitions/130.html), [CAPEC-147](https://capec.mitre.org/data/definitions/147.html), [CAPEC-197](https://capec.mitre.org/data/definitions/197.html), [CAPEC-229](https://capec.mitre.org/data/definitions/229.html), [CAPEC-230](https://capec.mitre.org/data/definitions/230.html), [CAPEC-231](https://capec.mitre.org/data/definitions/231.html), [CAPEC-469](https://capec.mitre.org/data/definitions/469.html), [CAPEC-482](https://capec.mitre.org/data/definitions/482.html), [CAPEC-486](https://capec.mitre.org/data/definitions/486.html), [CAPEC-487](https://capec.mitre.org/data/definitions/487.html), [CAPEC-488](https://capec.mitre.org/data/definitions/488.html), [CAPEC-489](https://capec.mitre.org/data/definitions/489.html), [CAPEC-490](https://capec.mitre.org/data/definitions/490.html), [CAPEC-491](https://capec.mitre.org/data/definitions/491.html), [CAPEC-493](https://capec.mitre.org/data/definitions/493.html), [CAPEC-494](https://capec.mitre.org/data/definitions/494.html), [CAPEC-495](https://capec.mitre.org/data/definitions/495.html), [CAPEC-496](https://capec.mitre.org/data/definitions/496.html), [CAPEC-528](https://capec.mitre.org/data/definitions/528.html)

### Taxonomy mappings

| Taxonomy | Entry ID | Entry name | Fit |
|---|---|---|---|
| The CERT Oracle Secure Coding Standard for Java (2011) | FIO04-J | Close resources when they are no longer needed |  |
| The CERT Oracle Secure Coding Standard for Java (2011) | SER12-J | Avoid memory and resource leaks during serialization |  |
| The CERT Oracle Secure Coding Standard for Java (2011) | MSC05-J | Do not exhaust heap space |  |
| ISA/IEC 62443 | Part 4-2 | Req CR 7.2 |  |
| ISA/IEC 62443 | Part 4-2 | Req CR 2.7 |  |
| ISA/IEC 62443 | Part 4-1 | Req SI-1 |  |
| ISA/IEC 62443 | Part 4-1 | Req SI-2 |  |
| ISA/IEC 62443 | Part 3-3 | Req SR 7.2 |  |
| ISA/IEC 62443 | Part 3-3 | Req SR 2.7 |  |

### Vulnerability mapping notes

**Usage:** Allowed

**Rationale:** This CWE entry is at the Base level of abstraction, which is a preferred level of abstraction for mapping to the root causes of vulnerabilities.

**Comments:** Carefully read both the name and description to ensure that this mapping is an appropriate fit. Do not try to 'force' a mapping to a lower-level Base/Variant simply to comply with this preferred level of abstraction.

**Reasons:** Acceptable-Use

### Notes

**Relationship:** This entry is different from uncontrolled resource consumption (CWE-400) in that there are other weaknesses that are related to inability to control resource consumption, such as holding on to a resource too long after use, or not correctly keeping track of active resources so that they can be managed and released when they are finished (CWE-771).

**Theoretical:** Vulnerability theory is largely about how behaviors and resources interact. "Resource exhaustion" can be regarded as either a consequence or an attack, depending on the perspective. This entry is an attempt to reflect one of the underlying weaknesses that enable these attacks (or consequences) to take place.

### Dimensions

Behavior-Type: Allocation; Behavior-Property: Without Limits or Throttling; Resource-Type: Resources

### Memberships

Categories and views this entry belongs to (for example OWASP Top Ten and earlier CWE Top 25 lists).

| Type | ID | Name |
|---|---|---|
| Category | 399 | Resource Management Errors |
| Category | 802 | 2010 Top 25 - Risky Resource Management |
| Category | 840 | Business Logic Errors |
| Category | 857 | The CERT Oracle Secure Coding Standard for Java (2011) Chapter 14 - Input Output (FIO) |
| Category | 858 | The CERT Oracle Secure Coding Standard for Java (2011) Chapter 15 - Serialization (SER) |
| Category | 861 | The CERT Oracle Secure Coding Standard for Java (2011) Chapter 18 - Miscellaneous (MSC) |
| Category | 867 | 2011 Top 25 - Weaknesses On the Cusp |
| Category | 876 | CERT C++ Secure Coding Section 08 - Memory Management (MEM) |
| Category | 877 | CERT C++ Secure Coding Section 09 - Input Output (FIO) |
| View | 884 | CWE Cross-section |
| Category | 985 | SFP Secondary Cluster: Unrestricted Consumption |
| Category | 1011 | Authorize Actors |
| Category | 1147 | SEI CERT Oracle Secure Coding Standard for Java - Guidelines 13. Input Output (FIO) |
| Category | 1148 | SEI CERT Oracle Secure Coding Standard for Java - Guidelines 14. Serialization (SER) |
| Category | 1152 | SEI CERT Oracle Secure Coding Standard for Java - Guidelines 49. Miscellaneous (MSC) |
| Category | 1416 | Comprehensive Categorization: Resource Lifecycle Management |
| View | 1435 | Weaknesses in the 2025 CWE Top 25 Most Dangerous Software Weaknesses |

### References

- [REF-386] Joao Antunes, Nuno Ferreira Neves, Paulo Verissimo. "Detection and Prediction of Resource-Exhaustion Vulnerabilities", 2008. https://www.di.fc.ul.pt/~nuno/PAPERS/ISSRE08.pdf
- [REF-387] D.J. Bernstein. "Resource exhaustion". http://cr.yp.to/docs/resources.html
- [REF-388] Pascal Meunier. "Resource exhaustion", 2004. http://homes.cerias.purdue.edu/~pmeunier/secprog/sanitized/class1/6.resource%20exhaustion.ppt
- [REF-7] Michael Howard, David LeBlanc. "Writing Secure Code", 2002, Chapter 17, "Protecting Against Denial of Service Attacks" Page 517. https://www.microsoftpressstore.com/store/writing-secure-code-9780735617223
- [REF-667] Rafal Los. "Real-Life Example of a 'Business Logic Defect' (Screen Shots!)", 2011. http://h30501.www3.hp.com/t5/Following-the-White-Rabbit-A/Real-Life-Example-of-a-Business-Logic-Defect-Screen-Shots/ba-p/22581
- [REF-672] Frank Kim. "Top 25 Series - Rank 22 - Allocation of Resources Without Limits or Throttling", 2010. https://web.archive.org/web/20170113055136/https://software-security.sans.org/blog/2010/03/23/top-25-series-rank-22-allocation-of-resources-without-limits-or-throttling/
- [REF-62] Mark Dowd, John McDonald, Justin Schuh. "The Art of Software Security Assessment", 2006, Chapter 10, "Resource Limits", Page 574

### Content history (summary)

- Submitted: 2009-05-13 by MITRE
- Modified 34 times; latest: 2026-10-28
- Full history: https://cwe.mitre.org/data/definitions/770.html#Content_History

---

*Part 2 is taken from the MITRE CWE List, version 5.0 (2026-10-28), https://cwe.mitre.org. Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation. Used under the CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html). Part 1 was written for the Providus Bank Secure Coding programme by Training Heights.*
