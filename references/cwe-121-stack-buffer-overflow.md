# CWE-121: Stack-based Buffer Overflow

> **2025 CWE Top 25:** rank 14 · score 5.75 · CVEs in CISA KEV: 4 · change since 2024: new

## Part 1: Review guide

### What it is, in plain words

A stack-based buffer overflow: a local buffer on the stack is overrun, which can overwrite the return address.

### How to spot it

**Java**
- JNI C code with fixed local arrays

**C#**
- `stackalloc` buffers filled with input-length loops in `unsafe` code

**React / Node.js**
- WebAssembly modules with fixed local arrays

### Not this weakness (safe look-alikes)

- `Span<byte> buf = stackalloc byte[n]` used with bounds-checked `CopyTo`.

### How to tell it apart from related weaknesses

Use CWE-121 when the overflowed buffer is on the stack; CWE-122 on the heap; CWE-120 when the size isn't checked at all and location is unclear; CWE-787 as the general case.

### Vulnerable and secure examples

#### Java

*Context:* Plain Java checks every array access. The risk appears when Java reaches native memory: sun.misc.Unsafe, direct buffers or JNI calls into C.

Vulnerable:

```java
native void parseTrack2(byte[] track2);
...
parseTrack2(readFromCardReader());
// C: char pan[19];
//    memcpy(pan, bytes, len);
```

Why: The C function copies however many bytes Java sends onto its stack.

Secure:

```java
if (track2.length > 40)
  throw new IllegalArgumentException();
parseTrack2(track2);
// build the C library with
// -fstack-protector-strong -D_FORTIFY_SOURCE=2
```

Why it works: Track 2 is at most 40 characters: enforce it, and build native code with stack protection.

#### C#

*Context:* Safe C# checks every array access. The risk appears with unsafe code, raw pointers, stackalloc and P/Invoke calls into native libraries.

Vulnerable:

```csharp
unsafe {
  byte* pan = stackalloc byte[19];
  for (int i = 0; i < track2.Length; i++)
    pan[i] = track2[i];
}
```

Why: Longer input writes past pan on the stack.

Secure:

```csharp
if (track2.Length > 19)
  throw new FormatException();
Span<byte> pan = stackalloc byte[19];
track2.CopyTo(pan);
// never size stackalloc from input;
// use ArrayPool for large or variable sizes
```

Why it works: A bounds-checked Span, with a fixed small size.

#### React / Node.js

*Context:* JavaScript has no raw memory access. The risk is in WebAssembly modules, compiled from C or C++, that a React app loads for things like image or PDF processing.

Vulnerable:

```jsx
// C inside the module:
//   void parse(const char *in)
//   { char pan[19]; sprintf(pan, "%s", in); }
wasm.parse(allocString(track2));
```

Why: WebAssembly keeps return addresses out of reach, but the overflow still corrupts the module’s other data.

Secure:

```jsx
if (!/^\d{12,19}$/.test(pan))
  throw new Error("Bad card number");
wasm.parse(allocString(pan));
// and fix the C: char pan[20]; snprintf(...)
```

Why it works: Validate the format first, and fix the C buffer and copy.

### Fix guidance

**Primary defences**

1. **Check length before copying.** Small, fixed buffers with explicit limits.
2. **Safe stack use in C#.** Span over stackalloc; never size it from input.
3. **Build with protections.** Stack canaries, ASLR, non-executable stack.

**Defence in depth**

- Strict format checks (12 to 19 digits)
- Fuzz card and ISO 8583 parsers
- ArrayPool for variable sizes
- Review every unsafe block

**In each stack**

- Java: Validate before JNI calls
- C#: Span over small fixed stackalloc
- React / Node.js: Regex-check card data first

**Don't rely on**

- Compiler protection alone
- stackalloc sized from input
- Assuming card data is well-formed

### How to verify the fix

60 bytes of track data are rejected and the parser never runs.

### Severity guide (Providus)

Critical in native code reachable from input.

---

## Part 2: MITRE CWE entry (complete)

**Abstraction:** Variant · **Structure:** Simple · **Status:** Draft  
**MITRE page:** https://cwe.mitre.org/data/definitions/121.html
  
**MITRE diagram:** https://cwe.mitre.org/data/images/CWE-121-Diagram.png

### Description

The product writes past the end of a buffer that was allocated on the stack.

### Alternate terms

- **Stack Overflow**: "Stack Overflow" is often used to mean the same thing as stack-based buffer overflow, however it is also used on occasion to mean stack exhaustion, usually a result from an excessively recursive function call. Due to the ambiguity of the term, use of stack overflow to describe either circumstance is discouraged.
- **Stack Buffer Overflow**

### Background details

There are generally several security-critical data on an execution stack that can lead to arbitrary code execution. The most prominent is the stored return address, the memory address at which execution should continue once the current function is finished executing. The attacker can overwrite this value with some memory address to which the attacker also has write access, into which they place arbitrary code to be run with the full privileges of the vulnerable program. Alternately, the attacker can supply the address of an important call, for instance the POSIX system() call, leaving arguments to the call on the stack. This is often called a return into libc exploit, since the attacker generally forces the program to jump at return time into an interesting routine in the C standard library (libc). Other important data commonly on the stack include the stack pointer and frame pointer, two values that indicate offsets for computing memory addresses. Modifying those values can often be leveraged into a "write-what-where" condition.

### Common consequences

| Scope | Impact | Likelihood | Note |
|---|---|---|---|
| Availability | Modify Memory, DoS: Crash, Exit, or Restart, DoS: Resource Consumption (CPU), DoS: Resource Consumption (Memory) |  | Buffer overflows generally lead to crashes. Other attacks leading to lack of availability are possible, including putting the program into an infinite loop. |
| Integrity, Confidentiality, Availability, Access Control | Modify Memory, Execute Unauthorized Code or Commands, Bypass Protection Mechanism |  | Buffer overflows often can be used to execute arbitrary code, which is usually outside the scope of a program's implicit security policy. |
| Integrity, Confidentiality, Availability, Access Control, Other | Modify Memory, Execute Unauthorized Code or Commands, Bypass Protection Mechanism, Other |  | When the consequence is arbitrary code execution, this can often be used to subvert any other security service. |

### Likelihood of exploit

High

### Modes of introduction

- **Implementation**

### Applicable platforms

- Language: Class: Memory-Unsafe (Often)
- Language: C (Often)
- Language: C++ (Often)
- Technology: Class: Not Technology-Specific (Undetermined)

### Weakness ordinalities

- **Primary**

### Functional areas

- Memory Management

### Affected resources

- Memory

### Potential mitigations

**1. Phase: Operation, Build and Compilation** · Strategy: Environment Hardening · ID: MIT-10

Use automatic buffer overflow detection mechanisms that are offered by certain compilers or compiler extensions. Examples include: the Microsoft Visual Studio /GS flag, Fedora/Red Hat FORTIFY_SOURCE GCC flag, StackGuard, and ProPolice, which provide various mechanisms including canary-based detection and range/index checking.

D3-SFCV (Stack Frame Canary Validation) from D3FEND [REF-1334] discusses canary-based detection in detail.

*Effectiveness: Defense in Depth*. This is not necessarily a complete solution, since these mechanisms only detect certain types of overflows. In addition, the result is still a denial of service, since the typical response is to exit the application.

**2. Phase: Architecture and Design**

Use an abstraction library to abstract away risky APIs. Not a complete solution.

**3. Phase: Implementation**

Implement and perform bounds checking on input.

**4. Phase: Implementation**

Do not use dangerous functions such as gets. Use safer, equivalent functions which check for boundary errors.

**5. Phase: Operation, Build and Compilation** · Strategy: Environment Hardening · ID: MIT-11

Run or compile the software using features or extensions that randomly arrange the positions of a program's executable and libraries in memory. Because this makes the addresses unpredictable, it can prevent an attacker from reliably jumping to exploitable code.

Examples include Address Space Layout Randomization (ASLR) [REF-58] [REF-60] and Position-Independent Executables (PIE) [REF-64]. Imported modules may be similarly realigned if their default memory addresses conflict with other modules, in a process known as "rebasing" (for Windows) and "prelinking" (for Linux) [REF-1332] using randomly generated addresses. ASLR for libraries cannot be used in conjunction with prelink since it would require relocating the libraries at run-time, defeating the whole purpose of prelinking.

For more information on these techniques see D3-SAOR (Segment Address Offset Randomization) from D3FEND [REF-1335].

*Effectiveness: Defense in Depth*. These techniques do not provide a complete solution. For instance, exploits frequently use a bug that discloses memory addresses in order to maximize reliability of code execution [REF-1337]. It has also been shown that a side-channel attack can bypass ASLR [REF-1333].

### Detection methods

**Fuzzing** (effectiveness: High)

Fuzz testing (fuzzing) is a powerful technique for generating large numbers of diverse inputs - either randomly or algorithmically - and dynamically invoking the code with those inputs. Even with random inputs, it is often capable of generating unexpected results such as crashes, memory corruption, or resource consumption. Fuzzing effectively produces repeatable test cases that clearly indicate bugs, which helps developers to diagnose the issues.

**Automated Static Analysis** (effectiveness: High)

Automated static analysis, commonly referred to as Static Application Security Testing (SAST), can find some instances of this weakness by analyzing source code (or binary/compiled code) without having to execute it. Typically, this is done by building a model of data flow and control flow, then searching for potentially-vulnerable patterns that connect "sources" (origins of input) with "sinks" (destinations where the data interacts with external components, a lower layer such as the OS, etc.)

**Automated Dynamic Analysis** (effectiveness: Moderate)

Use tools that are integrated during compilation to insert runtime error-checking mechanisms related to memory safety errors, such as AddressSanitizer (ASan) for C/C++ [REF-1518].

*Crafted inputs are necessary to reach the code containing the error, such as generated by fuzzers. Also, these tools may reduce performance, and they only report the error condition - not the original mistake that led to the error.*

### Demonstrative examples

**Example 1**

While buffer overflow examples can be rather complex, it is possible to have very simple, yet still exploitable, stack-based buffer overflows:

*Bad code (C):*

```c
#define BUFSIZE 256
int main(int argc, char **argv) {
    char buf[BUFSIZE];
    strcpy(buf, argv[1]);
}
```

The buffer size is fixed, but there is no guarantee the string in argv[1] will not exceed this size and cause an overflow.

**Example 2**

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

This function allocates a buffer of 64 bytes to store the hostname, however there is no guarantee that the hostname will not be larger than 64 bytes. If an attacker specifies an address which resolves to a very large hostname, then the function may overwrite sensitive data or even relinquish control flow to the attacker.

Note that this example also contains an unchecked return value (CWE-252) that can lead to a NULL pointer dereference (CWE-476).

### Observed examples (real vulnerabilities)

| Reference | Description |
|---|---|
| [CVE-2021-35395](https://www.cve.org/CVERecord?id=CVE-2021-35395) | Stack-based buffer overflows in SFK for wifi chipset used for IoT/embedded devices, as exploited in the wild per CISA KEV. |

### Relationships

Includes relationships recorded on this entry and those recorded on other entries that point to it (as MITRE's page shows them).

| Nature | CWE | Name | View | Recorded on |
|---|---|---|---|---|
| ChildOf | CWE-787 | Out-of-bounds Write | 1000 Complete Weakness Hierarchy | this entry |
| ChildOf (primary) | CWE-788 | Access of Memory Location After End of Buffer | 1000 Complete Weakness Hierarchy | this entry |

### Taxonomy mappings

| Taxonomy | Entry ID | Entry name | Fit |
|---|---|---|---|
| CLASP |  | Stack overflow |  |
| Software Fault Patterns | SFP8 | Faulty Buffer Access |  |
| CERT C Secure Coding | ARR38-C | Guarantee that library functions do not form invalid pointers | Imprecise |
| CERT C Secure Coding | STR31-C | Guarantee that storage for strings has sufficient space for character data and the null terminator | CWE More Specific |

### Vulnerability mapping notes

**Usage:** Allowed

**Rationale:** This CWE entry is at the Variant level of abstraction, which is a preferred level of abstraction for mapping to the root causes of vulnerabilities.

**Comments:** Carefully read both the name and description to ensure that this mapping is an appropriate fit. Do not try to 'force' a mapping to a lower-level Base/Variant simply to comply with this preferred level of abstraction.

**Reasons:** Acceptable-Use

### Notes

**Terminology:** There is significant inconsistency regarding the "buffer overflow" term, which can have multiple interpretations and uses. Many people mean "writing past the end of a buffer." Others mean "writing past the end of a buffer, or before the beginning of a buffer." Still others might include "read" in the term.

**Relationship:** Stack-based buffer overflows can instantiate in return address overwrites, stack pointer overwrites or frame pointer overwrites. They can also be considered function pointer overwrites, array index overwrites or write-what-where condition, etc.

### Memberships

Categories and views this entry belongs to (for example OWASP Top Ten and earlier CWE Top 25 lists).

| Type | ID | Name |
|---|---|---|
| Category | 970 | SFP Secondary Cluster: Faulty Buffer Access |
| Category | 1160 | SEI CERT C Coding Standard - Guidelines 06. Arrays (ARR) |
| Category | 1161 | SEI CERT C Coding Standard - Guidelines 07. Characters and Strings (STR) |
| Category | 1365 | ICS Communications: Unreliability |
| Category | 1366 | ICS Communications: Frail Security in Protocols |
| Category | 1399 | Comprehensive Categorization: Memory Safety |
| View | 1435 | Weaknesses in the 2025 CWE Top 25 Most Dangerous Software Weaknesses |

### References

- [REF-1029] Aleph One. "Smashing The Stack For Fun And Profit", 1996. https://phrack.org/issues/49/14.html
- [REF-7] Michael Howard, David LeBlanc. "Writing Secure Code", 2002, Chapter 5, "Stack Overruns" Page 129. https://www.microsoftpressstore.com/store/writing-secure-code-9780735617223
- [REF-44] Michael Howard, David LeBlanc, John Viega. "24 Deadly Sins of Software Security", 2010, "Sin 5: Buffer Overruns." Page 89
- [REF-62] Mark Dowd, John McDonald, Justin Schuh. "The Art of Software Security Assessment", 2006, Chapter 3, "Nonexecutable Stack", Page 76
- [REF-62] Mark Dowd, John McDonald, Justin Schuh. "The Art of Software Security Assessment", 2006, Chapter 5, "Protection Mechanisms", Page 189
- [REF-18] Secure Software, Inc.. "The CLASP Application Security Process", 2005. https://cwe.mitre.org/documents/sources/TheCLASPApplicationSecurityProcess.pdf
- [REF-58] Michael Howard. "Address Space Layout Randomization in Windows Vista". https://learn.microsoft.com/en-us/archive/blogs/michael_howard/address-space-layout-randomization-in-windows-vista
- [REF-60] "PaX". https://en.wikipedia.org/wiki/Executable_space_protection#PaX
- [REF-64] Grant Murphy. "Position Independent Executables (PIE)", 2012. https://www.redhat.com/en/blog/position-independent-executables-pie
- [REF-1332] John Richard Moser. "Prelink and address space randomization", 2006. https://lwn.net/Articles/190139/
- [REF-1333] Dmitry Evtyushkin, Dmitry Ponomarev, Nael Abu-Ghazaleh. "Jump Over ASLR: Attacking Branch Predictors to Bypass ASLR", 2016. http://www.cs.ucr.edu/~nael/pubs/micro16.pdf
- [REF-1334] D3FEND. "Stack Frame Canary Validation (D3-SFCV)", 2023. https://d3fend.mitre.org/technique/d3f:StackFrameCanaryValidation/
- [REF-1335] D3FEND. "Segment Address Offset Randomization (D3-SAOR)", 2023. https://d3fend.mitre.org/technique/d3f:SegmentAddressOffsetRandomization/
- [REF-1337] Alexander Sotirov and Mark Dowd. "Bypassing Browser Memory Protections: Setting back browser security by 10 years", 2008, Memory information leaks. https://www.blackhat.com/presentations/bh-usa-08/Sotirov_Dowd/bh08-sotirov-dowd.pdf
- [REF-1477] Cybersecurity and Infrastructure Security Agency. "Secure by Design Alert: Eliminating Buffer Overflow Vulnerabilities", 2025. https://www.cisa.gov/resources-tools/resources/secure-design-alert-eliminating-buffer-overflow-vulnerabilities
- [REF-1518] "AddressSanitizer". https://clang.llvm.org/docs/AddressSanitizer.html

### Content history (summary)

- Submitted: 2006-07-19 by CLASP
- Modified 28 times; latest: 2026-10-28
- Full history: https://cwe.mitre.org/data/definitions/121.html#Content_History

---

*Part 2 is taken from the MITRE CWE List, version 5.0 (2026-10-28), https://cwe.mitre.org. Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation. Used under the CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html). Part 1 was written for the Providus Bank Secure Coding programme by Training Heights.*
