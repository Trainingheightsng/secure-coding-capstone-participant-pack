# CWE-122: Heap-based Buffer Overflow

> **2025 CWE Top 25:** rank 16 · score 5.21 · CVEs in CISA KEV: 6 · change since 2024: new

## Part 1: Review guide

### What it is, in plain words

A heap-based buffer overflow: memory allocated on the heap is overrun, often because size arithmetic overflowed before allocating.

### How to spot it

**Java**
- JNI/Unsafe allocations sized by `count * size` from input

**C#**
- `Marshal.AllocHGlobal(n * size)` with unchecked multiplication
- Pointer writes into native heap buffers

**React / Node.js**
- WebAssembly `malloc` sizes computed from input

### Not this weakness (safe look-alikes)

- Managed arrays sized from input with a maximum check (they cannot overflow, though see CWE-770 for size).

### How to tell it apart from related weaknesses

Heap location means CWE-122; stack CWE-121; unchecked copy CWE-120; general out-of-bounds write CWE-787.

### Vulnerable and secure examples

#### Java

*Context:* Plain Java checks every array access. The risk appears when Java reaches native memory: sun.misc.Unsafe, direct buffers or JNI calls into C.

Vulnerable:

```java
short total = (short) (hdrLen + bodyLen);
ByteBuffer buf =
  ByteBuffer.allocateDirect(total & 0xFFFF);
nativeDecode(buf, body);  // C writes bodyLen
```

Why: Java’s own put() would throw, but the native decoder trusts the sizes.

Secure:

```java
int total = Math.addExact(hdrLen, bodyLen);
if (total > MAX_TOTAL) throw new IOException();
ByteBuffer buf = ByteBuffer.allocateDirect(total);
nativeDecode(buf, body);
// and the C side checks buf's capacity
```

Why it works: addExact throws instead of wrapping, and the total is capped.

#### C#

*Context:* Safe C# checks every array access. The risk appears with unsafe code, raw pointers, stackalloc and P/Invoke calls into native libraries.

Vulnerable:

```csharp
ushort total = (ushort)(hdrLen + bodyLen);
IntPtr p = Marshal.AllocHGlobal(total);
Marshal.Copy(body, 0, p + hdrLen, body.Length);
```

Why: The size wraps, and Marshal.Copy doesn’t check the destination.

Secure:

```csharp
int total = checked(hdrLen + bodyLen);
if (total > MaxTotal)
  throw new InvalidDataException();
byte[] buf = new byte[total];  // managed memory
body.CopyTo(buf, hdrLen);
```

Why it works: checked arithmetic throws on overflow, and managed arrays are bounds-checked.

#### React / Node.js

*Context:* JavaScript has no raw memory access. The risk is in WebAssembly modules, compiled from C or C++, that a React app loads for things like image or PDF processing.

Vulnerable:

```jsx
const size = new Uint16Array(1);
size[0] = hdrLen + bodyLen;    // wraps at 65,536
const ptr = wasm.alloc(size[0]);
const mem = new Uint8Array(wasm.memory.buffer);
mem.set(body, ptr + hdrLen);   // past the block
```

Why: 60,000 + 10,000 is stored as 4,464, so the copy runs far past the block.

Secure:

```jsx
if (hdrLen > MAX_HDR || bodyLen > MAX_BODY)
  throw new Error("Too large");
const total = hdrLen + bodyLen;
const ptr = wasm.alloc(total);
new Uint8Array(wasm.memory.buffer, ptr, total)
  .set(body, hdrLen);  // throws if it won't fit
```

Why it works: Check the sizes, and write through a view limited to the block.

### Fix guidance

**Primary defences**

1. **Check size arithmetic.** checked in C#, Math.addExact in Java.
2. **Cap sizes from input.** Maximum header, body and file sizes.
3. **Patch parsing libraries fast.** SBOM and SCA for image, PDF and zip libraries.

**Defence in depth**

- Fuzz file parsers
- Process uploads in isolated workers
- Prefer managed memory
- Monitor for parser crashes

**In each stack**

- Java: Math.addExact; cap sizes
- C#: checked; byte[] over AllocHGlobal
- React / Node.js: Check sizes before wasm.alloc

**Don't rely on**

- Sizes read from the file
- 16-bit size fields
- Old bundled decoders

### How to verify the fix

A file with oversized lengths is rejected before any allocation.

### Severity guide (Providus)

Critical in native code reachable from input.

---

## Part 2: MITRE CWE entry (complete)

**Abstraction:** Variant · **Structure:** Simple · **Status:** Draft  
**MITRE page:** https://cwe.mitre.org/data/definitions/122.html
  
**MITRE diagram:** https://cwe.mitre.org/data/images/CWE-122-Diagram.png

### Description

The product writes past the end of a buffer that was allocated on the heap.

### Alternate terms

- **Heap Overflow**
- **Heap Buffer Overflow**

### Common consequences

| Scope | Impact | Likelihood | Note |
|---|---|---|---|
| Availability | DoS: Crash, Exit, or Restart, DoS: Resource Consumption (CPU), DoS: Resource Consumption (Memory) |  | Buffer overflows generally lead to crashes. Other attacks leading to lack of availability are possible, including putting the program into an infinite loop. |
| Integrity, Confidentiality, Availability, Access Control | Execute Unauthorized Code or Commands, Bypass Protection Mechanism, Modify Memory |  | Buffer overflows often can be used to execute arbitrary code, which is usually outside the scope of a program's implicit security policy. Besides important user data, heap-based overflows can be used to overwrite function pointers that may be living in memory, pointing it to the attacker's code. Even in applications that do not explicitly use function pointers, the run-time will usually leave many in memory. For example, object methods in C++ are generally implemented using function pointers. Even in C programs, there is often a global offset table used by the underlying runtime. |
| Integrity, Confidentiality, Availability, Access Control, Other | Execute Unauthorized Code or Commands, Bypass Protection Mechanism, Other |  | When the consequence is arbitrary code execution, this can often be used to subvert any other security service. |

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

**1. Phase: **

Pre-design: Use a language or compiler that performs automatic bounds checking.

**2. Phase: Architecture and Design**

Use an abstraction library to abstract away risky APIs. Not a complete solution.

**3. Phase: Operation, Build and Compilation** · Strategy: Environment Hardening · ID: MIT-10

Use automatic buffer overflow detection mechanisms that are offered by certain compilers or compiler extensions. Examples include: the Microsoft Visual Studio /GS flag, Fedora/Red Hat FORTIFY_SOURCE GCC flag, StackGuard, and ProPolice, which provide various mechanisms including canary-based detection and range/index checking.

D3-SFCV (Stack Frame Canary Validation) from D3FEND [REF-1334] discusses canary-based detection in detail.

*Effectiveness: Defense in Depth*. This is not necessarily a complete solution, since these mechanisms only detect certain types of overflows. In addition, the result is still a denial of service, since the typical response is to exit the application.

**4. Phase: Operation, Build and Compilation** · Strategy: Environment Hardening · ID: MIT-11

Run or compile the software using features or extensions that randomly arrange the positions of a program's executable and libraries in memory. Because this makes the addresses unpredictable, it can prevent an attacker from reliably jumping to exploitable code.

Examples include Address Space Layout Randomization (ASLR) [REF-58] [REF-60] and Position-Independent Executables (PIE) [REF-64]. Imported modules may be similarly realigned if their default memory addresses conflict with other modules, in a process known as "rebasing" (for Windows) and "prelinking" (for Linux) [REF-1332] using randomly generated addresses. ASLR for libraries cannot be used in conjunction with prelink since it would require relocating the libraries at run-time, defeating the whole purpose of prelinking.

For more information on these techniques see D3-SAOR (Segment Address Offset Randomization) from D3FEND [REF-1335].

*Effectiveness: Defense in Depth*. These techniques do not provide a complete solution. For instance, exploits frequently use a bug that discloses memory addresses in order to maximize reliability of code execution [REF-1337]. It has also been shown that a side-channel attack can bypass ASLR [REF-1333].

**5. Phase: Implementation**

Implement and perform bounds checking on input.

**6. Phase: Implementation** · Strategy: Libraries or Frameworks

Do not use dangerous functions such as gets. Look for their safe equivalent, which checks for the boundary.

**7. Phase: Operation**

Use OS-level preventative functionality. This is not a complete solution, but it provides some defense in depth.

### Detection methods

**Fuzzing** (effectiveness: High)

Fuzz testing (fuzzing) is a powerful technique for generating large numbers of diverse inputs - either randomly or algorithmically - and dynamically invoking the code with those inputs. Even with random inputs, it is often capable of generating unexpected results such as crashes, memory corruption, or resource consumption. Fuzzing effectively produces repeatable test cases that clearly indicate bugs, which helps developers to diagnose the issues.

**Automated Dynamic Analysis** (effectiveness: Moderate)

Use tools that are integrated during compilation to insert runtime error-checking mechanisms related to memory safety errors, such as AddressSanitizer (ASan) for C/C++ [REF-1518].

*Crafted inputs are necessary to reach the code containing the error, such as generated by fuzzers. Also, these tools may reduce performance, and they only report the error condition - not the original mistake that led to the error.*

### Demonstrative examples

**Example 1**

While buffer overflow examples can be rather complex, it is possible to have very simple, yet still exploitable, heap-based buffer overflows:

*Bad code (C):*

```c
#define BUFSIZE 256
int main(int argc, char **argv) {
    char *buf;
    buf = (char *)malloc(sizeof(char)*BUFSIZE);
    strcpy(buf, argv[1]);
}
```

The buffer is allocated heap memory with a fixed size, but there is no guarantee the string in argv[1] will not exceed this size and cause an overflow.

**Example 2**

This example applies an encoding procedure to an input string and stores it into a buffer.

*Bad code (C):*

```c
char * copy_input(char *user_supplied_string){
    int i, dst_index;
    char *dst_buf = (char*)malloc(4*sizeof(char) * MAX_SIZE);
    if ( MAX_SIZE <= strlen(user_supplied_string) ){
        die("user string too long, die evil hacker!");
    }
    dst_index = 0;
    for ( i = 0; i < strlen(user_supplied_string); i++ ){
        if( '&' == user_supplied_string[i] ){
            dst_buf[dst_index++] = '&';
            dst_buf[dst_index++] = 'a';
            dst_buf[dst_index++] = 'm';
            dst_buf[dst_index++] = 'p';
            dst_buf[dst_index++] = ';';
        }
        else if ('<' == user_supplied_string[i] ){
            /* encode to &lt; */
        }
        else dst_buf[dst_index++] = user_supplied_string[i];
    }
    return dst_buf;
}
```

The programmer attempts to encode the ampersand character in the user-controlled string, however the length of the string is validated before the encoding procedure is applied. Furthermore, the programmer assumes encoding expansion will only expand a given character by a factor of 4, while the encoding of the ampersand expands by 5. As a result, when the encoding procedure expands the string it is possible to overflow the destination buffer if the attacker provides a string of many ampersands.

### Observed examples (real vulnerabilities)

| Reference | Description |
|---|---|
| [CVE-2025-46687](https://www.cve.org/CVERecord?id=CVE-2025-46687) | Chain: Javascript engine code does not perform a length check (CWE-1284) leading to integer overflow (CWE-190) causing allocation of smaller buffer than expected (CWE-131) resulting in a heap-based buffer overflow (CWE-122) |
| [CVE-2021-43537](https://www.cve.org/CVERecord?id=CVE-2021-43537) | Chain: in a web browser, an unsigned 64-bit integer is forcibly cast to a 32-bit integer (CWE-681) and potentially leading to an integer overflow (CWE-190). If an integer overflow occurs, this can cause heap memory corruption (CWE-122) |
| [CVE-2007-4268](https://www.cve.org/CVERecord?id=CVE-2007-4268) | Chain: integer signedness error (CWE-195) passes signed comparison, leading to heap overflow (CWE-122) |
| [CVE-2009-2523](https://www.cve.org/CVERecord?id=CVE-2009-2523) | Chain: product does not handle when an input string is not NULL terminated (CWE-170), leading to buffer over-read (CWE-125) or heap-based buffer overflow (CWE-122). |
| [CVE-2021-29529](https://www.cve.org/CVERecord?id=CVE-2021-29529) | Chain: machine-learning product can have a heap-based buffer overflow (CWE-122) when some integer-oriented bounds are calculated by using ceiling() and floor() on floating point values (CWE-1339) |
| [CVE-2010-1866](https://www.cve.org/CVERecord?id=CVE-2010-1866) | Chain: integer overflow (CWE-190) causes a negative signed value, which later bypasses a maximum-only check (CWE-839), leading to heap-based buffer overflow (CWE-122). |

### Relationships

Includes relationships recorded on this entry and those recorded on other entries that point to it (as MITRE's page shows them).

| Nature | CWE | Name | View | Recorded on |
|---|---|---|---|---|
| ChildOf | CWE-787 | Out-of-bounds Write | 1000 Complete Weakness Hierarchy | this entry |
| ChildOf (primary) | CWE-788 | Access of Memory Location After End of Buffer | 1000 Complete Weakness Hierarchy | this entry |

### Related attack patterns (CAPEC)

[CAPEC-92](https://capec.mitre.org/data/definitions/92.html)

### Taxonomy mappings

| Taxonomy | Entry ID | Entry name | Fit |
|---|---|---|---|
| CLASP |  | Heap overflow |  |
| Software Fault Patterns | SFP8 | Faulty Buffer Access |  |
| CERT C Secure Coding | STR31-C | Guarantee that storage for strings has sufficient space for character data and the null terminator | CWE More Specific |
| ISA/IEC 62443 | Part 4-2 | Req CR 3.5 |  |
| ISA/IEC 62443 | Part 3-3 | Req SR 3.5 |  |
| ISA/IEC 62443 | Part 4-1 | Req SI-1 |  |
| ISA/IEC 62443 | Part 4-1 | Req SI-2 |  |
| ISA/IEC 62443 | Part 4-1 | Req SVV-1 |  |
| ISA/IEC 62443 | Part 4-1 | Req SVV-3 |  |

### Vulnerability mapping notes

**Usage:** Allowed

**Rationale:** This CWE entry is at the Variant level of abstraction, which is a preferred level of abstraction for mapping to the root causes of vulnerabilities.

**Comments:** Carefully read both the name and description to ensure that this mapping is an appropriate fit. Do not try to 'force' a mapping to a lower-level Base/Variant simply to comply with this preferred level of abstraction.

**Reasons:** Acceptable-Use

### Notes

**Terminology:** There is significant inconsistency regarding the "buffer overflow" term, which can have multiple interpretations and uses. Many people mean "writing past the end of a buffer." Others mean "writing past the end of a buffer, or before the beginning of a buffer." Still others might include "read" in the term.

### Memberships

Categories and views this entry belongs to (for example OWASP Top Ten and earlier CWE Top 25 lists).

| Type | ID | Name |
|---|---|---|
| Category | 970 | SFP Secondary Cluster: Faulty Buffer Access |
| Category | 1161 | SEI CERT C Coding Standard - Guidelines 07. Characters and Strings (STR) |
| Category | 1399 | Comprehensive Categorization: Memory Safety |
| View | 1435 | Weaknesses in the 2025 CWE Top 25 Most Dangerous Software Weaknesses |

### References

- [REF-7] Michael Howard, David LeBlanc. "Writing Secure Code", 2002, Chapter 5, "Heap Overruns" Page 138. https://www.microsoftpressstore.com/store/writing-secure-code-9780735617223
- [REF-44] Michael Howard, David LeBlanc, John Viega. "24 Deadly Sins of Software Security", 2010, "Sin 5: Buffer Overruns." Page 89
- [REF-62] Mark Dowd, John McDonald, Justin Schuh. "The Art of Software Security Assessment", 2006, Chapter 3, "Nonexecutable Stack", Page 76
- [REF-62] Mark Dowd, John McDonald, Justin Schuh. "The Art of Software Security Assessment", 2006, Chapter 5, "Protection Mechanisms", Page 189
- [REF-58] Michael Howard. "Address Space Layout Randomization in Windows Vista". https://learn.microsoft.com/en-us/archive/blogs/michael_howard/address-space-layout-randomization-in-windows-vista
- [REF-60] "PaX". https://en.wikipedia.org/wiki/Executable_space_protection#PaX
- [REF-64] Grant Murphy. "Position Independent Executables (PIE)", 2012. https://www.redhat.com/en/blog/position-independent-executables-pie
- [REF-18] Secure Software, Inc.. "The CLASP Application Security Process", 2005. https://cwe.mitre.org/documents/sources/TheCLASPApplicationSecurityProcess.pdf
- [REF-1337] Alexander Sotirov and Mark Dowd. "Bypassing Browser Memory Protections: Setting back browser security by 10 years", 2008, Memory information leaks. https://www.blackhat.com/presentations/bh-usa-08/Sotirov_Dowd/bh08-sotirov-dowd.pdf
- [REF-1332] John Richard Moser. "Prelink and address space randomization", 2006. https://lwn.net/Articles/190139/
- [REF-1333] Dmitry Evtyushkin, Dmitry Ponomarev, Nael Abu-Ghazaleh. "Jump Over ASLR: Attacking Branch Predictors to Bypass ASLR", 2016. http://www.cs.ucr.edu/~nael/pubs/micro16.pdf
- [REF-1334] D3FEND. "Stack Frame Canary Validation (D3-SFCV)", 2023. https://d3fend.mitre.org/technique/d3f:StackFrameCanaryValidation/
- [REF-1335] D3FEND. "Segment Address Offset Randomization (D3-SAOR)", 2023. https://d3fend.mitre.org/technique/d3f:SegmentAddressOffsetRandomization/
- [REF-1477] Cybersecurity and Infrastructure Security Agency. "Secure by Design Alert: Eliminating Buffer Overflow Vulnerabilities", 2025. https://www.cisa.gov/resources-tools/resources/secure-design-alert-eliminating-buffer-overflow-vulnerabilities
- [REF-1518] "AddressSanitizer". https://clang.llvm.org/docs/AddressSanitizer.html

### Content history (summary)

- Submitted: 2006-07-19 by CLASP
- Modified 28 times; latest: 2026-10-28
- Full history: https://cwe.mitre.org/data/definitions/122.html#Content_History

---

*Part 2 is taken from the MITRE CWE List, version 5.0 (2026-10-28), https://cwe.mitre.org. Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation. Used under the CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html). Part 1 was written for the Providus Bank Secure Coding programme by Training Heights.*
