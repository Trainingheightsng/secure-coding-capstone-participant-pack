# CWE-416: Use After Free

> **2025 CWE Top 25:** rank 7 · score 8.47 · CVEs in CISA KEV: 14 · change since 2024: +1

## Part 1: Review guide

### What it is, in plain words

The program keeps using memory (or a native resource) after it has been freed, when it may already hold something else.

### How to spot it

**Java**
- JNI code holding native pointers after release
- Direct `ByteBuffer`s or off-heap memory freed manually then reused

**C#**
- Using objects after `Dispose()` in `unsafe`/P/Invoke code
- `IntPtr` handles freed (`Marshal.FreeHGlobal`) then used
- Returning buffers to `ArrayPool` and keeping a reference

**React / Node.js**
- WebAssembly modules calling `free` then reading the pointer
- Native Node add-ons
- (Managed look-alike) using a transferred/detached `ArrayBuffer`

### Not this weakness (safe look-alikes)

- Normal garbage-collected objects in Java, C# and JavaScript cannot be used after free.
- `SafeHandle` and `using` blocks with no reuse afterwards.

### How to tell it apart from related weaknesses

Use after free is about the lifetime of memory; for reading or writing outside a buffer's bounds see CWE-125/787. Null references are CWE-476.

### Vulnerable and secure examples

#### Java

*Context:* Plain Java checks every array access. The risk appears when Java reaches native memory: sun.misc.Unsafe, direct buffers or JNI calls into C.

Vulnerable:

```java
long h = Hsm.openSession(slot);  // native pointer
Hsm.closeSession(h);
...
Hsm.sign(h, payload);  // freed in native code
```

Why: The long still holds the old address after the native side has freed it.

Secure:

```java
try (HsmSession s = HsmSession.open(slot)) {
  s.sign(payload);
}
// HsmSession tracks its state, closes once,
// and throws if used after close()
```

Why it works: Wrap native handles in an AutoCloseable class with a single owner.

#### C#

*Context:* Safe C# checks every array access. The risk appears with unsafe code, raw pointers, stackalloc and P/Invoke calls into native libraries.

Vulnerable:

```csharp
IntPtr h = Hsm.Open(slot);
Hsm.Close(h);
...
Hsm.Sign(h, payload);  // h may now be reused
```

Why: A raw IntPtr can point at a different resource after Close.

Secure:

```csharp
using HsmHandle h = Hsm.Open(slot);
Hsm.Sign(h, payload);
// HsmHandle derives from SafeHandle:
// released once,
// ObjectDisposedException if used after
```

Why it works: SafeHandle releases the native resource once and refuses later use.

#### React / Node.js

*Context:* JavaScript has no raw memory access. The risk is in WebAssembly modules, compiled from C or C++, that a React app loads for things like image or PDF processing.

Vulnerable:

```jsx
const ptr = wasm.decodeImage(file);
const pixels = new Uint8Array(
  wasm.memory.buffer, ptr, size);
wasm.free(ptr);
drawToCanvas(pixels);  // memory was freed
```

Why: After free, the module can reuse that memory, so the canvas shows whatever is there now.

Secure:

```jsx
const ptr = wasm.decodeImage(file);
const pixels = new Uint8Array(
  wasm.memory.buffer, ptr, size).slice();
wasm.free(ptr);       // slice() made a copy
drawToCanvas(pixels);
```

Why it works: Copy out what you need before freeing, or use generated bindings that manage lifetimes.

### Fix guidance

**Primary defences**

1. **One owner per native resource.** SafeHandle in C#, AutoCloseable wrappers in Java.
2. **Close once, then make it unusable.** Track state so use after close throws.
3. **Test native code with sanitizers.** AddressSanitizer and fuzzing find these in C/C++.

**Defence in depth**

- using / try-with-resources everywhere
- No raw handle values in business code
- Patch browsers and OS on staff machines
- Review error paths carefully

**In each stack**

- Java: try-with-resources wrappers
- C#: SafeHandle + using
- React / Node.js: slice() before wasm free()

**Don't rely on**

- Remembering to close in every path
- Raw IntPtr or long handles
- Assuming GC covers native memory

### How to verify the fix

Using a closed handle throws; nothing reaches the native library.

### Severity guide (Providus)

Critical in native code reachable from input; in managed code, usually a reliability bug unless it involves pooled buffers holding another user's data.

---

## Part 2: MITRE CWE entry (complete)

**Abstraction:** Variant · **Structure:** Simple · **Status:** Stable  
**MITRE page:** https://cwe.mitre.org/data/definitions/416.html
  
**MITRE diagram:** https://cwe.mitre.org/data/images/CWE-416-Diagram.png

### Description

The product reuses or references memory after it has been freed. At some point afterward, the memory may be allocated again and saved in another pointer, while the original pointer references a location somewhere within the new allocation. Any operations using the original pointer are no longer valid because the memory "belongs" to the code that operates on the new pointer.

### Alternate terms

- **Dangling pointer**: a pointer that no longer points to valid memory, often after it has been freed
- **UAF**: commonly used acronym for Use After Free
- **Use-After-Free**

### Common consequences

| Scope | Impact | Likelihood | Note |
|---|---|---|---|
| Integrity | Modify Memory |  | The use of previously freed memory may corrupt valid data, if the memory area in question has been allocated and used properly elsewhere. |
| Availability | DoS: Crash, Exit, or Restart |  | If chunk consolidation occurs after the use of previously freed data, the process may crash when invalid data is used as chunk information. |
| Confidentiality | Read Memory |  | Read operations on freed memory can sometimes leak sensitive information instead of causing a crash |
| Integrity, Confidentiality, Availability | Execute Unauthorized Code or Commands |  | If malicious data is entered before chunk consolidation can take place, it may be possible to take advantage of a write-what-where primitive to execute arbitrary code. If the newly allocated data happens to hold a class, in C++ for example, various function pointers may be scattered within the heap data. If one of these function pointers is overwritten with an address to valid shellcode, execution of arbitrary code can be achieved. |

### Likelihood of exploit

High

### Modes of introduction

- **Implementation**

### Applicable platforms

- Language: Class: Memory-Unsafe (Often)
- Language: C (Often)
- Language: C++ (Often)

### Weakness ordinalities

- **Resultant**: If the product accesses a previously-freed pointer, then it means that a separate weakness or error already occurred previously, such as a race condition, an unexpected or poorly handled error condition, confusion over which part of the program is responsible for freeing the memory, performing the free too soon, etc.

### Functional areas

- Memory Management

### Affected resources

- Memory

### Potential mitigations

**1. Phase: Architecture and Design** · Strategy: Language Selection

Choose a language that provides automatic memory management.

**2. Phase: Implementation** · Strategy: Attack Surface Reduction

When freeing pointers, be sure to set them to NULL once they are freed. However, the utilization of multiple or complex data structures may lower the usefulness of this strategy.

*Effectiveness: Defense in Depth*. If a bug causes an attempted access of this pointer, then a NULL dereference could still lead to a crash or other unexpected behavior, but it will reduce or eliminate the risk of code execution.

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

The following example demonstrates the weakness.

*Bad code (C):*

```c
#include <stdio.h>
#include <unistd.h>
#define BUFSIZER1 512
#define BUFSIZER2 ((BUFSIZER1/2) - 8)
int main(int argc, char **argv) {
    char *buf1R1;
    char *buf2R1;
    char *buf2R2;
    char *buf3R2;
    buf1R1 = (char *) malloc(BUFSIZER1);
    buf2R1 = (char *) malloc(BUFSIZER1);
    free(buf2R1);
    buf2R2 = (char *) malloc(BUFSIZER2);
    buf3R2 = (char *) malloc(BUFSIZER2);
    strncpy(buf2R1, argv[1], BUFSIZER1-1);
    free(buf1R1);
    free(buf2R2);
    free(buf3R2);
}
```

**Example 2**

The following code illustrates a use after free error:

*Bad code (C):*

```c
char* ptr = (char*)malloc (SIZE);
if (err) {
    abrt = 1;
    free(ptr);
}
...
if (abrt) {
    logError("operation aborted before commit", ptr);
}
```

When an error occurs, the pointer is immediately freed. However, this pointer is later incorrectly used in the logError function.

### Observed examples (real vulnerabilities)

| Reference | Description |
|---|---|
| [CVE-2023-38160](https://www.cve.org/CVERecord?id=CVE-2023-38160) | TCP/IP code for an OS has a use-after-free that can leak heap memory contents |
| [CVE-2023-5447](https://www.cve.org/CVERecord?id=CVE-2023-5447) | Chain: missing lock check (CWE-414) leads to Use-After-Free (CWE-416) |
| [CVE-2022-20141](https://www.cve.org/CVERecord?id=CVE-2022-20141) | Chain: an operating system kernel has insufficient resource locking (CWE-413) leading to a use after free (CWE-416). |
| [CVE-2022-2621](https://www.cve.org/CVERecord?id=CVE-2022-2621) | Chain: two threads in a web browser use the same resource (CWE-366), but one of those threads can destroy the resource before the other has completed (CWE-416). |
| [CVE-2021-0920](https://www.cve.org/CVERecord?id=CVE-2021-0920) | Chain: mobile platform race condition (CWE-362) leading to use-after-free (CWE-416), as exploited in the wild per CISA KEV. |
| [CVE-2020-6819](https://www.cve.org/CVERecord?id=CVE-2020-6819) | Chain: race condition (CWE-362) leads to use-after-free (CWE-416), as exploited in the wild per CISA KEV. |
| [CVE-2010-4168](https://www.cve.org/CVERecord?id=CVE-2010-4168) | Use-after-free triggered by closing a connection while data is still being transmitted. |
| [CVE-2010-2941](https://www.cve.org/CVERecord?id=CVE-2010-2941) | Improper allocation for invalid data leads to use-after-free. |
| [CVE-2010-2547](https://www.cve.org/CVERecord?id=CVE-2010-2547) | certificate with a large number of Subject Alternate Names not properly handled in realloc, leading to use-after-free |
| [CVE-2010-1772](https://www.cve.org/CVERecord?id=CVE-2010-1772) | Timers are not disabled when a related object is deleted |
| [CVE-2010-1437](https://www.cve.org/CVERecord?id=CVE-2010-1437) | Access to a "dead" object that is being cleaned up |
| [CVE-2010-1208](https://www.cve.org/CVERecord?id=CVE-2010-1208) | object is deleted even with a non-zero reference count, and later accessed |
| [CVE-2010-0629](https://www.cve.org/CVERecord?id=CVE-2010-0629) | use-after-free involving request containing an invalid version number |
| [CVE-2010-0378](https://www.cve.org/CVERecord?id=CVE-2010-0378) | unload of an object that is currently being accessed by other functionality |
| [CVE-2010-0302](https://www.cve.org/CVERecord?id=CVE-2010-0302) | incorrectly tracking a reference count leads to use-after-free |
| [CVE-2010-0249](https://www.cve.org/CVERecord?id=CVE-2010-0249) | use-after-free related to use of uninitialized memory |
| [CVE-2010-0050](https://www.cve.org/CVERecord?id=CVE-2010-0050) | HTML document with incorrectly-nested tags |
| [CVE-2009-3658](https://www.cve.org/CVERecord?id=CVE-2009-3658) | Use after free in ActiveX object by providing a malformed argument to a method |
| [CVE-2009-3616](https://www.cve.org/CVERecord?id=CVE-2009-3616) | use-after-free by disconnecting during data transfer, or a message containing incorrect data types |
| [CVE-2009-3553](https://www.cve.org/CVERecord?id=CVE-2009-3553) | disconnect during a large data transfer causes incorrect reference count, leading to use-after-free |
| [CVE-2009-2416](https://www.cve.org/CVERecord?id=CVE-2009-2416) | use-after-free found by fuzzing |
| [CVE-2009-1837](https://www.cve.org/CVERecord?id=CVE-2009-1837) | Chain: race condition (CWE-362) from improper handling of a page transition in web client while an applet is loading (CWE-368) leads to use after free (CWE-416) |
| [CVE-2009-0749](https://www.cve.org/CVERecord?id=CVE-2009-0749) | realloc generates new buffer and pointer, but previous pointer is still retained, leading to use after free |
| [CVE-2010-3328](https://www.cve.org/CVERecord?id=CVE-2010-3328) | Use-after-free in web browser, probably resultant from not initializing memory. |
| [CVE-2008-5038](https://www.cve.org/CVERecord?id=CVE-2008-5038) | use-after-free when one thread accessed memory that was freed by another thread |
| [CVE-2008-0077](https://www.cve.org/CVERecord?id=CVE-2008-0077) | assignment of malformed values to certain properties triggers use after free |
| [CVE-2006-4434](https://www.cve.org/CVERecord?id=CVE-2006-4434) | mail server does not properly handle a long header. |
| [CVE-2010-2753](https://www.cve.org/CVERecord?id=CVE-2010-2753) | Chain: integer overflow leads to use-after-free |
| [CVE-2006-4997](https://www.cve.org/CVERecord?id=CVE-2006-4997) | freed pointer dereference |
| [CVE-2003-0813](https://www.cve.org/CVERecord?id=CVE-2003-0813) | Chain: A multi-threaded race condition (CWE-367) allows attackers to cause two threads to process the same RPC request, which causes a use-after-free (CWE-416) in one thread |

### Relationships

Includes relationships recorded on this entry and those recorded on other entries that point to it (as MITRE's page shows them).

| Nature | CWE | Name | View | Recorded on |
|---|---|---|---|---|
| ChildOf (primary) | CWE-825 | Expired Pointer Dereference | 1000 Complete Weakness Hierarchy | this entry |
| ChildOf (primary) | CWE-672 | Operation on a Resource after Expiration or Release | 1003 Weaknesses for Simplified Mapping of Published Vulnerabilities | this entry |
| ChildOf (primary) | CWE-672 | Operation on a Resource after Expiration or Release | 1305 CISQ Quality Measures (2020) | this entry |
| ChildOf (primary) | CWE-672 | Operation on a Resource after Expiration or Release | 1340 CISQ Data Protection Measures | this entry |
| PeerOf | CWE-415 | Double Free | 1000 Complete Weakness Hierarchy | CWE-415 |
| CanPrecede | CWE-120 | Buffer Copy without Checking Size of Input | 1000 Complete Weakness Hierarchy | this entry |
| CanPrecede | CWE-123 | Write-what-where Condition | 1000 Complete Weakness Hierarchy | this entry |
| CanFollow | CWE-362 | Concurrent Execution using Shared Resource with Improper Synchronization | 1000 Complete Weakness Hierarchy | CWE-362 |
| CanFollow | CWE-364 | Signal Handler Race Condition | 1000 Complete Weakness Hierarchy | CWE-364 |
| CanFollow | CWE-754 | Improper Check for Unusual or Exceptional Conditions | 1000 Complete Weakness Hierarchy | CWE-754 |
| CanFollow | CWE-1265 | Unintended Reentrant Invocation of Non-reentrant Code Via Nested Calls | 1000 Complete Weakness Hierarchy | CWE-1265 |

### Taxonomy mappings

| Taxonomy | Entry ID | Entry name | Fit |
|---|---|---|---|
| ISA/IEC 62443 | Part 4-1 | Req SI-1 |  |
| 7 Pernicious Kingdoms |  | Use After Free |  |
| CLASP |  | Using freed memory |  |
| CERT C Secure Coding | MEM00-C | Allocate and free memory in the same module, at the same level of abstraction |  |
| CERT C Secure Coding | MEM01-C | Store a new value in pointers immediately after free() |  |
| CERT C Secure Coding | MEM30-C | Do not access freed memory | Exact |
| Software Fault Patterns | SFP15 | Faulty Resource Use |  |

### Vulnerability mapping notes

**Usage:** Allowed

**Rationale:** This CWE entry is at the Variant level of abstraction, which is a preferred level of abstraction for mapping to the root causes of vulnerabilities.

**Comments:** Carefully read both the name and description to ensure that this mapping is an appropriate fit. Do not try to 'force' a mapping to a lower-level Base/Variant simply to comply with this preferred level of abstraction.

**Reasons:** Acceptable-Use

### Memberships

Categories and views this entry belongs to (for example OWASP Top Ten and earlier CWE Top 25 lists).

| Type | ID | Name |
|---|---|---|
| Category | 398 | 7PK - Code Quality |
| Category | 742 | CERT C Secure Coding Standard (2008) Chapter 9 - Memory Management (MEM) |
| Category | 808 | 2010 Top 25 - Weaknesses On the Cusp |
| Category | 876 | CERT C++ Secure Coding Section 08 - Memory Management (MEM) |
| Category | 983 | SFP Secondary Cluster: Faulty Resource Use |
| Category | 1162 | SEI CERT C Coding Standard - Guidelines 08. Memory Management (MEM) |
| View | 1200 | Weaknesses in the 2019 CWE Top 25 Most Dangerous Software Errors |
| View | 1337 | Weaknesses in the 2021 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1350 | Weaknesses in the 2020 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1387 | Weaknesses in the 2022 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1399 | Comprehensive Categorization: Memory Safety |
| View | 1425 | Weaknesses in the 2023 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1430 | Weaknesses in the 2024 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1435 | Weaknesses in the 2025 CWE Top 25 Most Dangerous Software Weaknesses |

### References

- [REF-6] Katrina Tsipenyuk, Brian Chess, Gary McGraw. "Seven Pernicious Kingdoms: A Taxonomy of Software Security Errors", 2005. https://cwe.mitre.org/documents/sources/SevenPerniciousKingdoms.pdf
- [REF-18] Secure Software, Inc.. "The CLASP Application Security Process", 2005. https://cwe.mitre.org/documents/sources/TheCLASPApplicationSecurityProcess.pdf
- [REF-44] Michael Howard, David LeBlanc, John Viega. "24 Deadly Sins of Software Security", 2010, "Sin 8: C++ Catastrophes." Page 143
- [REF-1518] "AddressSanitizer". https://clang.llvm.org/docs/AddressSanitizer.html
- [REF-1534] OMG. "Automated Technical Debt Measure, Version 2", 2024. https://www.omg.org/spec/ATDM2/1.0/PDF

### Content history (summary)

- Submitted: 2006-07-19 by 7 Pernicious Kingdoms
- Modified 40 times; latest: 2026-10-28
- Full history: https://cwe.mitre.org/data/definitions/416.html#Content_History

---

*Part 2 is taken from the MITRE CWE List, version 5.0 (2026-10-28), https://cwe.mitre.org. Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation. Used under the CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html). Part 1 was written for the Providus Bank Secure Coding programme by Training Heights.*
