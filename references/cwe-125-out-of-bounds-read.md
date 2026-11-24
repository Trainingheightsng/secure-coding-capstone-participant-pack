# CWE-125: Out-of-bounds Read

> **2025 CWE Top 25:** rank 8 · score 7.88 · CVEs in CISA KEV: 3 · change since 2024: -2

## Part 1: Review guide

### What it is, in plain words

The program reads beyond the end of the data it should read, often because it trusts a length from the input, and returns or uses neighbouring memory.

### How to spot it

**Java**
- Lengths from messages used with `Unsafe`, direct buffers or JNI
- Reused buffers (`ByteBuf`, pooled arrays) returned to the client up to a client-supplied length

**C#**
- `new ReadOnlySpan<byte>(ptr, len)` with `len` from input
- `ArrayPool` buffers sent back with a client-supplied length
- `MemoryStream.GetBuffer()` returned whole

**React / Node.js**
- `Buffer.allocUnsafe(n)` with `n` from input and not fully filled
- WebAssembly reads with unchecked offsets

### Not this weakness (safe look-alikes)

- `AsSpan(start, len)` and array access in managed code (they throw on out-of-range).
- `Buffer.alloc` (zero-filled).

### How to tell it apart from related weaknesses

Reading out of bounds is CWE-125; writing is CWE-787. A response that deliberately returns too much data is CWE-200.

### Vulnerable and secure examples

#### Java

*Context:* Java won’t read outside an array, but reusing buffers recreates the same leak.

Vulnerable:

```java
byte[] buf = POOL.take();         // reused
int claimed = in.readUnsignedShort();
in.read(buf, 0, claimed);
out.write(buf, 0, claimed);  // trusts claimed
```

Why: If fewer bytes arrived than claimed, the rest of buf is the previous customer’s data.

Secure:

```java
int claimed = in.readUnsignedShort();
if (claimed > MAX_PAYLOAD) throw new IOException();
byte[] payload = in.readNBytes(claimed);
if (payload.length != claimed)
  throw new IOException("Short payload");
out.write(payload);
```

Why it works: Read exactly what arrived into a fresh array, and check the length matches.

#### C#

*Context:* Safe C# checks every array access. The risk appears with unsafe code, raw pointers, stackalloc and P/Invoke calls into native libraries.

Vulnerable:

```csharp
int len = BitConverter.ToInt32(header, 4);
unsafe {
  fixed (byte* p = buf) {
    Send(new ReadOnlySpan<byte>(p, len));
  }
}
```

Why: The pointer-based span believes len, so it reads past the end of buf.

Secure:

```csharp
int len = BitConverter.ToInt32(header, 4);
if (len < 0 || len > buf.Length)
  throw new InvalidDataException();
Send(buf.AsSpan(0, len));
```

Why it works: AsSpan is bounds-checked against the real array.

#### React / Node.js

*Context:* JavaScript has no raw memory access. The risk is in WebAssembly modules, compiled from C or C++, that a React app loads for things like image or PDF processing.

Vulnerable:

```jsx
// length field read from the uploaded file
const len = header.getUint32(4);
const data = new Uint8Array(
  wasm.memory.buffer, ptr, len);
upload(data);
```

Why: If len is bigger than the real block, the view also reads the data next to it, like Heartbleed.

Secure:

```jsx
const len = header.getUint32(4);
if (len > blockSize)
  throw new Error("Bad length field");
const data = new Uint8Array(
  wasm.memory.buffer, ptr, len);
```

Why it works: Check every length from the input against the real block size.

### Fix guidance

**Primary defences**

1. **Never trust a length from the input.** Compare it with the real size of the data.
2. **Fresh buffers per request.** Or clear pooled buffers before reuse.
3. **Patch TLS and parsing libraries.** OpenSSL-type bugs are fixed by updating.

**Defence in depth**

- Cap maximum message sizes
- Fuzz custom protocol parsers
- Bounds-checked APIs only
- Alert on unusually large responses

**In each stack**

- Java: readNBytes(n) + length check
- C#: AsSpan(0, len) after a check
- React / Node.js: Validate length fields first

**Don't rely on**

- The length field in the message
- Buffer pools that keep old data
- Unpatched OpenSSL or parsers

### How to verify the fix

claimed 500 with 4 bytes of data is rejected, with no extra bytes returned.

### Severity guide (Providus)

Critical if it can leak keys, tokens or other customers' data (Heartbleed-style); high otherwise.

---

## Part 2: MITRE CWE entry (complete)

**Abstraction:** Base · **Structure:** Simple · **Status:** Draft  
**MITRE page:** https://cwe.mitre.org/data/definitions/125.html
  
**MITRE diagram:** https://cwe.mitre.org/data/images/CWE-125-Diagram.png

### Description

The product reads data past the end, or before the beginning, of the intended buffer.

### Alternate terms

- **OOB read**: Shorthand for "Out of bounds" read

### Common consequences

| Scope | Impact | Likelihood | Note |
|---|---|---|---|
| Confidentiality | Read Memory |  | An attacker could get secret values such as cryptographic keys, PII, memory addresses, or other information that could be used in additional attacks. |
| Confidentiality | Bypass Protection Mechanism |  | Out-of-bounds memory could contain memory addresses or other information that can be used to bypass ASLR and other protection mechanisms in order to improve the reliability of exploiting a separate weakness for code execution. |
| Availability | DoS: Crash, Exit, or Restart |  | An attacker could cause a segmentation fault or crash by causing memory to be read outside of the bounds of the buffer. This is especially likely when the code reads a variable amount of data and assumes that a sentinel exists to stop the read operation, such as a NUL in a string. |
| Other | Varies by Context |  | The read operation could produce other undefined or unexpected results. |

### Modes of introduction

- **Implementation**

### Applicable platforms

- Language: Class: Memory-Unsafe (Undetermined)
- Language: Go (Undetermined)
- Language: C (Undetermined)
- Language: C++ (Undetermined)
- Technology: Class: ICS/OT (Often)

### Weakness ordinalities

- **Resultant**: When an out-of-bounds read occurs, typically the product has already made a separate mistake, such as modifying an index or performing pointer arithmetic that produces an out-of-bounds address.
- **Primary**

### Functional areas

- Memory Management

### Affected resources

- Memory

### Potential mitigations

**1. Phase: Implementation** · Strategy: Input Validation · ID: MIT-5

Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., use a list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications, or transform it into something that does.

When performing input validation, consider all potentially relevant properties, including length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to business rules. As an example of business rule logic, "boat" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if the input is only expected to contain colors such as "red" or "blue."

Do not rely exclusively on looking for malicious or malformed inputs. This is likely to miss at least one undesirable input, especially if the code's environment changes. This can give attackers enough room to bypass the intended validation. However, denylists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright.

To reduce the likelihood of introducing an out-of-bounds read, ensure that you validate and ensure correct calculations for any length argument, buffer size calculation, or offset. Be especially careful of relying on a sentinel (i.e. special character such as NUL) in untrusted inputs.

**2. Phase: Architecture and Design** · Strategy: Language Selection

Use a language that provides appropriate memory abstractions.

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

In the following code, the method retrieves a value from an array at a specific array index location that is given as an input parameter to the method

*Bad code (C):*

```c
int getValueFromArray(int *array, int len, int index) {
    int value;
    // check that the array index is less than the maximum
    // length of the array
    if (index < len) {
        // get the value at the specified index of the array
        value = array[index];
    }
    // if array index is invalid then output error message
    // and return value indicating error
    else {
        printf("Value is: %d\n", array[index]);
        value = -1;
    }
    return value;
}
```

However, this method only verifies that the given array index is less than the maximum length of the array but does not check for the minimum value (CWE-839). This will allow a negative value to be accepted as the input array index, which will result in reading data before the beginning of the buffer (CWE-127) and may allow access to sensitive memory. The input array index should be checked to verify that is within the maximum and minimum range required for the array (CWE-129). In this example the if statement should be modified to include a minimum range check, as shown below.

*Good code (C):*

```c
...
// check that the array index is within the correct
// range of values for the array
if (index >= 0 && index < len) {
...
```

**Example 2**

In the following C/C++ example, the method processMessageFromSocket() will get a message from a socket, save the message into a buffer, and place the contents of the buffer into a structure that contains the message length and the message body. Then a for loop is used to copy the message body into a local character string, which will be passed to another method for processing.

*Bad code (C):*

```c
int processMessageFromSocket(int socket) {
    // initialize variable to represent the failure case by default
    int success = -1;
    char buffer[BUFFER_SIZE];
    char message[MESSAGE_SIZE];
    // get message from socket and store into buffer
    // for clarity of this example, ignore the possibility that buffer > BUFFER_SIZE
    if (getMessage(socket, buffer, BUFFER_SIZE) > 0) {
        // place contents of the buffer into message structure
        ExMessage *msg = recastBuffer(buffer);
        // copy message body into string for processing
        int index;
        for (index = 0; index < msg->msgLength; index++) {
            message[index] = msg->msgBody[index];
        }
        message[index] = '\0';
        // process message
        success = processMessage(message);
    }
    return success;
}
```

However, the message length variable (msgLength) from the structure is used as the condition for ending the for loop without validating that msgLength accurately reflects the actual length of the message body (CWE-606). If msgLength indicates a length that is longer than the size of a message body (CWE-130), then this can result in a buffer over-read by reading past the end of the buffer (CWE-126).

### Observed examples (real vulnerabilities)

| Reference | Description |
|---|---|
| [CVE-2026-7320](https://www.cve.org/CVERecord?id=CVE-2026-7320) | Out-of-bounds read in audio processor used in a common web browser, allowing a read of the global data section |
| [CVE-2023-1018](https://www.cve.org/CVERecord?id=CVE-2023-1018) | The reference implementation code for a Trusted Platform Module does not implement length checks on data, allowing for an attacker to read 2 bytes past the end of a buffer. |
| [CVE-2020-11899](https://www.cve.org/CVERecord?id=CVE-2020-11899) | Out-of-bounds read in IP stack used in embedded systems, as exploited in the wild per CISA KEV. |
| [CVE-2014-0160](https://www.cve.org/CVERecord?id=CVE-2014-0160) | Chain: "Heartbleed" bug receives an inconsistent length parameter (CWE-130) enabling an out-of-bounds read (CWE-126), returning memory that could include private cryptographic keys and other sensitive data. |
| [CVE-2021-40985](https://www.cve.org/CVERecord?id=CVE-2021-40985) | HTML conversion package has a buffer under-read, allowing a crash |
| [CVE-2018-10887](https://www.cve.org/CVERecord?id=CVE-2018-10887) | Chain: unexpected sign extension (CWE-194) leads to integer overflow (CWE-190), causing an out-of-bounds read (CWE-125) |
| [CVE-2009-2523](https://www.cve.org/CVERecord?id=CVE-2009-2523) | Chain: product does not handle when an input string is not NULL terminated (CWE-170), leading to buffer over-read (CWE-125) or heap-based buffer overflow (CWE-122). |
| [CVE-2018-16069](https://www.cve.org/CVERecord?id=CVE-2018-16069) | Chain: series of floating-point precision errors (CWE-1339) in a web browser rendering engine causes out-of-bounds read (CWE-125), giving access to cross-origin data |
| [CVE-2004-0112](https://www.cve.org/CVERecord?id=CVE-2004-0112) | out-of-bounds read due to improper length check |
| [CVE-2004-0183](https://www.cve.org/CVERecord?id=CVE-2004-0183) | packet with large number of specified elements cause out-of-bounds read. |
| [CVE-2004-0221](https://www.cve.org/CVERecord?id=CVE-2004-0221) | packet with large number of specified elements cause out-of-bounds read. |
| [CVE-2004-0184](https://www.cve.org/CVERecord?id=CVE-2004-0184) | out-of-bounds read, resultant from integer underflow |
| [CVE-2004-1940](https://www.cve.org/CVERecord?id=CVE-2004-1940) | large length value causes out-of-bounds read |
| [CVE-2004-0421](https://www.cve.org/CVERecord?id=CVE-2004-0421) | malformed image causes out-of-bounds read |
| [CVE-2008-4113](https://www.cve.org/CVERecord?id=CVE-2008-4113) | OS kernel trusts userland-supplied length value, allowing reading of sensitive information |

### Relationships

Includes relationships recorded on this entry and those recorded on other entries that point to it (as MITRE's page shows them).

| Nature | CWE | Name | View | Recorded on |
|---|---|---|---|---|
| ChildOf (primary) | CWE-119 | Improper Restriction of Operations within the Bounds of a Memory Buffer | 1000 Complete Weakness Hierarchy | this entry |
| ChildOf (primary) | CWE-119 | Improper Restriction of Operations within the Bounds of a Memory Buffer | 1003 Weaknesses for Simplified Mapping of Published Vulnerabilities | this entry |
| ChildOf (primary) | CWE-119 | Improper Restriction of Operations within the Bounds of a Memory Buffer | 1305 CISQ Quality Measures (2020) | this entry |
| ChildOf (primary) | CWE-119 | Improper Restriction of Operations within the Bounds of a Memory Buffer | 1340 CISQ Data Protection Measures | this entry |
| ParentOf | CWE-126 | Buffer Over-read | 1000 Complete Weakness Hierarchy | CWE-126 |
| ParentOf | CWE-127 | Buffer Under-read | 1000 Complete Weakness Hierarchy | CWE-127 |
| CanFollow | CWE-822 | Untrusted Pointer Dereference | 1000 Complete Weakness Hierarchy | CWE-822 |
| CanFollow | CWE-823 | Use of Out-of-range Pointer Offset | 1000 Complete Weakness Hierarchy | CWE-823 |
| CanFollow | CWE-824 | Access of Uninitialized Pointer | 1000 Complete Weakness Hierarchy | CWE-824 |
| CanFollow | CWE-825 | Expired Pointer Dereference | 1000 Complete Weakness Hierarchy | CWE-825 |

### Related attack patterns (CAPEC)

[CAPEC-540](https://capec.mitre.org/data/definitions/540.html)

### Taxonomy mappings

| Taxonomy | Entry ID | Entry name | Fit |
|---|---|---|---|
| PLOVER |  | Out-of-bounds Read |  |
| CERT C Secure Coding | ARR30-C | Do not form or use out-of-bounds pointers or array subscripts | Imprecise |
| CERT C Secure Coding | ARR38-C | Guarantee that library functions do not form invalid pointers | Imprecise |
| CERT C Secure Coding | EXP39-C | Do not access a variable through a pointer of an incompatible type | Imprecise |
| CERT C Secure Coding | STR31-C | Guarantee that storage for strings has sufficient space for character data and the null terminator | Imprecise |
| CERT C Secure Coding | STR32-C | Do not pass a non-null-terminated character sequence to a library function that expects a string | CWE More Abstract |
| Software Fault Patterns | SFP8 | Faulty Buffer Access |  |
| OWASP Golang Secure Coding Practices Guide |  | Memory Management |  |

### Vulnerability mapping notes

**Usage:** Allowed

**Rationale:** This CWE entry is at the Base level of abstraction, which is a preferred level of abstraction for mapping to the root causes of vulnerabilities.

**Comments:** Carefully read both the name and description to ensure that this mapping is an appropriate fit. Do not try to 'force' a mapping to a lower-level Base/Variant simply to comply with this preferred level of abstraction.

**Reasons:** Acceptable-Use

### Dimensions

Behavior-Type: Read; Resource-Type: Memory Buffer; Resource-Property: Out-of-bounds

### Memberships

Categories and views this entry belongs to (for example OWASP Top Ten and earlier CWE Top 25 lists).

| Type | ID | Name |
|---|---|---|
| Category | 970 | SFP Secondary Cluster: Faulty Buffer Access |
| Category | 1157 | SEI CERT C Coding Standard - Guidelines 03. Expressions (EXP) |
| Category | 1160 | SEI CERT C Coding Standard - Guidelines 06. Arrays (ARR) |
| Category | 1161 | SEI CERT C Coding Standard - Guidelines 07. Characters and Strings (STR) |
| View | 1200 | Weaknesses in the 2019 CWE Top 25 Most Dangerous Software Errors |
| Category | 1218 | Memory Buffer Errors |
| View | 1337 | Weaknesses in the 2021 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1350 | Weaknesses in the 2020 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1366 | ICS Communications: Frail Security in Protocols |
| View | 1387 | Weaknesses in the 2022 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1399 | Comprehensive Categorization: Memory Safety |
| View | 1425 | Weaknesses in the 2023 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1430 | Weaknesses in the 2024 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1435 | Weaknesses in the 2025 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1468 | Weaknesses Addressed by the OWASP Golang Secure Coding Practices Guide |

### References

- [REF-1034] Raoul Strackx, Yves Younan, Pieter Philippaerts, Frank Piessens, Sven Lachmund, Thomas Walter. "Breaking the memory secrecy assumption", 2009. https://dl.acm.org/doi/10.1145/1519144.1519145
- [REF-1035] Fermin J. Serna. "The info leak era on software exploitation", 2012. https://media.blackhat.com/bh-us-12/Briefings/Serna/BH_US_12_Serna_Leak_Era_Slides.pdf
- [REF-44] Michael Howard, David LeBlanc, John Viega. "24 Deadly Sins of Software Security", 2010, "Sin 5: Buffer Overruns." Page 89
- [REF-1518] "AddressSanitizer". https://clang.llvm.org/docs/AddressSanitizer.html
- [REF-1534] OMG. "Automated Technical Debt Measure, Version 2", 2024. https://www.omg.org/spec/ATDM2/1.0/PDF
- [REF-1566] OWASP. "Golang Secure Coding Practices guide", 2024, Memory Management, page 69. https://github.com/OWASP/Go-SCP

### Content history (summary)

- Submitted: 2006-07-19 by PLOVER
- Modified 30 times; latest: 2026-10-28
- Full history: https://cwe.mitre.org/data/definitions/125.html#Content_History

---

*Part 2 is taken from the MITRE CWE List, version 5.0 (2026-10-28), https://cwe.mitre.org. Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation. Used under the CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html). Part 1 was written for the Providus Bank Secure Coding programme by Training Heights.*
