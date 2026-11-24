# CWE-787: Out-of-bounds Write

> **2025 CWE Top 25:** rank 5 · score 12.68 · CVEs in CISA KEV: 12 · change since 2024: -3

## Part 1: Review guide

### What it is, in plain words

The program writes data past the end (or before the start) of the memory it was given, overwriting other data or control information.

### How to spot it

**Java**
- `sun.misc.Unsafe.putByte/putLong` with computed offsets
- JNI code writing into Java arrays or direct buffers
- Native libraries called with lengths taken from input

**C#**
- `unsafe` blocks, pointers, `stackalloc` with loops bounded by input length
- `Marshal.Copy`, `MemoryMarshal`, `Unsafe.Add` with unchecked lengths
- P/Invoke into native code passing buffer sizes from input

**React / Node.js**
- WebAssembly modules (C/C++ compiled) receiving data larger than the allocated block
- `Uint8Array` views over the whole `wasm.memory.buffer`
- Native Node add-ons fed unchecked sizes

### Not this weakness (safe look-alikes)

- Ordinary Java arrays, C# arrays and `Span<T>`, and JavaScript arrays: these are bounds-checked and throw instead of writing out of bounds.

### How to tell it apart from related weaknesses

Writing out of bounds is CWE-787; reading is CWE-125. CWE-120/121/122 are specific forms of buffer overflow (copy without size check, on the stack, on the heap): use the most specific one that fits.

### Vulnerable and secure examples

#### Java

*Context:* Plain Java checks every array access. The risk appears when Java reaches native memory: sun.misc.Unsafe, direct buffers or JNI calls into C.

Vulnerable:

```java
// off-heap buffer through sun.misc.Unsafe
long addr = UNSAFE.allocateMemory(16);
for (int i = 0; i < data.length; i++)
  UNSAFE.putByte(addr + i, data[i]);
```

Why: Unsafe has no bounds checks. A 17th byte is written past the block.

Secure:

```java
// Java 22+ Foreign Function & Memory API
try (Arena arena = Arena.ofConfined()) {
  MemorySegment seg = arena.allocate(16);
  MemorySegment.copy(data, 0, seg,
      ValueLayout.JAVA_BYTE, 0, data.length);
}
```

Why it works: MemorySegment is bounds-checked: too much data throws IndexOutOfBoundsException.

#### C#

*Context:* Safe C# checks every array access. The risk appears with unsafe code, raw pointers, stackalloc and P/Invoke calls into native libraries.

Vulnerable:

```csharp
unsafe {
  byte* buf = stackalloc byte[16];
  for (int i = 0; i < data.Length; i++)
    buf[i] = data[i];
}
```

Why: Raw pointers skip the checks, so long input writes over the stack.

Secure:

```csharp
Span<byte> buf = stackalloc byte[16];
if (data.Length > buf.Length)
  throw new ArgumentException("Too long");
data.CopyTo(buf);
```

Why it works: Span is bounds-checked, even over stack memory.

#### React / Node.js

*Context:* JavaScript has no raw memory access. The risk is in WebAssembly modules, compiled from C or C++, that a React app loads for things like image or PDF processing.

Vulnerable:

```jsx
// image filter compiled to WebAssembly
const ptr = wasm.alloc(256);
const mem = new Uint8Array(wasm.memory.buffer);
mem.set(fileBytes, ptr);   // any size
wasm.sharpen(ptr, fileBytes.length);
```

Why: The view covers all of the module’s memory, so a large file overwrites whatever sits after the block.

Secure:

```jsx
const len = fileBytes.length;
if (len > MAX_IMAGE) throw new Error("Too large");
const ptr = wasm.alloc(len);
const view = new Uint8Array(
  wasm.memory.buffer, ptr, len);
view.set(fileBytes);  // throws if it won't fit
```

Why it works: Allocate the real size and write through a view limited to that block.

### Fix guidance

**Primary defences**

1. **Stay in memory-safe code.** Avoid unsafe, Unsafe and raw pointers. Use Span, arrays and MemorySegment.
2. **Check every length and index.** Validate sizes before any copy at a native boundary.
3. **Patch native dependencies fast.** Most CWE-787 reaches us through libraries and runtimes.

**Defence in depth**

- Allow-list input sizes at the API
- SCA and SBOM for native libraries
- Fuzz native parsers
- Review every unsafe block

**In each stack**

- Java: Arrays and MemorySegment; avoid sun.misc.Unsafe
- C#: Span<T>; keep AllowUnsafeBlocks off
- React / Node.js: Bounded typed-array views over WebAssembly memory

**Don't rely on**

- A length sent by the client
- “Input is never that long”
- Catching crashes and carrying on

### How to verify the fix

Oversized input is rejected, with no crash or corrupted values.

### Severity guide (Providus)

Critical when reachable from network input in native code; otherwise high. Usually reaches Java, C# and React teams through dependencies, so report outdated native libraries too.

---

## Part 2: MITRE CWE entry (complete)

**Abstraction:** Base · **Structure:** Simple · **Status:** Draft  
**MITRE page:** https://cwe.mitre.org/data/definitions/787.html
  
**MITRE diagram:** https://cwe.mitre.org/data/images/CWE-787-Diagram.png

### Description

The product writes data past the end, or before the beginning, of the intended buffer.

### Alternate terms

- **Memory Corruption**: Often used to describe the consequences of writing to memory outside the bounds of a buffer, or to memory that is otherwise invalid.

### Common consequences

| Scope | Impact | Likelihood | Note |
|---|---|---|---|
| Integrity | Modify Memory, Execute Unauthorized Code or Commands |  | Write operations could cause memory corruption. In some cases, an adversary can modify control data such as return addresses in order to execute unexpected code. |
| Availability | DoS: Crash, Exit, or Restart |  | Attempting to access out-of-range, invalid, or unauthorized memory could cause the product to crash. |
| Other | Unexpected State |  | Subsequent write operations can produce undefined or unexpected results. |

### Likelihood of exploit

High

### Modes of introduction

- **Implementation**

### Applicable platforms

- Language: Class: Memory-Unsafe (Often)
- Language: C (Often)
- Language: C++ (Often)
- Language: Class: Assembly (Undetermined)
- Technology: Class: ICS/OT (Often)

### Weakness ordinalities

- **Resultant**: At the point when the product writes data to an invalid location, it is likely that a separate weakness already occurred earlier. For example, the product might alter an index, perform incorrect pointer arithmetic, initialize or release memory incorrectly, etc., thus referencing a memory location outside the buffer.

### Functional areas

- Memory Management

### Affected resources

- Memory

### Potential mitigations

**1. Phase: Requirements** · Strategy: Language Selection · ID: MIT-3

Use a language that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.

For example, many languages that perform their own memory management, such as Java and Perl, are not subject to buffer overflows. Other languages, such as Ada and C#, typically provide overflow protection, but the protection can be disabled by the programmer.

Be wary that a language's interface to native code may still be subject to overflows, even if the language itself is theoretically safe.

**2. Phase: Architecture and Design** · Strategy: Libraries or Frameworks · ID: MIT-4.1

Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.

Examples include the Safe C String Library (SafeStr) by Messier and Viega [REF-57], and the Strsafe.h library from Microsoft [REF-56]. These libraries provide safer versions of overflow-prone string-handling functions.

**3. Phase: Operation, Build and Compilation** · Strategy: Environment Hardening · ID: MIT-10

Use automatic buffer overflow detection mechanisms that are offered by certain compilers or compiler extensions. Examples include: the Microsoft Visual Studio /GS flag, Fedora/Red Hat FORTIFY_SOURCE GCC flag, StackGuard, and ProPolice, which provide various mechanisms including canary-based detection and range/index checking.

D3-SFCV (Stack Frame Canary Validation) from D3FEND [REF-1334] discusses canary-based detection in detail.

*Effectiveness: Defense in Depth*. This is not necessarily a complete solution, since these mechanisms only detect certain types of overflows. In addition, the result is still a denial of service, since the typical response is to exit the application.

**4. Phase: Implementation** · ID: MIT-9

Consider adhering to the following rules when allocating and managing an application's memory:

- Double check that the buffer is as large as specified.
- When using functions that accept a number of bytes to copy, such as strncpy(), be aware that if the destination buffer size is equal to the source buffer size, it may not NULL-terminate the string.
- Check buffer boundaries if accessing the buffer in a loop and make sure there is no danger of writing past the allocated space.
- If necessary, truncate all input strings to a reasonable length before passing them to the copy and concatenation functions.

**5. Phase: Operation, Build and Compilation** · Strategy: Environment Hardening · ID: MIT-11

Run or compile the software using features or extensions that randomly arrange the positions of a program's executable and libraries in memory. Because this makes the addresses unpredictable, it can prevent an attacker from reliably jumping to exploitable code.

Examples include Address Space Layout Randomization (ASLR) [REF-58] [REF-60] and Position-Independent Executables (PIE) [REF-64]. Imported modules may be similarly realigned if their default memory addresses conflict with other modules, in a process known as "rebasing" (for Windows) and "prelinking" (for Linux) [REF-1332] using randomly generated addresses. ASLR for libraries cannot be used in conjunction with prelink since it would require relocating the libraries at run-time, defeating the whole purpose of prelinking.

For more information on these techniques see D3-SAOR (Segment Address Offset Randomization) from D3FEND [REF-1335].

*Effectiveness: Defense in Depth*. These techniques do not provide a complete solution. For instance, exploits frequently use a bug that discloses memory addresses in order to maximize reliability of code execution [REF-1337]. It has also been shown that a side-channel attack can bypass ASLR [REF-1333].

**6. Phase: Operation** · Strategy: Environment Hardening · ID: MIT-12

Use a CPU and operating system that offers Data Execution Protection (using hardware NX or XD bits) or the equivalent techniques that simulate this feature in software, such as PaX [REF-60] [REF-61]. These techniques ensure that any instruction executed is exclusively at a memory address that is part of the code segment.

For more information on these techniques see D3-PSEP (Process Segment Execution Prevention) from D3FEND [REF-1336].

*Effectiveness: Defense in Depth*. This is not a complete solution, since buffer overflows could be used to overwrite nearby variables to modify the software's state in dangerous ways. In addition, it cannot be used in cases in which self-modifying code is required. Finally, an attack could still cause a denial of service, since the typical response is to exit the application.

**7. Phase: Implementation** · ID: MIT-13

Replace unbounded copy functions with analogous functions that support length arguments, such as strcpy with strncpy. Create these if they are not available.

*Effectiveness: Moderate*. This approach is still susceptible to calculation errors, including issues such as off-by-one errors (CWE-193) and incorrectly calculating buffer lengths (CWE-131).

### Detection methods

**Automated Static Analysis** (effectiveness: High)

This weakness can often be detected using automated static analysis tools. Many modern tools use data flow analysis or constraint-based techniques to minimize the number of false positives.

Automated static analysis generally does not account for environmental considerations when reporting out-of-bounds memory operations. This can make it difficult for users to determine which warnings should be investigated first. For example, an analysis tool might report buffer overflows that originate from command line arguments in a program that is not expected to run with setuid or other special privileges.

*Detection techniques for buffer-related errors are more mature than for most other weakness types.*

**Automated Dynamic Analysis**

This weakness can be detected using dynamic tools and techniques that interact with the software using large test suites with many diverse inputs, such as fuzz testing (fuzzing), robustness testing, and fault injection. The software's operation may slow down, but it should not become unstable, crash, or generate incorrect results.

**Automated Dynamic Analysis** (effectiveness: Moderate)

Use tools that are integrated during compilation to insert runtime error-checking mechanisms related to memory safety errors, such as AddressSanitizer (ASan) for C/C++ [REF-1518].

*Crafted inputs are necessary to reach the code containing the error, such as generated by fuzzers. Also, these tools may reduce performance, and they only report the error condition - not the original mistake that led to the error.*

### Demonstrative examples

**Example 1**

The following code attempts to save four different identification numbers into an array.

*Bad code (C):*

```c
int id_sequence[3];
/* Populate the id array. */
id_sequence[0] = 123;
id_sequence[1] = 234;
id_sequence[2] = 345;
id_sequence[3] = 456;
```

Since the array is only allocated to hold three elements, the valid indices are 0 to 2; so, the assignment to id_sequence[3] is out of bounds.

**Example 2**

In the following code, it is possible to request that memcpy move a much larger segment of memory than assumed:

*Bad code (C):*

```c
int returnChunkSize(void *) {
    /* if chunk info is valid, return the size of usable memory,
    * else, return -1 to indicate an error
    */
    ...
}
int main() {
    ...
    memcpy(destBuf, srcBuf, (returnChunkSize(destBuf)-1));
    ...
}
```

If returnChunkSize() happens to encounter an error it will return -1. Notice that the return value is not checked before the memcpy operation (CWE-252), so -1 can be passed as the size argument to memcpy() (CWE-805). Because memcpy() assumes that the value is unsigned, it will be interpreted as MAXINT-1 (CWE-195), and therefore will copy far more memory than is likely available to the destination buffer (CWE-787, CWE-788).

**Example 3**

This code takes an IP address from the user and verifies that it is well formed. It then looks up the hostname and copies it into a buffer.

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

This function allocates a buffer of 64 bytes to store the hostname. However, there is no guarantee that the hostname will not be larger than 64 bytes. If an attacker specifies an address which resolves to a very large hostname, then the function may overwrite sensitive data or even relinquish control flow to the attacker.

Note that this example also contains an unchecked return value (CWE-252) that can lead to a NULL pointer dereference (CWE-476).

**Example 4**

This code applies an encoding procedure to an input string and stores it into a buffer.

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

The programmer attempts to encode the ampersand character in the user-controlled string. However, the length of the string is validated before the encoding procedure is applied. Furthermore, the programmer assumes encoding expansion will only expand a given character by a factor of 4, while the encoding of the ampersand expands by 5. As a result, when the encoding procedure expands the string it is possible to overflow the destination buffer if the attacker provides a string of many ampersands.

**Example 5**

In the following C/C++ code, a utility function is used to trim trailing whitespace from a character string. The function copies the input string to a local character string and uses a while statement to remove the trailing whitespace by moving backward through the string and overwriting whitespace with a NUL character.

*Bad code (C):*

```c
char* trimTrailingWhitespace(char *strMessage, int length) {
    char *retMessage;
    char *message = malloc(sizeof(char)*(length+1));
    // copy input string to a temporary string
    char message[length+1];
    int index;
    for (index = 0; index < length; index++) {
        message[index] = strMessage[index];
    }
    message[index] = '\0';
    // trim trailing whitespace
    int len = index-1;
    while (isspace(message[len])) {
        message[len] = '\0';
        len--;
    }
    // return string without trailing whitespace
    retMessage = message;
    return retMessage;
}
```

However, this function can cause a buffer underwrite if the input character string contains all whitespace. On some systems the while statement will move backwards past the beginning of a character string and will call the isspace() function on an address outside of the bounds of the local buffer.

**Example 6**

The following code allocates memory for a maximum number of widgets. It then gets a user-specified number of widgets, making sure that the user does not request too many. It then initializes the elements of the array using InitializeWidget(). Because the number of widgets can vary for each request, the code inserts a NULL pointer to signify the location of the last widget.

*Bad code (C):*

```c
int i;
unsigned int numWidgets;
Widget **WidgetList;
numWidgets = GetUntrustedSizeValue();
if ((numWidgets == 0) || (numWidgets > MAX_NUM_WIDGETS)) {
    ExitError("Incorrect number of widgets requested!");
}
WidgetList = (Widget **)malloc(numWidgets * sizeof(Widget *));
printf("WidgetList ptr=%p\n", WidgetList);
for(i=0; i<numWidgets; i++) {
    WidgetList[i] = InitializeWidget();
}
WidgetList[numWidgets] = NULL;
showWidgets(WidgetList);
```

However, this code contains an off-by-one calculation error (CWE-193). It allocates exactly enough space to contain the specified number of widgets, but it does not include the space for the NULL pointer. As a result, the allocated buffer is smaller than it is supposed to be (CWE-131). So if the user ever requests MAX_NUM_WIDGETS, there is an out-of-bounds write (CWE-787) when the NULL is assigned. Depending on the environment and compilation settings, this could cause memory corruption.

**Example 7**

The following is an example of code that may result in a buffer underwrite. This code is attempting to replace the substring "Replace Me" in destBuf with the string stored in srcBuf. It does so by using the function strstr(), which returns a pointer to the found substring in destBuf. Using pointer arithmetic, the starting index of the substring is found.

*Bad code (C):*

```c
int main() {
    ...
    char *result = strstr(destBuf, "Replace Me");
    int idx = result - destBuf;
    strcpy(&destBuf[idx], srcBuf);
    ...
}
```

In the case where the substring is not found in destBuf, strstr() will return NULL, causing the pointer arithmetic to be undefined, potentially setting the value of idx to a negative number. If idx is negative, this will result in a buffer underwrite of destBuf.

### Observed examples (real vulnerabilities)

| Reference | Description |
|---|---|
| [CVE-2026-7270](https://www.cve.org/CVERecord?id=CVE-2026-7270) | Chain: calculation expression does not use parentheses to address operator precedence (CWE-783), causing an incorrect calculation (CWE-682) leading to a buffer overflow (CWE-787). |
| [CVE-2025-27363](https://www.cve.org/CVERecord?id=CVE-2025-27363) | Font rendering library does not properly handle assigning a signed short value to an unsigned long (CWE-195), leading to an integer wraparound (CWE-190), causing too small of a buffer (CWE-131), leading to an out-of-bounds write (CWE-787). |
| [CVE-2023-1017](https://www.cve.org/CVERecord?id=CVE-2023-1017) | The reference implementation code for a Trusted Platform Module does not implement length checks on data, allowing for an attacker to write 2 bytes past the end of a buffer. |
| [CVE-2021-21220](https://www.cve.org/CVERecord?id=CVE-2021-21220) | Chain: insufficient input validation (CWE-20) in browser allows heap corruption (CWE-787), as exploited in the wild per CISA KEV. |
| [CVE-2021-28664](https://www.cve.org/CVERecord?id=CVE-2021-28664) | GPU kernel driver allows memory corruption because a user can obtain read/write access to read-only pages, as exploited in the wild per CISA KEV. |
| [CVE-2020-17087](https://www.cve.org/CVERecord?id=CVE-2020-17087) | Chain: integer truncation (CWE-197) causes small buffer allocation (CWE-131) leading to out-of-bounds write (CWE-787) in kernel pool, as exploited in the wild per CISA KEV. |
| [CVE-2020-1054](https://www.cve.org/CVERecord?id=CVE-2020-1054) | Out-of-bounds write in kernel-mode driver, as exploited in the wild per CISA KEV. |
| [CVE-2020-0041](https://www.cve.org/CVERecord?id=CVE-2020-0041) | Escape from browser sandbox using out-of-bounds write due to incorrect bounds check, as exploited in the wild per CISA KEV. |
| [CVE-2020-0968](https://www.cve.org/CVERecord?id=CVE-2020-0968) | Memory corruption in web browser scripting engine, as exploited in the wild per CISA KEV. |
| [CVE-2020-0022](https://www.cve.org/CVERecord?id=CVE-2020-0022) | Chain: mobile phone Bluetooth implementation does not include offset when calculating packet length (CWE-682), leading to out-of-bounds write (CWE-787) |
| [CVE-2019-1010006](https://www.cve.org/CVERecord?id=CVE-2019-1010006) | Chain: compiler optimization (CWE-733) removes or modifies code used to detect integer overflow (CWE-190), allowing out-of-bounds write (CWE-787). |
| [CVE-2009-1532](https://www.cve.org/CVERecord?id=CVE-2009-1532) | malformed inputs cause accesses of uninitialized or previously-deleted objects, leading to memory corruption |
| [CVE-2009-0269](https://www.cve.org/CVERecord?id=CVE-2009-0269) | Chain: -1 value from a function call was intended to indicate an error, but is used as an array index instead. |
| [CVE-2002-2227](https://www.cve.org/CVERecord?id=CVE-2002-2227) | Unchecked length of SSLv2 challenge value leads to buffer underflow. |
| [CVE-2007-4580](https://www.cve.org/CVERecord?id=CVE-2007-4580) | Buffer underflow from a small size value with a large buffer (length parameter inconsistency, CWE-130) |
| [CVE-2007-4268](https://www.cve.org/CVERecord?id=CVE-2007-4268) | Chain: integer signedness error (CWE-195) passes signed comparison, leading to heap overflow (CWE-122) |
| [CVE-2009-2550](https://www.cve.org/CVERecord?id=CVE-2009-2550) | Classic stack-based buffer overflow in media player using a long entry in a playlist |
| [CVE-2009-2403](https://www.cve.org/CVERecord?id=CVE-2009-2403) | Heap-based buffer overflow in media player using a long entry in a playlist |

### Relationships

Includes relationships recorded on this entry and those recorded on other entries that point to it (as MITRE's page shows them).

| Nature | CWE | Name | View | Recorded on |
|---|---|---|---|---|
| ChildOf (primary) | CWE-119 | Improper Restriction of Operations within the Bounds of a Memory Buffer | 1000 Complete Weakness Hierarchy | this entry |
| ChildOf (primary) | CWE-119 | Improper Restriction of Operations within the Bounds of a Memory Buffer | 1003 Weaknesses for Simplified Mapping of Published Vulnerabilities | this entry |
| ChildOf (primary) | CWE-119 | Improper Restriction of Operations within the Bounds of a Memory Buffer | 1305 CISQ Quality Measures (2020) | this entry |
| ChildOf (primary) | CWE-119 | Improper Restriction of Operations within the Bounds of a Memory Buffer | 1340 CISQ Data Protection Measures | this entry |
| ParentOf | CWE-120 | Buffer Copy without Checking Size of Input | 1000 Complete Weakness Hierarchy | CWE-120 |
| ParentOf | CWE-121 | Stack-based Buffer Overflow | 1000 Complete Weakness Hierarchy | CWE-121 |
| ParentOf | CWE-122 | Heap-based Buffer Overflow | 1000 Complete Weakness Hierarchy | CWE-122 |
| ParentOf | CWE-123 | Write-what-where Condition | 1000 Complete Weakness Hierarchy | CWE-123 |
| ParentOf | CWE-124 | Buffer Underwrite | 1000 Complete Weakness Hierarchy | CWE-124 |
| ParentOf | CWE-785 | Use of Path Manipulation Function without Maximum-sized Buffer | 1000 Complete Weakness Hierarchy | CWE-785 |
| ParentOf | CWE-120 | Buffer Copy without Checking Size of Input | 1305 CISQ Quality Measures (2020) | CWE-120 |
| ParentOf | CWE-123 | Write-what-where Condition | 1305 CISQ Quality Measures (2020) | CWE-123 |
| ParentOf | CWE-120 | Buffer Copy without Checking Size of Input | 1340 CISQ Data Protection Measures | CWE-120 |
| CanFollow | CWE-822 | Untrusted Pointer Dereference | 1000 Complete Weakness Hierarchy | CWE-822 |
| CanFollow | CWE-823 | Use of Out-of-range Pointer Offset | 1000 Complete Weakness Hierarchy | CWE-823 |
| CanFollow | CWE-824 | Access of Uninitialized Pointer | 1000 Complete Weakness Hierarchy | CWE-824 |
| CanFollow | CWE-825 | Expired Pointer Dereference | 1000 Complete Weakness Hierarchy | CWE-825 |
| Related (Overlaps) | CWE-788 | Access of Memory Location After End of Buffer | 1000 Complete Weakness Hierarchy | CWE-788 |

### Taxonomy mappings

| Taxonomy | Entry ID | Entry name | Fit |
|---|---|---|---|
| ISA/IEC 62443 | Part 3-3 | Req SR 3.5 |  |
| ISA/IEC 62443 | Part 4-1 | Req SI-1 |  |
| ISA/IEC 62443 | Part 4-1 | Req SI-2 |  |
| ISA/IEC 62443 | Part 4-1 | Req SVV-1 |  |
| ISA/IEC 62443 | Part 4-1 | Req SVV-3 |  |
| ISA/IEC 62443 | Part 4-2 | Req CR 3.5 |  |
| PLC Top 20 | 10 | Assign designated register blocks by function (read/write/validate) |  |

### Vulnerability mapping notes

**Usage:** Allowed-with-Review

**Rationale:** This CWE entry is at the Base level of abstraction, which is a preferred level of abstraction for mapping to the root causes of vulnerabilities. However, closer examination is required.

**Comments:** While this CWE is allowed for mapping, it has more specific children that might be a better fit. Carefully read both the name and description to ensure that this mapping is appropriate. Consider the root cause errors that have led to the out-of-bounds write by examining "CanFollow" relationships for this entry.

**Reasons:** Frequent Misuse, Abstraction

**Suggestions:**
- CWE-120 Buffer Copy without Checking Size of Input: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')
- CWE-121 Stack-based Buffer Overflow: Stack-based Buffer Overflow
- CWE-122 Heap-based Buffer Overflow: Heap-based Buffer Overflow
- CWE-124 Buffer Underwrite: Buffer Underwrite ('Buffer Underflow')

### Dimensions

Behavior-Type: Write; Resource-Type: Memory Buffer; Resource-Property: Out-of-bounds

### Memberships

Categories and views this entry belongs to (for example OWASP Top Ten and earlier CWE Top 25 lists).

| Type | ID | Name |
|---|---|---|
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
| View | 1460 | Weaknesses Addressed by the Top 20 Secure PLC Coding Practices |

### References

- [REF-1029] Aleph One. "Smashing The Stack For Fun And Profit", 1996. https://phrack.org/issues/49/14.html
- [REF-7] Michael Howard, David LeBlanc. "Writing Secure Code", 2002, Chapter 5, "Stack Overruns" Page 129. https://www.microsoftpressstore.com/store/writing-secure-code-9780735617223
- [REF-7] Michael Howard, David LeBlanc. "Writing Secure Code", 2002, Chapter 5, "Heap Overruns" Page 138. https://www.microsoftpressstore.com/store/writing-secure-code-9780735617223
- [REF-44] Michael Howard, David LeBlanc, John Viega. "24 Deadly Sins of Software Security", 2010, "Sin 5: Buffer Overruns." Page 89
- [REF-62] Mark Dowd, John McDonald, Justin Schuh. "The Art of Software Security Assessment", 2006, Chapter 3, "Nonexecutable Stack", Page 76
- [REF-62] Mark Dowd, John McDonald, Justin Schuh. "The Art of Software Security Assessment", 2006, Chapter 5, "Protection Mechanisms", Page 189
- [REF-90] "Buffer UNDERFLOWS: What do you know about it?", 2004. https://seclists.org/vuln-dev/2004/Jan/22
- [REF-56] Microsoft. "Using the Strsafe.h Functions". https://learn.microsoft.com/en-us/windows/win32/menurc/strsafe-ovw?redirectedfrom=MSDN
- [REF-57] Matt Messier, John Viega. "Safe C String Library v1.0.3". http://www.gnu-darwin.org/www001/ports-1.5a-CURRENT/devel/safestr/work/safestr-1.0.3/doc/safestr.html
- [REF-58] Michael Howard. "Address Space Layout Randomization in Windows Vista". https://learn.microsoft.com/en-us/archive/blogs/michael_howard/address-space-layout-randomization-in-windows-vista
- [REF-60] "PaX". https://en.wikipedia.org/wiki/Executable_space_protection#PaX
- [REF-61] Microsoft. "Understanding DEP as a mitigation technology part 1". https://msrc.microsoft.com/blog/2009/06/understanding-dep-as-a-mitigation-technology-part-1/
- [REF-64] Grant Murphy. "Position Independent Executables (PIE)", 2012. https://www.redhat.com/en/blog/position-independent-executables-pie
- [REF-1332] John Richard Moser. "Prelink and address space randomization", 2006. https://lwn.net/Articles/190139/
- [REF-1333] Dmitry Evtyushkin, Dmitry Ponomarev, Nael Abu-Ghazaleh. "Jump Over ASLR: Attacking Branch Predictors to Bypass ASLR", 2016. http://www.cs.ucr.edu/~nael/pubs/micro16.pdf
- [REF-1334] D3FEND. "Stack Frame Canary Validation (D3-SFCV)", 2023. https://d3fend.mitre.org/technique/d3f:StackFrameCanaryValidation/
- [REF-1335] D3FEND. "Segment Address Offset Randomization (D3-SAOR)", 2023. https://d3fend.mitre.org/technique/d3f:SegmentAddressOffsetRandomization/
- [REF-1336] D3FEND. "Process Segment Execution Prevention (D3-PSEP)", 2023. https://d3fend.mitre.org/technique/d3f:ProcessSegmentExecutionPrevention/
- [REF-1337] Alexander Sotirov and Mark Dowd. "Bypassing Browser Memory Protections: Setting back browser security by 10 years", 2008, Memory information leaks. https://www.blackhat.com/presentations/bh-usa-08/Sotirov_Dowd/bh08-sotirov-dowd.pdf
- [REF-1477] Cybersecurity and Infrastructure Security Agency. "Secure by Design Alert: Eliminating Buffer Overflow Vulnerabilities", 2025. https://www.cisa.gov/resources-tools/resources/secure-design-alert-eliminating-buffer-overflow-vulnerabilities
- [REF-1518] "AddressSanitizer". https://clang.llvm.org/docs/AddressSanitizer.html
- [REF-1534] OMG. "Automated Technical Debt Measure, Version 2", 2024. https://www.omg.org/spec/ATDM2/1.0/PDF
- [REF-1550] Secure PLC Programming project. "Secure PLC Coding Practices: Top 20 List", 2021. https://plc-security.com/

### Content history (summary)

- Submitted: 2009-10-21 by MITRE
- Modified 26 times; latest: 2026-10-28
- Full history: https://cwe.mitre.org/data/definitions/787.html#Content_History

---

*Part 2 is taken from the MITRE CWE List, version 5.0 (2026-10-28), https://cwe.mitre.org. Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation. Used under the CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html). Part 1 was written for the Providus Bank Secure Coding programme by Training Heights.*
