# CWE-434: Unrestricted Upload of File with Dangerous Type

> **2025 CWE Top 25:** rank 12 · score 6.87 · CVEs in CISA KEV: 4 · change since 2024: -2

## Part 1: Review guide

### What it is, in plain words

The application accepts an uploaded file without checking what it really is and stores it where it can be executed or served, so an attacker can upload a web shell or malware.

### How to spot it

**Java**
- `MultipartFile.transferTo` or `Files.copy` using `getOriginalFilename()`
- Uploads saved under `static/`, `public/` or the web root
- Checks that trust `getContentType()` or only the extension

**C#**
- `IFormFile.CopyToAsync` with `file.FileName` into `wwwroot`
- Content type taken from `file.ContentType` (client-supplied)
- No size limit (`RequestSizeLimit`) on upload actions

**React / Node.js**
- Multer `diskStorage` keeping `file.originalname` in a public folder
- Accept-attribute (`<input accept=...>`) as the only check
- Next.js routes writing uploads into `public/`

### Not this weakness (safe look-alikes)

- Files stored outside the web root (or in object storage) under a server-generated name, with type checked by content (magic bytes) against an allow-list.
- Images re-encoded server-side before use.

### How to tell it apart from related weaknesses

Dangerous file type accepted is CWE-434. A file name that escapes the folder (`../`) is CWE-22. Unbounded upload size is CWE-770.

### Vulnerable and secure examples

#### Java

Vulnerable:

```java
Path dest = Paths.get("src/main/resources/static/uploads",
                      file.getOriginalFilename());
file.transferTo(dest);
```

Why: `shell.jsp` uploaded into a served folder.

Secure:

```java
String ext = detectByMagicBytes(file.getInputStream());   // pdf, png, jpg
if (!ALLOWED.contains(ext)) throw new BadRequestException("Type not allowed");
Path dest = UPLOADS.resolve(UUID.randomUUID() + "." + ext);  // outside web root
file.transferTo(dest);
```

Why it works: Type checked by content, random name, stored outside the web root.

#### C#

Vulnerable:

```csharp
var path = Path.Combine(_env.WebRootPath, "kyc", file.FileName);
await using var fs = File.Create(path);
await file.CopyToAsync(fs);
```

Why: Client file name, saved under `wwwroot`.

Secure:

```csharp
if (!await FileSignatures.IsAllowedAsync(file, ".pdf", ".jpg", ".png"))
    return BadRequest();
var name = $"{Guid.NewGuid()}{Path.GetExtension(file.FileName).ToLowerInvariant()}";
await _blob.UploadAsync($"kyc/{name}", file.OpenReadStream());   // private store
```

Why it works: Signature check, generated name, private storage.

#### React / Node.js

Vulnerable:

```jsx
const upload = multer({ storage: multer.diskStorage({
  destination: "public/uploads",
  filename: (req, f, cb) => cb(null, f.originalname) }) });
```

Why: Original name, public folder.

Secure:

```jsx
const upload = multer({ storage: multer.memoryStorage(),
  limits: { fileSize: 5_000_000 } });
// then: const t = await fileTypeFromBuffer(buf); allow-list t.mime; save with random name
```

Why it works: Size limit, type by content, private storage.

### Fix guidance

**Primary defences**

1. Allow-list file types by content (magic bytes), not by name or Content-Type
2. Store uploads outside the web root with server-generated names
3. Limit size and scan for malware

**Defence in depth**

- Serve downloads with `Content-Disposition: attachment` and correct type
- Re-encode images
- Separate storage domain

### How to verify the fix

Uploading `shell.jsp` renamed to `.pdf` is rejected, and no upload is ever reachable as executable code.

### Severity guide (Providus)

Critical if uploads land in an executable or web-served location; high otherwise (e.g., malware sharing to staff).

---

## Part 2: MITRE CWE entry (complete)

**Abstraction:** Base · **Structure:** Simple · **Status:** Draft  
**MITRE page:** https://cwe.mitre.org/data/definitions/434.html
  
**MITRE diagram:** https://cwe.mitre.org/data/images/CWE-434-Diagram.png

### Description

The product allows the upload or transfer of dangerous file types that are automatically processed within its environment.

### Alternate terms

- **Unrestricted File Upload**: Used in vulnerability databases and elsewhere, but it is insufficiently precise. The phrase could be interpreted as the lack of restrictions on the size or number of uploaded files, which is a resource consumption issue.

### Common consequences

| Scope | Impact | Likelihood | Note |
|---|---|---|---|
| Integrity, Confidentiality, Availability | Execute Unauthorized Code or Commands |  | Arbitrary code execution is possible if an uploaded file is interpreted and executed as code by the recipient. This is especially true for web-server extensions such as .asp and .php because these file types are often treated as automatically executable, even when file system permissions do not specify execution. For example, in Unix environments, programs typically cannot run unless the execute bit is set, but PHP programs may be executed by the web server without directly invoking them on the operating system. |

### Likelihood of exploit

Medium

### Modes of introduction

- **Implementation**
- **Architecture and Design**: OMISSION: This weakness is caused by missing a security tactic during the architecture and design phase.

### Applicable platforms

- Language: ASP.NET (Sometimes)
- Language: PHP (Often)
- Language: Class: Not Language-Specific (Undetermined)
- Technology: Web Server (Sometimes)
- Technology: AI/ML (Undetermined)

### Weakness ordinalities

- **Primary**: This can be primary when there is no check for the file type at all.
- **Resultant**: This can be resultant when use of double extensions (e.g. ".php.gif") bypasses a check.
- **Resultant**: This can be resultant from client-side enforcement (CWE-602); some products will include web script in web clients to check the filename, without verifying on the server side.

### Functional areas

- File Processing

### Affected resources

- File or Directory

### Potential mitigations

**1. Phase: Architecture and Design**

Generate a new, unique filename for an uploaded file instead of using the user-supplied filename, so that no external input is used at all.[REF-422] [REF-423]

**2. Phase: Architecture and Design** · Strategy: Enforcement by Conversion · ID: MIT-21

When the set of acceptable objects, such as filenames or URLs, is limited or known, create a mapping from a set of fixed input values (such as numeric IDs) to the actual filenames or URLs, and reject all other inputs.

**3. Phase: Architecture and Design**

Consider storing the uploaded files outside of the web document root entirely. Then, use other mechanisms to deliver the files dynamically. [REF-423]

**4. Phase: Implementation** · Strategy: Input Validation · ID: MIT-5

Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., use a list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications, or transform it into something that does.

When performing input validation, consider all potentially relevant properties, including length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to business rules. As an example of business rule logic, "boat" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if the input is only expected to contain colors such as "red" or "blue."

Do not rely exclusively on looking for malicious or malformed inputs. This is likely to miss at least one undesirable input, especially if the code's environment changes. This can give attackers enough room to bypass the intended validation. However, denylists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright.

For example, limiting filenames to alphanumeric characters can help to restrict the introduction of unintended file extensions.

**5. Phase: Architecture and Design**

Define a very limited set of allowable extensions and only generate filenames that end in these extensions. Consider the possibility of XSS (CWE-79) before allowing .html or .htm file types.

**6. Phase: Implementation** · Strategy: Input Validation

Ensure that only one extension is used in the filename. Some web servers, including some versions of Apache, may process files based on inner extensions so that "filename.php.gif" is fed to the PHP interpreter.[REF-422] [REF-423]

**7. Phase: Implementation**

When running on a web server that supports case-insensitive filenames, perform case-insensitive evaluations of the extensions that are provided.

**8. Phase: Architecture and Design** · ID: MIT-15

For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side, in order to avoid CWE-602. Attackers can bypass the client-side checks by modifying values after the checks have been performed, or by changing the client to remove the client-side checks entirely. Then, these modified values would be submitted to the server.

**9. Phase: Implementation**

Do not rely exclusively on sanity checks of file contents to ensure that the file is of the expected type and size. It may be possible for an attacker to hide code in some file segments that will still be executed by the server. For example, GIF images may contain a free-form comments field.

**10. Phase: Implementation**

Do not rely exclusively on the MIME content type or filename attribute when determining how to render a file. Validating the MIME content type and ensuring that it matches the extension is only a partial solution.

**11. Phase: Architecture and Design, Operation** · Strategy: Environment Hardening · ID: MIT-17

Run your code using the lowest privileges that are required to accomplish the necessary tasks [REF-76]. If possible, create isolated accounts with limited privileges that are only used for a single task. That way, a successful attack will not immediately give the attacker access to the rest of the software or its environment. For example, database applications rarely need to run as the database administrator, especially in day-to-day operations.

**12. Phase: Architecture and Design, Operation** · Strategy: Sandbox or Jail · ID: MIT-22

Run the code in a "jail" or similar sandbox environment that enforces strict boundaries between the process and the operating system. This may effectively restrict which files can be accessed in a particular directory or which commands can be executed by the software.

OS-level examples include the Unix chroot jail, AppArmor, and SELinux. In general, managed code may provide some protection. For example, java.io.FilePermission in the Java SecurityManager allows the software to specify restrictions on file operations.

This may not be a feasible solution, and it only limits the impact to the operating system; the rest of the application may still be subject to compromise.

Be careful to avoid CWE-243 and other weaknesses related to jails.

*Effectiveness: Limited*. The effectiveness of this mitigation depends on the prevention capabilities of the specific sandbox or jail being used and might only help to reduce the scope of an attack, such as restricting the attacker to certain system calls or limiting the portion of the file system that can be accessed.

### Detection methods

**Dynamic Analysis with Automated Results Interpretation** (effectiveness: SOAR Partial)

According to SOAR [REF-1479], the following detection techniques may be useful:

Cost effective for partial coverage:
- Web Application Scanner
- Web Services Scanner
- Database Scanners

**Dynamic Analysis with Manual Results Interpretation** (effectiveness: SOAR Partial)

According to SOAR [REF-1479], the following detection techniques may be useful:

Cost effective for partial coverage:
- Fuzz Tester
- Framework-based Fuzzer

**Manual Static Analysis - Source Code** (effectiveness: High)

According to SOAR [REF-1479], the following detection techniques may be useful:

Highly cost effective:
- Focused Manual Spotcheck - Focused manual analysis of source
- Manual Source Code Review (not inspections)

**Automated Static Analysis - Source Code** (effectiveness: High)

According to SOAR [REF-1479], the following detection techniques may be useful:

Highly cost effective:
- Source code Weakness Analyzer
- Context-configured Source Code Weakness Analyzer

**Architecture or Design Review** (effectiveness: High)

According to SOAR [REF-1479], the following detection techniques may be useful:

Highly cost effective:
- Formal Methods / Correct-By-Construction

Cost effective for partial coverage:
- Inspection (IEEE 1028 standard) (can apply to requirements, design, source code, etc.)

### Demonstrative examples

**Example 1**

The following code intends to allow a user to upload a picture to the web server. The HTML code that drives the form on the user end has an input field of type "file".

*Good code (HTML):*

```html
<form action="upload_picture.php" method="post" enctype="multipart/form-data">
Choose a file to upload:
<input type="file" name="filename"/>
<br/>
<input type="submit" name="submit" value="Submit"/>
</form>
```

Once submitted, the form above sends the file to upload_picture.php on the web server. PHP stores the file in a temporary location until it is retrieved (or discarded) by the server side code. In this example, the file is moved to a more permanent pictures/ directory.

*Bad code (PHP):*

```php
// Define the target location where the picture being
// uploaded is going to be saved.
$target = "pictures/" . basename($_FILES['uploadedfile']['name']);
// Move the uploaded file to the new location.
if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target))
{
    echo "The picture has been successfully uploaded.";
}
else
{
    echo "There was an error uploading the picture, please try again.";
}
```

The problem with the above code is that there is no check regarding type of file being uploaded. Assuming that pictures/ is available in the web document root, an attacker could upload a file with the name:

*Attack code:*

```
malicious.php
```

Since this filename ends in ".php" it can be executed by the web server. In the contents of this uploaded file, the attacker could use:

*Attack code (PHP):*

```php
<?php
    system($_GET['cmd']);
?>
```

Once this file has been installed, the attacker can enter arbitrary commands to execute using a URL such as:

*Attack code:*

```
http://server.example.com/upload_dir/malicious.php?cmd=ls%20-l
```

which runs the "ls -l" command - or any other type of command that the attacker wants to specify.

**Example 2**

The following code demonstrates the unrestricted upload of a file with a Java servlet and a path traversal vulnerability. The action attribute of an HTML form is sending the upload file request to the Java servlet.

*Good code (HTML):*

```html
<form action="FileUploadServlet" method="post" enctype="multipart/form-data">
Choose a file to upload:
<input type="file" name="filename"/>
<br/>
<input type="submit" name="submit" value="Submit"/>
</form>
```

When submitted the Java servlet's doPost method will receive the request, extract the name of the file from the Http request header, read the file contents from the request and output the file to the local upload directory.

*Bad code (Java):*

```java
public class FileUploadServlet extends HttpServlet {
    ...
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        String contentType = request.getContentType();
        // the starting position of the boundary header
        int ind = contentType.indexOf("boundary=");
        String boundary = contentType.substring(ind+9);
        String pLine = new String();
        String uploadLocation = new String(UPLOAD_DIRECTORY_STRING); //Constant value
        // verify that content type is multipart form data
        if (contentType != null && contentType.indexOf("multipart/form-data") != -1) {
            // extract the filename from the Http header
            BufferedReader br = new BufferedReader(new InputStreamReader(request.getInputStream()));
            ...
            pLine = br.readLine();
            String filename = pLine.substring(pLine.lastIndexOf("\\"), pLine.lastIndexOf("\""));
            ...
            // output the file to the local upload directory
            try {
                BufferedWriter bw = new BufferedWriter(new FileWriter(uploadLocation+filename, true));
                for (String line; (line=br.readLine())!=null; ) {
                    if (line.indexOf(boundary) == -1) {
                        bw.write(line);
                        bw.newLine();
                        bw.flush();
                    }
                } //end of for loop
                bw.close();
            } catch (IOException ex) {...}
            // output successful upload response HTML page
        }
        // output unsuccessful upload response HTML page
        else
        {...}
    }
        ...
}
```

This code does not perform a check on the type of the file being uploaded (CWE-434). This could allow an attacker to upload any executable file or other file with malicious code.

Additionally, the creation of the BufferedWriter object is subject to relative path traversal (CWE-23). Since the code does not check the filename that is provided in the header, an attacker can use "../" sequences to write to files outside of the intended directory. Depending on the executing environment, the attacker may be able to specify arbitrary files to write to, leading to a wide variety of consequences, from code execution, XSS (CWE-79), or system crash.

### Observed examples (real vulnerabilities)

| Reference | Description |
|---|---|
| [CVE-2023-5227](https://www.cve.org/CVERecord?id=CVE-2023-5227) | PHP-based FAQ management app does not check the MIME type for uploaded images |
| [CVE-2001-0901](https://www.cve.org/CVERecord?id=CVE-2001-0901) | Web-based mail product stores ".shtml" attachments that could contain SSI |
| [CVE-2002-1841](https://www.cve.org/CVERecord?id=CVE-2002-1841) | PHP upload does not restrict file types |
| [CVE-2005-1868](https://www.cve.org/CVERecord?id=CVE-2005-1868) | upload and execution of .php file |
| [CVE-2005-1881](https://www.cve.org/CVERecord?id=CVE-2005-1881) | upload file with dangerous extension |
| [CVE-2005-0254](https://www.cve.org/CVERecord?id=CVE-2005-0254) | program does not restrict file types |
| [CVE-2004-2262](https://www.cve.org/CVERecord?id=CVE-2004-2262) | improper type checking of uploaded files |
| [CVE-2006-4558](https://www.cve.org/CVERecord?id=CVE-2006-4558) | Double "php" extension leaves an active php extension in the generated filename. |
| [CVE-2006-6994](https://www.cve.org/CVERecord?id=CVE-2006-6994) | Chain: ASP program allows upload of .asp files (CWE-434) by bypassing client-side checks (CWE-601. |
| [CVE-2005-3288](https://www.cve.org/CVERecord?id=CVE-2005-3288) | ASP file upload |
| [CVE-2006-2428](https://www.cve.org/CVERecord?id=CVE-2006-2428) | ASP file upload |

### Relationships

Includes relationships recorded on this entry and those recorded on other entries that point to it (as MITRE's page shows them).

| Nature | CWE | Name | View | Recorded on |
|---|---|---|---|---|
| ChildOf (primary) | CWE-669 | Incorrect Resource Transfer Between Spheres | 1000 Complete Weakness Hierarchy | this entry |
| ChildOf (primary) | CWE-669 | Incorrect Resource Transfer Between Spheres | 1003 Weaknesses for Simplified Mapping of Published Vulnerabilities | this entry |
| PeerOf | CWE-351 | Insufficient Type Distinction | 1000 Complete Weakness Hierarchy | this entry |
| PeerOf | CWE-430 | Deployment of Wrong Handler | 1000 Complete Weakness Hierarchy | this entry |
| PeerOf | CWE-436 | Interpretation Conflict | 1000 Complete Weakness Hierarchy | this entry |
| PeerOf | CWE-646 | Reliance on File Name or Extension of Externally-Supplied File | 1000 Complete Weakness Hierarchy | CWE-646 |
| CanFollow | CWE-73 | External Control of File Name or Path | 1000 Complete Weakness Hierarchy | CWE-73 |
| CanFollow | CWE-183 | Permissive List of Allowed Inputs | 1000 Complete Weakness Hierarchy | CWE-183 |
| CanFollow | CWE-184 | Incomplete List of Disallowed Inputs | 1000 Complete Weakness Hierarchy | CWE-184 |

### Related attack patterns (CAPEC)

[CAPEC-1](https://capec.mitre.org/data/definitions/1.html)

### Taxonomy mappings

| Taxonomy | Entry ID | Entry name | Fit |
|---|---|---|---|
| PLOVER |  | Unrestricted File Upload |  |
| OWASP Top Ten 2007 | A3 | Malicious File Execution | CWE More Specific |
| OMG ASCSM | ASCSM-CWE-434 |  |  |

### Vulnerability mapping notes

**Usage:** Allowed

**Rationale:** This CWE entry is at the Base level of abstraction, which is a preferred level of abstraction for mapping to the root causes of vulnerabilities.

**Comments:** Carefully read both the name and description to ensure that this mapping is an appropriate fit. Do not try to 'force' a mapping to a lower-level Base/Variant simply to comply with this preferred level of abstraction.

**Reasons:** Acceptable-Use

### Notes

**Relationship:** This can have a chaining relationship with incomplete denylist / permissive allowlist errors when the product tries, but fails, to properly limit which types of files are allowed (CWE-183, CWE-184).

This can also overlap multiple interpretation errors for intermediaries, e.g. anti-virus products that do not remove or quarantine attachments with certain file extensions that can be processed by client systems.

### Memberships

Categories and views this entry belongs to (for example OWASP Top Ten and earlier CWE Top 25 lists).

| Type | ID | Name |
|---|---|---|
| Category | 429 | Handler Errors |
| Category | 714 | OWASP Top Ten 2007 Category A3 - Malicious File Execution |
| Category | 801 | 2010 Top 25 - Insecure Interaction Between Components |
| Category | 813 | OWASP Top Ten 2010 Category A4 - Insecure Direct Object References |
| Category | 864 | 2011 Top 25 - Insecure Interaction Between Components |
| View | 884 | CWE Cross-section |
| Category | 1011 | Authorize Actors |
| Category | 1131 | CISQ Quality Measures (2016) - Security |
| View | 1200 | Weaknesses in the 2019 CWE Top 25 Most Dangerous Software Errors |
| Category | 1308 | CISQ Quality Measures - Security |
| View | 1337 | Weaknesses in the 2021 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1340 | CISQ Data Protection Measures |
| Category | 1348 | OWASP Top Ten 2021 Category A04:2021 - Insecure Design |
| View | 1350 | Weaknesses in the 2020 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1364 | ICS Communications: Zone Boundary Failures |
| View | 1387 | Weaknesses in the 2022 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1416 | Comprehensive Categorization: Resource Lifecycle Management |
| View | 1425 | Weaknesses in the 2023 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1430 | Weaknesses in the 2024 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1435 | Weaknesses in the 2025 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1441 | OWASP Top Ten 2025 Category A06:2025 - Insecure Design |
| Category | 1447 | General Software Weaknesses that Appear in Products that Use or Support AI/ML Technology |

### References

- [REF-422] Richard Stanway (r1CH). "Dynamic File Uploads, Security and You". https://web.archive.org/web/20090208005456/http://shsc.info/FileUploadSecurity
- [REF-423] Johannes Ullrich. "8 Basic Rules to Implement Secure File Uploads", 2009. https://www.sans.org/blog/8-basic-rules-to-implement-secure-file-uploads/
- [REF-424] Johannes Ullrich. "Top 25 Series - Rank 8 - Unrestricted Upload of Dangerous File Type", 2010. https://www.sans.org/blog/top-25-series-rank-8-unrestricted-upload-of-dangerous-file-type/
- [REF-76] Sean Barnum, Michael Gegick. "Least Privilege", 2005. https://web.archive.org/web/20211209014121/https://www.cisa.gov/uscert/bsi/articles/knowledge/principles/least-privilege
- [REF-62] Mark Dowd, John McDonald, Justin Schuh. "The Art of Software Security Assessment", 2006, Chapter 17, "File Uploading", Page 1068
- [REF-962] Object Management Group (OMG). "Automated Source Code Security Measure (ASCSM)", 2016, ASCSM-CWE-434. http://www.omg.org/spec/ASCSM/1.0/
- [REF-1479] Gregory Larsen, E. Kenneth Hong Fong, David A. Wheeler, Rama S. Moorthy. "State-of-the-Art Resources (SOAR) for Software Vulnerability Detection, Test, and Evaluation", 2014. https://www.ida.org/-/media/feature/publications/s/st/stateoftheart-resources-soar-for-software-vulnerability-detection-test-and-evaluation/p-5061.ashx
- [REF-1534] OMG. "Automated Technical Debt Measure, Version 2", 2024. https://www.omg.org/spec/ATDM2/1.0/PDF

### Content history (summary)

- Submitted: 2006-07-19 by PLOVER
- Modified 40 times; latest: 2026-10-28
- Previous names: "Unrestricted File Upload" (until 2010-02-16)
- Full history: https://cwe.mitre.org/data/definitions/434.html#Content_History

---

*Part 2 is taken from the MITRE CWE List, version 5.0 (2026-10-28), https://cwe.mitre.org. Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation. Used under the CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html). Part 1 was written for the Providus Bank Secure Coding programme by Training Heights.*
