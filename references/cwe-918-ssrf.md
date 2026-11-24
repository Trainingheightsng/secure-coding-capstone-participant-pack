# CWE-918: Server-Side Request Forgery (SSRF)

> **2025 CWE Top 25:** rank 22 · score 3.36 · CVEs in CISA KEV: 0 · change since 2024: -3
>  
> **Name in MITRE CWE v5.0:** Server-Side Request Forgery

## Part 1: Review guide

### What it is, in plain words

The server fetches a URL the user supplies, so an attacker can make it call internal services or cloud metadata endpoints.

### How to spot it

**Java**
- `RestTemplate`/`WebClient`/`HttpClient` with a URL from the request
- Image/import-from-URL, webhook or PDF-from-URL features
- Following redirects to new hosts

**C#**
- `HttpClient.GetAsync(userUrl)`
- `WebRequest.Create(input)`
- Allow-lists checked before DNS resolution only (rebinding)

**React / Node.js**
- Next.js/Node `fetch(req.query.url)`
- Next.js image optimiser `remotePatterns` set to `**`
- Server-side previews of user links

### Not this weakness (safe look-alikes)

- Calls to fixed, configured hosts.
- User input limited to an ID that maps to a known URL.

### How to tell it apart from related weaknesses

The server making the request is CWE-918. Redirecting the user's browser is CWE-601 (open redirect, not in the Top 25).

### Vulnerable and secure examples

#### Java

Vulnerable:

```java
URI u = URI.create(req.logoUrl());
HttpResponse<byte[]> r = client.send(
  HttpRequest.newBuilder(u).build(),
  BodyHandlers.ofByteArray());
```

Why: Any URL, including internal addresses and cloud metadata.

Secure:

```java
URI u = URI.create(req.logoUrl());
if (!"https".equals(u.getScheme())
    || !ALLOWED_HOSTS.contains(u.getHost()))
  throw new IllegalArgumentException();
HttpClient c = HttpClient.newBuilder()
  .followRedirects(HttpClient.Redirect.NEVER)
  .build();
```

Why it works: Check scheme and host, and never follow redirects.

#### C#

Vulnerable:

```csharp
var bytes = await http.GetByteArrayAsync(
  req.LogoUrl);
```

Why: The same: our server fetches any address it’s given.

Secure:

```csharp
if (!Uri.TryCreate(req.LogoUrl, UriKind.Absolute,
      out var u) || u.Scheme != "https"
    || !AllowedHosts.Contains(u.Host))
  return BadRequest();
var http = new HttpClient(new HttpClientHandler
  { AllowAutoRedirect = false });
```

Why it works: Allow-list, HTTPS only, redirects off.

#### React / Node.js

*Context:* This is the server side of a React app: a Next.js route handler that fetches a logo for preview.

Vulnerable:

```jsx
export async function POST(req) {
  const { url } = await req.json();
  const img = await fetch(url);
  return new Response(img.body);
}
// url = http://169.254.169.254/latest/...
```

Why: The server fetches whatever it’s given and returns the response.

Secure:

```jsx
const u = new URL(url);
if (u.protocol !== "https:"
    || !ALLOWED_HOSTS.has(u.hostname))
  return new Response("Not allowed",
    { status: 400 });
const img = await fetch(u, { redirect: "error" });
```

Why it works: Allow-list hosts, HTTPS only, and no redirects.

### Fix guidance

**Primary defences**

1. **Allow-list destinations.** Known hosts, HTTPS only.
2. **No redirects.** Or re-check every hop.
3. **Lock down the network.** IMDSv2 and egress rules for fetchers.

**Defence in depth**

- Resolve DNS and block private ranges
- Don’t return raw responses
- Timeouts and size limits
- Log all outbound requests

**In each stack**

- Java: URI checks + Redirect.NEVER
- C#: TryCreate + AllowAutoRedirect off
- React / Node.js: new URL() + redirect: "error"

**Don't rely on**

- Block-lists of “bad” IPs
- Checking only the first URL
- The WAF alone

### How to verify the fix

Requests to 169.254.169.254, localhost and 10.x are refused.

### Severity guide (Providus)

Critical in cloud environments (metadata credentials) or where internal admin APIs are reachable; high otherwise.

---

## Part 2: MITRE CWE entry (complete)

**Abstraction:** Base · **Structure:** Simple · **Status:** Incomplete  
**MITRE page:** https://cwe.mitre.org/data/definitions/918.html
  
**MITRE diagram:** https://cwe.mitre.org/data/images/CWE-918-Diagram.png

### Description

The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.

### Alternate terms

- **XSPA**: Cross Site Port Attack
- **SSRF**: Server-Side Request Forgery

### Common consequences

| Scope | Impact | Likelihood | Note |
|---|---|---|---|
| Confidentiality | Read Application Data |  |  |
| Integrity | Execute Unauthorized Code or Commands |  |  |
| Access Control | Bypass Protection Mechanism |  | By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers from accessing the URLs directly. The server can be used as a proxy to conduct port scanning of hosts in internal networks, use other URLs such as that can access documents on the system (using file://), or use other protocols such as gopher:// or tftp://, which may provide greater control over the contents of requests. |

### Modes of introduction

- **Architecture and Design**
- **Implementation**

### Applicable platforms

- Language: Class: Not Language-Specific (Undetermined)
- Technology: Class: Web Based (Undetermined)
- Technology: AI/ML (Often)
- Technology: Web Server (Undetermined)

### Weakness ordinalities

- **Resultant**

### Potential mitigations

**1. Phase: Implementation, Operation**

If there is a known list of applications, IP, hostname, and/or domains to which the product is allowed to communicate, then use allowlists to ensure that outgoing requests are restricted to these known entities. The allowlists could be in the application code or possibly enforced by firewalls or network segmentation [REF-1511].

**2. Phase: Implementation, Operation**

If the product is expected to be able to connect to arbitrary IP addresses or domains, consider using a denylist that includes private network addresses, internal domain names, etc. The denylist could be in the application code or possibly enforced by firewalls or network segmentation [REF-1511].

*Effectiveness: Moderate*. While denylists can often be bypassed (see CWE-184), this might be the strongest option available.

**3. Phase: Implementation** · Strategy: Input Validation · ID: MIT-5

Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., use a list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications, or transform it into something that does.

When performing input validation, consider all potentially relevant properties, including length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to business rules. As an example of business rule logic, "boat" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if the input is only expected to contain colors such as "red" or "blue."

Do not rely exclusively on looking for malicious or malformed inputs. This is likely to miss at least one undesirable input, especially if the code's environment changes. This can give attackers enough room to bypass the intended validation. However, denylists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright.

When constructing outgoing requests from input strings, use stringent allowlists that limit the character set based on the expected value of the parameter in the request. This will indirectly limit the scope of an attack, but this technique is less important than proper output encoding and escaping.

### Detection methods

**Automated Static Analysis** (effectiveness: High)

Automated static analysis, commonly referred to as Static Application Security Testing (SAST), can find some instances of this weakness by analyzing source code (or binary/compiled code) without having to execute it. Typically, this is done by building a model of data flow and control flow, then searching for potentially-vulnerable patterns that connect "sources" (origins of input) with "sinks" (destinations where the data interacts with external components, a lower layer such as the OS, etc.)

### Demonstrative examples

**Example 1**

This code intends to receive a URL from a user, access the URL, and return the results to the user.

*Bad code (PHP):*

```php
$url = $_GET['url'];# User-controlled input
# Fetch the content of the provided URL
$response = file_get_contents($url);
echo $response;
```

The given PHP code is vulnerable to Server-Side Request Forgery (SSRF) because it directly accepts a user-supplied URL from the $_GET['url'] parameter and fetches its content using file_get_contents(), without any validation or restrictions. This allows an attacker to request internal or restricted resources within the server's network, such as internal admin panels, cloud metadata endpoints, or local services running on localhost.

*Good code (PHP):*

```php
# Define allowed URLs (or domains)
$allowed_urls = [
    'https://example.com/data.json',
    'https://api.example.com/info',
];
# Get the user-provided URL
$url = $_GET['url'] ?? '';
# Validate against allowed URLs
if (!in_array($url, $allowed_urls)) {
    http_response_code(400);
    echo "Invalid or unauthorized URL.";
    exit;
}
# Fetch content safely
$response = @file_get_contents($url);
if ($response === false) {
    http_response_code(500);
    echo "Failed to fetch content.";
    exit;
}
echo htmlspecialchars($response);# Escape output for safety
```

### Observed examples (real vulnerabilities)

| Reference | Description |
|---|---|
| [CVE-2026-33626](https://www.cve.org/CVERecord?id=CVE-2026-33626) | SSRF in LLM toolkit accesses arbitrary URLs for images, as exploited in the wild in April 2026 to conduct port scanning [REF-1519] |
| [CVE-2024-3095](https://www.cve.org/CVERecord?id=CVE-2024-3095) | SSRF in LLM application development framework because the URL retriever allows connections to local addresses using a crafted Location header |
| [CVE-2023-32786](https://www.cve.org/CVERecord?id=CVE-2023-32786) | Chain: LLM integration framework has prompt injection (CWE-1427) that allows an attacker to force the service to retrieve data from an arbitrary URL, essentially providing SSRF (CWE-918) and potentially injecting content into downstream tasks. |
| [CVE-2021-26855](https://www.cve.org/CVERecord?id=CVE-2021-26855) | Server Side Request Forgery (SSRF) in mail server, as exploited in the wild per CISA KEV. |
| [CVE-2021-21973](https://www.cve.org/CVERecord?id=CVE-2021-21973) | Server Side Request Forgery in cloud platform, as exploited in the wild per CISA KEV. |
| [CVE-2016-4029](https://www.cve.org/CVERecord?id=CVE-2016-4029) | Chain: incorrect validation of intended decimal-based IP address format (CWE-1286) enables parsing of octal or hexadecimal formats (CWE-1389), allowing bypass of an SSRF protection mechanism (CWE-918). |
| [CVE-2002-1484](https://www.cve.org/CVERecord?id=CVE-2002-1484) | Web server allows attackers to request a URL from another server, including other ports, which allows proxied scanning. |
| [CVE-2004-2061](https://www.cve.org/CVERecord?id=CVE-2004-2061) | CGI script accepts and retrieves incoming URLs. |
| [CVE-2010-1637](https://www.cve.org/CVERecord?id=CVE-2010-1637) | Web-based mail program allows internal network scanning using a modified POP3 port number. |
| [CVE-2009-0037](https://www.cve.org/CVERecord?id=CVE-2009-0037) | URL-downloading library automatically follows redirects to file:// and scp:// URLs |

### Relationships

Includes relationships recorded on this entry and those recorded on other entries that point to it (as MITRE's page shows them).

| Nature | CWE | Name | View | Recorded on |
|---|---|---|---|---|
| ChildOf (primary) | CWE-441 | Unintended Proxy or Intermediary | 1000 Complete Weakness Hierarchy | this entry |
| ChildOf (primary) | CWE-610 | Externally Controlled Reference to a Resource in Another Sphere | 1003 Weaknesses for Simplified Mapping of Published Vulnerabilities | this entry |

### Related attack patterns (CAPEC)

[CAPEC-664](https://capec.mitre.org/data/definitions/664.html)

### Vulnerability mapping notes

**Usage:** Allowed

**Rationale:** This CWE entry is at the Base level of abstraction, which is a preferred level of abstraction for mapping to the root causes of vulnerabilities.

**Comments:** Carefully read both the name and description to ensure that this mapping is an appropriate fit. Do not try to 'force' a mapping to a lower-level Base/Variant simply to comply with this preferred level of abstraction.

**Reasons:** Acceptable-Use

### Notes

**Relationship:** CWE-918 (SSRF) and CWE-611 (XXE) are closely related, because they both involve web-related technologies and can launch outbound requests to unexpected destinations. However, XXE can be performed client-side, or in other contexts in which the software is not acting directly as a server, so the "Server" portion of the SSRF acronym does not necessarily apply.

### Memberships

Categories and views this entry belongs to (for example OWASP Top Ten and earlier CWE Top 25 lists).

| Type | ID | Name |
|---|---|---|
| Category | 417 | Communication Channel Errors |
| View | 1337 | Weaknesses in the 2021 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1356 | OWASP Top Ten 2021 Category A10:2021 - Server-Side Request Forgery (SSRF) |
| View | 1387 | Weaknesses in the 2022 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1396 | Comprehensive Categorization: Access Control |
| View | 1425 | Weaknesses in the 2023 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1430 | Weaknesses in the 2024 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1435 | Weaknesses in the 2025 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1436 | OWASP Top Ten 2025 Category A01:2025 - Broken Access Control |
| Category | 1447 | General Software Weaknesses that Appear in Products that Use or Support AI/ML Technology |

### References

- [REF-913] Alexander Polyakov, Dmitry Chastukhin. "SSRF vs. Business-critical applications: XXE tunneling in SAP", 2012. https://media.blackhat.com/bh-us-12/Briefings/Polyakov/BH_US_12_Polyakov_SSRF_Business_Slides.pdf
- [REF-914] Alexander Polyakov, Dmitry Chastukhin, Alexey Tyurin. "SSRF vs. Business-critical Applications. Part 1: XXE Tunnelling in SAP NetWeaver". http://erpscan.com/wp-content/uploads/2012/08/SSRF-vs-Businness-critical-applications-whitepaper.pdf
- [REF-915] Riyaz Ahemed Walikar. "Cross Site Port Attacks - XSPA - Part 1", 2012. https://ibreak.software/2012/11/cross-site-port-attacks-xspa-part-1/
- [REF-916] Riyaz Ahemed Walikar. "Cross Site Port Attacks - XSPA - Part 2", 2012. https://ibreak.software/2012/11/cross-site-port-attacks-xspa-part-2/
- [REF-917] Riyaz Ahemed Walikar. "Cross Site Port Attacks - XSPA - Part 3", 2012. https://ibreak.software/2012/11/cross-site-port-attacks-xspa-part-3/
- [REF-918] Vladimir Vorontsov, Alexander Golovko. "SSRF attacks and sockets: smorgasbord of vulnerabilities". https://www.slideshare.net/DefconRussia/vorontsov-golovko-ssrf-attacks-and-sockets-smorgasbord-of-vulnerabilities
- [REF-919] ONsec Lab. "SSRF bible. Cheatsheet", 2013. https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit?pli=1#
- [REF-920] Deral Heiland. "Web Portals: Gateway To Information, Or A Hole In Our Perimeter Defenses", 2008. https://archive.org/details/Web_Portals_Gateway_to_Information_or_a_Hole_in_our_Perimeter_Defenses_Deral_Hei
- [REF-1511] OWASP. "Server-Side Request Forgery Prevention Cheat Sheet", 2019. https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- [REF-1519] Sysdig Threat Research Team. "CVE-2026-33626: How attackers exploited LMDeploy LLM Inference Engines in 12 hours", 2026. https://www.sysdig.com/blog/cve-2026-33626-how-attackers-exploited-lmdeploy-llm-inference-engines-in-12-hours

### Content history (summary)

- Submitted: 2013-02-17 by MITRE
- Modified 17 times; latest: 2026-10-28
- Previous names: "Server-Side Request Forgery (SSRF)" (until 2026-10-28)
- Full history: https://cwe.mitre.org/data/definitions/918.html#Content_History

---

*Part 2 is taken from the MITRE CWE List, version 5.0 (2026-10-28), https://cwe.mitre.org. Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation. Used under the CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html). Part 1 was written for the Providus Bank Secure Coding programme by Training Heights.*
