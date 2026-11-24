# CWE-352: Cross-Site Request Forgery (CSRF)

> **2025 CWE Top 25:** rank 3 · score 13.64 · CVEs in CISA KEV: 0 · change since 2024: +1
>  
> **Name in MITRE CWE v5.0:** Cross-Site Request Forgery

## Part 1: Review guide

### What it is, in plain words

The server accepts a state-changing request because the browser sent a valid session cookie, without proving the user meant to send it. Another site can make the user's browser submit a transfer.

### How to spot it

**Java**
- `http.csrf(c -> c.disable())` (or `.csrf().disable()`) in a Spring Security config for an app that uses session cookies
- State changes on `GET` (`@GetMapping("/transfer")`)
- `csrf().ignoringRequestMatchers(...)` covering form or cookie-authenticated endpoints

**C#**
- MVC/Razor Pages POST actions with `[IgnoreAntiforgeryToken]`, or no `[ValidateAntiForgeryToken]`/global `AutoValidateAntiforgeryTokenAttribute`
- Minimal APIs taking form posts with `.DisableAntiforgery()` and cookie auth
- Cookies set with `SameSite=None` for the session

**React / Node.js**
- Express/Next.js with cookie sessions and no CSRF token check on POST/PUT/DELETE
- Session cookie `sameSite: 'none'` or unset in older stacks
- CORS `credentials: true` with a reflected or wildcard origin

### Not this weakness (safe look-alikes)

- APIs authenticated only with an `Authorization: Bearer` header (not cookies) are not CSRF-prone.
- Spring Security with CSRF left enabled (the default) for browser sessions.
- Cookie sessions with `SameSite=Lax` or `Strict` plus a CSRF token on state changes.

### How to tell it apart from related weaknesses

CSRF rides the victim's own credentials without running script. If script runs in the page, it is CWE-79. If the endpoint has no access check at all, that is CWE-862/306.

### Vulnerable and secure examples

#### Java

Vulnerable:

```java
@Bean SecurityFilterChain chain(HttpSecurity http) throws Exception {
    return http.csrf(c -> c.disable())            // cookie sessions
               .formLogin(Customizer.withDefaults()).build();
}
```

Why: With session cookies, any site can submit forms as the user.

Secure:

```java
@Bean SecurityFilterChain chain(HttpSecurity http) throws Exception {
    return http.csrf(Customizer.withDefaults())   // token required
               .formLogin(Customizer.withDefaults()).build();
}
```

Why it works: Spring's CSRF token is checked on every state-changing request.

#### C#

Vulnerable:

```csharp
[HttpPost, IgnoreAntiforgeryToken]
public IActionResult AddBeneficiary(BeneficiaryForm f) { ... }
```

Why: The anti-forgery check is switched off for a money-related action.

Secure:

```csharp
// Program.cs
builder.Services.AddControllersWithViews(o =>
    o.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()));
```

Why it works: Every unsafe method needs a valid anti-forgery token.

#### React / Node.js

Vulnerable:

```jsx
app.use(session({ cookie: { sameSite: "none", secure: true } }));
app.post("/api/transfer", requireLogin, doTransfer);
```

Why: Cookie sent on cross-site requests, no token check.

Secure:

```jsx
app.use(session({ cookie: { sameSite: "lax", secure: true, httpOnly: true } }));
app.post("/api/transfer", requireLogin, verifyCsrfToken, doTransfer);
```

Why it works: SameSite=Lax plus a token sent in a header by the React app.

### Fix guidance

**Primary defences**

1. Keep the framework's CSRF protection on for cookie-based sessions
2. Use SameSite=Lax or Strict session cookies
3. Never change state on GET

**Defence in depth**

- Re-authenticate or step-up (OTP) for transfers and beneficiary changes
- Check Origin/Referer on sensitive requests
- Avoid CORS with credentials and broad origins

### How to verify the fix

A form posted from another origin without the token is rejected with 403.

### Severity guide (Providus)

High for any money movement, profile, beneficiary or limit change; medium for low-impact settings.

---

## Part 2: MITRE CWE entry (complete)

**Abstraction:** Compound · **Structure:** Composite · **Status:** Stable  
**MITRE page:** https://cwe.mitre.org/data/definitions/352.html
  
**MITRE diagram:** https://cwe.mitre.org/data/images/CWE-352-Diagram.png

### Description

The web application does not, or cannot, sufficiently verify whether a request was intentionally provided by the user who sent the request, which could have originated from an unauthorized actor.

### Alternate terms

- **Session Riding**
- **Cross Site Reference Forgery**
- **XSRF**
- **CSRF**

### Common consequences

| Scope | Impact | Likelihood | Note |
|---|---|---|---|
| Confidentiality, Integrity, Availability, Non-Repudiation, Access Control | Gain Privileges or Assume Identity, Bypass Protection Mechanism, Read Application Data, Modify Application Data, DoS: Crash, Exit, or Restart |  | The consequences will vary depending on the nature of the functionality that is vulnerable to CSRF. An attacker could trick a client into making an unintentional request to the web server via a URL, image load, XmlHttpRequest, etc., which would then be treated as an authentic request from the client - effectively performing any operations as the victim, leading to an exposure of data, unintended code execution, etc. If the victim is an administrator or privileged user, the consequences may include obtaining complete control over the web application - deleting or stealing data, uninstalling the product, or using it to launch other attacks against all of the product's users. Because the attacker has the identity of the victim, the scope of CSRF is limited only by the victim's privileges. |

### Likelihood of exploit

Medium

### Modes of introduction

- **Architecture and Design**: REALIZATION: This weakness is caused during implementation of an architectural security tactic.

### Applicable platforms

- Language: Class: Not Language-Specific (Undetermined)
- Language: Go (Undetermined)
- Technology: Class: Web Based (Undetermined)
- Technology: Web Server (Undetermined)

### Weakness ordinalities

- **Primary**
- **Resultant**

### Potential mitigations

**1. Phase: Architecture and Design** · Strategy: Libraries or Frameworks · ID: MIT-4

Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid [REF-1482].

For example, use anti-CSRF packages such as the OWASP CSRFGuard. [REF-330]

Another example is the ESAPI Session Management control, which includes a component for CSRF. [REF-45]

**2. Phase: Implementation**

Ensure that the application is free of cross-site scripting issues (CWE-79), because most CSRF defenses can be bypassed using attacker-controlled script.

**3. Phase: Architecture and Design**

Generate a unique nonce for each form, place the nonce into the form, and verify the nonce upon receipt of the form. Be sure that the nonce is not predictable (CWE-330). [REF-332]

**4. Phase: Architecture and Design**

Identify especially dangerous operations. When the user performs a dangerous operation, send a separate confirmation request to ensure that the user intended to perform that operation.

**5. Phase: Architecture and Design**

Use the "double-submitted cookie" method as described by Felten and Zeller:

When a user visits a site, the site should generate a pseudorandom value and set it as a cookie on the user's machine. The site should require every form submission to include this value as a form value and also as a cookie value. When a POST request is sent to the site, the request should only be considered valid if the form value and the cookie value are the same.

Because of the same-origin policy, an attacker cannot read or modify the value stored in the cookie. To successfully submit a form on behalf of the user, the attacker would have to correctly guess the pseudorandom value. If the pseudorandom value is cryptographically strong, this will be prohibitively difficult.

This technique requires Javascript, so it may not work for browsers that have Javascript disabled. [REF-331]

**6. Phase: Architecture and Design**

Do not use the GET method for any request that triggers a state change.

**7. Phase: Implementation**

Check the HTTP Referer header to see if the request originated from an expected page. This could break legitimate functionality, because users or proxies may have disabled sending the Referer for privacy reasons.

### Detection methods

**Manual Analysis** (effectiveness: High)

This weakness can be detected using tools and techniques that require manual (human) analysis, such as penetration testing, threat modeling, and interactive tools that allow the tester to record and modify an active session.

Specifically, manual analysis can be useful for finding this weakness, and for minimizing false positives assuming an understanding of business logic. However, it might not achieve desired code coverage within limited time constraints. For black-box analysis, if credentials are not known for privileged accounts, then the most security-critical portions of the application may not receive sufficient attention.

Consider using OWASP CSRFTester to identify potential issues and aid in manual analysis.

*These may be more effective than strictly automated techniques. This is especially the case with weaknesses that are related to design and business rules.*

**Automated Static Analysis** (effectiveness: Limited)

CSRF is currently difficult to detect reliably using automated techniques. This is because each application has its own implicit security policy that dictates which requests can be influenced by an outsider and automatically performed on behalf of a user, versus which requests require strong confidence that the user intends to make the request. For example, a keyword search of the public portion of a web site is typically expected to be encoded within a link that can be launched automatically when the user clicks on the link.

**Automated Static Analysis - Binary or Bytecode** (effectiveness: SOAR Partial)

According to SOAR [REF-1479], the following detection techniques may be useful:

Cost effective for partial coverage:
- Bytecode Weakness Analysis - including disassembler + source code weakness analysis
- Binary Weakness Analysis - including disassembler + source code weakness analysis

**Manual Static Analysis - Binary or Bytecode** (effectiveness: SOAR Partial)

According to SOAR [REF-1479], the following detection techniques may be useful:

Cost effective for partial coverage:
- Binary / Bytecode disassembler - then use manual analysis for vulnerabilities & anomalies

**Dynamic Analysis with Automated Results Interpretation** (effectiveness: High)

According to SOAR [REF-1479], the following detection techniques may be useful:

Highly cost effective:
- Web Application Scanner

**Dynamic Analysis with Manual Results Interpretation** (effectiveness: High)

According to SOAR [REF-1479], the following detection techniques may be useful:

Highly cost effective:
- Fuzz Tester
- Framework-based Fuzzer

**Manual Static Analysis - Source Code** (effectiveness: SOAR Partial)

According to SOAR [REF-1479], the following detection techniques may be useful:

Cost effective for partial coverage:
- Focused Manual Spotcheck - Focused manual analysis of source
- Manual Source Code Review (not inspections)

**Automated Static Analysis - Source Code** (effectiveness: SOAR Partial)

According to SOAR [REF-1479], the following detection techniques may be useful:

Cost effective for partial coverage:
- Source code Weakness Analyzer
- Context-configured Source Code Weakness Analyzer

**Architecture or Design Review** (effectiveness: SOAR Partial)

According to SOAR [REF-1479], the following detection techniques may be useful:

Cost effective for partial coverage:
- Inspection (IEEE 1028 standard) (can apply to requirements, design, source code, etc.)
- Formal Methods / Correct-By-Construction

### Demonstrative examples

**Example 1**

This example PHP code attempts to secure the form submission process by validating that the user submitting the form has a valid session. A CSRF attack would not be prevented by this countermeasure because the attacker forges a request through the user's web browser in which a valid session already exists.

The following HTML is intended to allow a user to update a profile.

*Bad code (HTML):*

```html
<form action="/url/profile.php" method="post">
<input type="text" name="firstname"/>
<input type="text" name="lastname"/>
<br/>
<input type="text" name="email"/>
<input type="submit" name="submit" value="Update"/>
</form>
```

profile.php contains the following code.

*Bad code (PHP):*

```php
// initiate the session in order to validate sessions
session_start();
//if the session is registered to a valid user then allow update
if (! session_is_registered("username")) {
    echo "invalid session detected!";
    // Redirect user to login page
    [...]
    exit;
}
// The user session is valid, so process the request
// and update the information
update_profile();
function update_profile {
    // read in the data from $POST and send an update
    // to the database
    SendUpdateToDatabase($_SESSION['username'], $_POST['email']);
    [...]
    echo "Your profile has been successfully updated.";
}
```

This code may look protected since it checks for a valid session. However, CSRF attacks can be staged from virtually any tag or HTML construct, including image tags, links, embed or object tags, or other attributes that load background images.

The attacker can then host code that will silently change the username and email address of any user that visits the page while remaining logged in to the target web application. The code might be an innocent-looking web page such as:

*Attack code (HTML):*

```html
<SCRIPT>
function SendAttack () {
    form.email = "attacker@example.com";
    // send to profile.php
    form.submit();
}
</SCRIPT>
<BODY onload="javascript:SendAttack();">
<form action="http://victim.example.com/profile.php" id="form" method="post">
<input type="hidden" name="firstname" value="Funny">
<input type="hidden" name="lastname" value="Joke">
<br/>
<input type="hidden" name="email">
</form>
```

Notice how the form contains hidden fields, so when it is loaded into the browser, the user will not notice it. Because SendAttack() is defined in the body's onload attribute, it will be automatically called when the victim loads the web page.

Assuming that the user is already logged in to victim.example.com, profile.php will see that a valid user session has been established, then update the email address to the attacker's own address. At this stage, the user's identity has been compromised, and messages sent through this profile could be sent to the attacker's address.

### Observed examples (real vulnerabilities)

| Reference | Description |
|---|---|
| [CVE-2004-1703](https://www.cve.org/CVERecord?id=CVE-2004-1703) | Add user accounts via a URL in an img tag |
| [CVE-2004-1995](https://www.cve.org/CVERecord?id=CVE-2004-1995) | Add user accounts via a URL in an img tag |
| [CVE-2004-1967](https://www.cve.org/CVERecord?id=CVE-2004-1967) | Arbitrary code execution by specifying the code in a crafted img tag or URL |
| [CVE-2004-1842](https://www.cve.org/CVERecord?id=CVE-2004-1842) | Gain administrative privileges via a URL in an img tag |
| [CVE-2005-1947](https://www.cve.org/CVERecord?id=CVE-2005-1947) | Delete a victim's information via a URL or an img tag |
| [CVE-2005-2059](https://www.cve.org/CVERecord?id=CVE-2005-2059) | Change another user's settings via a URL or an img tag |
| [CVE-2005-1674](https://www.cve.org/CVERecord?id=CVE-2005-1674) | Perform actions as administrator via a URL or an img tag |
| [CVE-2009-3520](https://www.cve.org/CVERecord?id=CVE-2009-3520) | modify password for the administrator |
| [CVE-2009-3022](https://www.cve.org/CVERecord?id=CVE-2009-3022) | CMS allows modification of configuration via CSRF attack against the administrator |
| [CVE-2009-3759](https://www.cve.org/CVERecord?id=CVE-2009-3759) | web interface allows password changes or stopping a virtual machine via CSRF |

### Relationships

Includes relationships recorded on this entry and those recorded on other entries that point to it (as MITRE's page shows them).

| Nature | CWE | Name | View | Recorded on |
|---|---|---|---|---|
| ChildOf (primary) | CWE-345 | Insufficient Verification of Data Authenticity | 1000 Complete Weakness Hierarchy | this entry |
| ChildOf (primary) | CWE-345 | Insufficient Verification of Data Authenticity | 1003 Weaknesses for Simplified Mapping of Published Vulnerabilities | this entry |
| Requires | CWE-346 | Origin Validation Error | 1000 Complete Weakness Hierarchy | this entry |
| Requires | CWE-441 | Unintended Proxy or Intermediary | 1000 Complete Weakness Hierarchy | this entry |
| Requires | CWE-613 | DEPRECATED: Insufficient Session Expiration | 1000 Complete Weakness Hierarchy | this entry |
| Requires | CWE-642 | External Control of Critical State Data | 1000 Complete Weakness Hierarchy | this entry |
| PeerOf | CWE-79 | Improper Neutralization of Input During Web Page Generation | 1000 Complete Weakness Hierarchy | CWE-79 |
| CanFollow | CWE-1275 | Sensitive Cookie with Improper SameSite Attribute | 1000 Complete Weakness Hierarchy | CWE-1275 |

### Related attack patterns (CAPEC)

[CAPEC-111](https://capec.mitre.org/data/definitions/111.html), [CAPEC-462](https://capec.mitre.org/data/definitions/462.html), [CAPEC-467](https://capec.mitre.org/data/definitions/467.html), [CAPEC-62](https://capec.mitre.org/data/definitions/62.html)

### Taxonomy mappings

| Taxonomy | Entry ID | Entry name | Fit |
|---|---|---|---|
| PLOVER |  | Cross-Site Request Forgery (CSRF) |  |
| OWASP Top Ten 2007 | A5 | Cross Site Request Forgery (CSRF) | Exact |
| WASC | 9 | Cross-site Request Forgery |  |
| OWASP Golang Secure Coding Practices Guide |  | Cross-site Request Forgery |  |

### Vulnerability mapping notes

**Usage:** Allowed

**Rationale:** This is a well-known Composite of multiple weaknesses that must all occur simultaneously, although it is attack-oriented in nature.

**Comments:** While attack-oriented composites are supported in CWE, they have not been a focus of research. There is a chance that future research or CWE scope clarifications will change or deprecate them. Perform root-cause analysis to determine if other weaknesses allow CSRF attacks to occur, and map to those weaknesses. For example, predictable CSRF tokens might allow bypass of CSRF protection mechanisms; if this occurs, they might be better characterized as randomness/predictability weaknesses.

**Reasons:** Other

### Notes

**Relationship:** There can be a close relationship between XSS and CSRF (CWE-352). An attacker might use CSRF in order to trick the victim into submitting requests to the server in which the requests contain an XSS payload. A well-known example of this was the Samy worm on MySpace [REF-956]. The worm used XSS to insert malicious HTML sequences into a user's profile and add the attacker as a MySpace friend. MySpace friends of that victim would then execute the payload to modify their own profiles, causing the worm to propagate exponentially. Since the victims did not intentionally insert the malicious script themselves, CSRF was a root cause.

**Theoretical:** The CSRF topology is multi-channel:

- Attacker (as outsider) to intermediary (as user). The interaction point is either an external or internal channel.
- Intermediary (as user) to server (as victim). The activation point is an internal channel.

### Memberships

Categories and views this entry belongs to (for example OWASP Top Ten and earlier CWE Top 25 lists).

| Type | ID | Name |
|---|---|---|
| View | 635 | Weaknesses Originally Used by NVD from 2008 to 2016 |
| Category | 716 | OWASP Top Ten 2007 Category A5 - Cross Site Request Forgery (CSRF) |
| Category | 751 | 2009 Top 25 - Insecure Interaction Between Components |
| Category | 801 | 2010 Top 25 - Insecure Interaction Between Components |
| Category | 814 | OWASP Top Ten 2010 Category A5 - Cross-Site Request Forgery(CSRF) |
| Category | 864 | 2011 Top 25 - Insecure Interaction Between Components |
| View | 884 | CWE Cross-section |
| Category | 936 | OWASP Top Ten 2013 Category A8 - Cross-Site Request Forgery (CSRF) |
| Category | 1019 | Validate Inputs |
| View | 1200 | Weaknesses in the 2019 CWE Top 25 Most Dangerous Software Errors |
| View | 1337 | Weaknesses in the 2021 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1345 | OWASP Top Ten 2021 Category A01:2021 - Broken Access Control |
| View | 1350 | Weaknesses in the 2020 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1387 | Weaknesses in the 2022 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1411 | Comprehensive Categorization: Insufficient Verification of Data Authenticity |
| View | 1425 | Weaknesses in the 2023 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1430 | Weaknesses in the 2024 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1435 | Weaknesses in the 2025 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1436 | OWASP Top Ten 2025 Category A01:2025 - Broken Access Control |
| View | 1468 | Weaknesses Addressed by the OWASP Golang Secure Coding Practices Guide |

### References

- [REF-44] Michael Howard, David LeBlanc, John Viega. "24 Deadly Sins of Software Security", 2010, "Sin 2: Web-Server Related Vulnerabilities (XSS, XSRF, and
 Response Splitting)." Page 37
- [REF-329] Peter W. "Cross-Site Request Forgeries (Re: The Dangers of Allowing Users to Post Images)". https://marc.info/?l=bugtraq&m=99263135911884&w=2
- [REF-330] OWASP. "Cross-Site Request Forgery (CSRF) Prevention Cheat Sheet". https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- [REF-331] Edward W. Felten, William Zeller. "Cross-Site Request Forgeries: Exploitation and Prevention", 2008. https://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.147.1445
- [REF-332] Robert Auger. "CSRF - The Cross-Site Request Forgery (CSRF/XSRF) FAQ". https://www.cgisecurity.com/csrf-faq.html
- [REF-333] "Cross-site request forgery", 2008. https://en.wikipedia.org/wiki/Cross-site_request_forgery
- [REF-334] Jason Lam. "Top 25 Series - Rank 4 - Cross Site Request Forgery", 2010. https://www.sans.org/blog/top-25-series-rank-4-cross-site-request-forgery
- [REF-335] Jeff Atwood. "Preventing CSRF and XSRF Attacks", 2008. https://blog.codinghorror.com/preventing-csrf-and-xsrf-attacks/
- [REF-45] OWASP. "OWASP Enterprise Security API (ESAPI) Project". https://owasp.org/www-project-enterprise-security-api/
- [REF-956] Wikipedia. "Samy (computer worm)". https://en.wikipedia.org/wiki/Samy_(computer_worm)
- [REF-1479] Gregory Larsen, E. Kenneth Hong Fong, David A. Wheeler, Rama S. Moorthy. "State-of-the-Art Resources (SOAR) for Software Vulnerability Detection, Test, and Evaluation", 2014. https://www.ida.org/-/media/feature/publications/s/st/stateoftheart-resources-soar-for-software-vulnerability-detection-test-and-evaluation/p-5061.ashx
- [REF-1482] D3FEND. "D3FEND: D3-TL Trusted Library". https://d3fend.mitre.org/technique/d3f:TrustedLibrary/
- [REF-1566] OWASP. "Golang Secure Coding Practices guide", 2024, Cross-Site Request Forgery, page 71. https://github.com/OWASP/Go-SCP

### Content history (summary)

- Submitted: 2006-07-19 by PLOVER
- Modified 36 times; latest: 2026-10-28
- Previous names: "Cross-Site Request Forgery (CSRF)" (until 2026-10-28)
- Full history: https://cwe.mitre.org/data/definitions/352.html#Content_History

---

*Part 2 is taken from the MITRE CWE List, version 5.0 (2026-10-28), https://cwe.mitre.org. Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation. Used under the CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html). Part 1 was written for the Providus Bank Secure Coding programme by Training Heights.*
