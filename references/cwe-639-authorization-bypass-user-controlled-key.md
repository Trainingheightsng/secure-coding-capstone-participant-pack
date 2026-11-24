# CWE-639: Authorization Bypass Through User-Controlled Key

> **2025 CWE Top 25:** rank 24 · score 2.62 · CVEs in CISA KEV: 0 · change since 2024: +6

## Part 1: Review guide

### What it is, in plain words

The code uses an ID from the request (account, statement, beneficiary) to fetch a record but never checks the record belongs to the caller, so changing the ID shows or changes someone else's data. Often called IDOR.

### How to spot it

**Java**
- `repo.findById(id)` with `id` from `@PathVariable`/`@RequestParam` and no owner comparison
- Queries by ID alone where the table has an owner or customer column
- Customer ID taken from the request instead of the authenticated principal

**C#**
- `_db.Accounts.Find(id)` / `FirstOrDefault(a => a.Id == id)` without `&& a.CustomerId == userId`
- `[FromRoute] customerId` trusted instead of `User.FindFirst(ClaimTypes.NameIdentifier)`

**React / Node.js**
- Node routes doing `Statement.findByPk(req.params.id)` with no ownership filter
- Front ends that hide other users' IDs, relying on the server never being called directly
- Sequential numeric IDs used as the only protection

### Not this weakness (safe look-alikes)

- Queries that filter by both ID and the authenticated owner (`findByIdAndCustomerId(id, me)`).
- Endpoints that take no ID at all and use the caller's identity (`/me/accounts`).
- Admin endpoints protected by a role check, where staff legitimately access any record.

### How to tell it apart from related weaknesses

The user chooses which record and the check on that record is missing: CWE-639. No role check for a function: CWE-862. A check that exists but is wrong: CWE-863.

### Vulnerable and secure examples

#### Java

Vulnerable:

```java
@GetMapping("/statements/{id}")
public Statement get(@PathVariable long id) {
    return statements.findById(id).orElseThrow();
}
```

Why: Changing the ID returns another customer's statement.

Secure:

```java
@GetMapping("/statements/{id}")
public Statement get(@PathVariable long id, Principal me) {
    return statements.findByIdAndCustomerId(id, customerId(me))
        .orElseThrow(NotFoundException::new);
}
```

Why it works: The query includes the owner from the session.

#### C#

Vulnerable:

```csharp
[HttpGet("beneficiaries/{id}")]
public Task<Beneficiary?> Get(long id) => _db.Beneficiaries.FindAsync(id).AsTask();
```

Why: Any ID works for any logged-in user.

Secure:

```csharp
[HttpGet("beneficiaries/{id}")]
public Task<Beneficiary?> Get(long id) =>
    _db.Beneficiaries.FirstOrDefaultAsync(b => b.Id == id && b.CustomerId == User.CustomerId());
```

Why it works: Owner check inside the query.

#### React / Node.js

Vulnerable:

```jsx
// app/api/accounts/[id]/route.js
export async function GET(req, { params }) {
  return Response.json(await db.account.findUnique({ where: { id: params.id } }));
}
```

Why: No ownership filter.

Secure:

```jsx
export async function GET(req, { params }) {
  const s = await auth();
  const acc = await db.account.findFirst({ where: { id: params.id, customerId: s.customerId } });
  return acc ? Response.json(acc) : new Response(null, { status: 404 });
}
```

Why it works: Filter by ID and the session's customer; 404 if not theirs.

### Fix guidance

**Primary defences**

1. Always scope queries by the authenticated owner (or check ownership explicitly)
2. Take the customer's identity from the session, never from the request
3. Return 404 for records the user doesn't own

**Defence in depth**

- Non-sequential IDs (UUIDs) as an extra layer, not the fix
- Automated tests that swap IDs between two test users
- Alert on many 404s from one user

### How to verify the fix

User A requesting user B's record ID receives 404 and no data.

### Severity guide (Providus)

Critical when it exposes or changes another customer's accounts, statements or beneficiaries.

---

## Part 2: MITRE CWE entry (complete)

**Abstraction:** Base · **Structure:** Simple · **Status:** Incomplete  
**MITRE page:** https://cwe.mitre.org/data/definitions/639.html

### Description

The system's authorization functionality does not prevent one user from gaining access to another user's data or record by modifying the key value identifying the data.

### Extended description

It is likely that an attacker would have to be an authenticated user in the system. However, the authorization process would not properly check the data access operation to ensure that the authenticated user performing the operation has sufficient entitlements to perform the requested data access, hence bypassing any other authorization checks present in the system.

For example, attackers can look at places where user specific data is retrieved (e.g. search screens) and determine whether the key for the item being looked up is controllable externally. The key may be a hidden field in the HTML form field, might be passed as a URL parameter or as an unencrypted cookie variable, then in each of these cases it will be possible to tamper with the key value.

### Alternate terms

- **Insecure Direct Object Reference / IDOR**: The "Insecure Direct Object Reference" term, as described in the OWASP Top Ten, is broader than this CWE because it also covers path traversal (CWE-22). Within the context of vulnerability theory, there is a similarity between the OWASP concept and CWE-706: Use of Incorrectly-Resolved Name or Reference.
- **Broken Object Level Authorization / BOLA**: BOLA is used in the 2019 OWASP API Security Top 10 and appears to have some overlap, but BOLA may be applicable to other weaknesses in addition to this one.
- **Horizontal Authorization**: "Horizontal Authorization" is used to describe situations in which two users have the same privilege level, but must be prevented from accessing each other's resources. This is fairly common when using key-based access to resources in a multi-user context.

### Common consequences

| Scope | Impact | Likelihood | Note |
|---|---|---|---|
| Access Control | Bypass Protection Mechanism |  | Access control checks for specific user data or functionality can be bypassed. |
| Access Control | Gain Privileges or Assume Identity |  | Horizontal escalation of privilege is possible (one user can view/modify information of another user). |
| Access Control | Gain Privileges or Assume Identity |  | Vertical escalation of privilege is possible if the user-controlled key is actually a flag that indicates administrator status, allowing the attacker to gain administrative access. |

### Likelihood of exploit

High

### Modes of introduction

- **Architecture and Design**: REALIZATION: This weakness is caused during implementation of an architectural security tactic.
- **Architecture and Design**: Retrieval of a user record occurs in the system based on some key value that is under user control. The key would typically identify a user-related record stored in the system and would be used to lookup that record for presentation to the user.
- **Implementation**: One manifestation of this weakness is when a system uses sequential or otherwise easily-guessable session IDs that would allow one user to easily switch to another user's session and read/modify their data.

### Applicable platforms

- Language: Class: Not Language-Specific (Undetermined)

### Weakness ordinalities

- **Primary**
- **Resultant**

### Potential mitigations

**1. Phase: Architecture and Design**

For each and every data access, ensure that the user has sufficient privilege to access the record that is being requested.

**2. Phase: Architecture and Design, Implementation**

Make sure that the key that is used in the lookup of a specific user's record is not controllable externally by the user or that any tampering can be detected.

**3. Phase: Architecture and Design**

Use encryption in order to make it more difficult to guess other legitimate values of the key or associate a digital signature with the key so that the server can verify that there has been no tampering.

### Detection methods

**Automated Static Analysis** (effectiveness: High)

Automated static analysis, commonly referred to as Static Application Security Testing (SAST), can find some instances of this weakness by analyzing source code (or binary/compiled code) without having to execute it. Typically, this is done by building a model of data flow and control flow, then searching for potentially-vulnerable patterns that connect "sources" (origins of input) with "sinks" (destinations where the data interacts with external components, a lower layer such as the OS, etc.)

### Demonstrative examples

**Example 1**

The following code uses a parameterized statement, which escapes metacharacters and prevents SQL injection vulnerabilities, to construct and execute a SQL query that searches for an invoice matching the specified identifier [1]. The identifier is selected from a list of all invoices associated with the current authenticated user.

*Bad code (C#):*

```csharp
...
conn = new SqlConnection(_ConnectionString);
conn.Open();
int16 id = System.Convert.ToInt16(invoiceID.Text);
SqlCommand query = new SqlCommand( "SELECT * FROM invoices WHERE id = @id", conn);
query.Parameters.AddWithValue("@id", id);
SqlDataReader objReader = objCommand.ExecuteReader();
...
```

The problem is that the developer has not considered all of the possible values of id. Although the interface generates a list of invoice identifiers that belong to the current user, an attacker can bypass this interface to request any desired invoice. Because the code in this example does not check to ensure that the user has permission to access the requested invoice, it will display any invoice, even if it does not belong to the current user.

### Observed examples (real vulnerabilities)

| Reference | Description |
|---|---|
| [CVE-2021-36539](https://www.cve.org/CVERecord?id=CVE-2021-36539) | An educational application does not appropriately restrict file IDs to a particular user. The attacker can brute-force guess IDs, indicating IDOR. |

### Relationships

Includes relationships recorded on this entry and those recorded on other entries that point to it (as MITRE's page shows them).

| Nature | CWE | Name | View | Recorded on |
|---|---|---|---|---|
| ChildOf (primary) | CWE-863 | Incorrect Authorization | 1000 Complete Weakness Hierarchy | this entry |
| ChildOf (primary) | CWE-863 | Incorrect Authorization | 1003 Weaknesses for Simplified Mapping of Published Vulnerabilities | this entry |
| ChildOf (primary) | CWE-284 | Improper Access Control | 1340 CISQ Data Protection Measures | this entry |
| ParentOf | CWE-566 | Authorization Bypass Through User-Controlled SQL Primary Key | 1000 Complete Weakness Hierarchy | CWE-566 |

### Vulnerability mapping notes

**Usage:** Allowed

**Rationale:** This CWE entry is at the Base level of abstraction, which is a preferred level of abstraction for mapping to the root causes of vulnerabilities.

**Comments:** Carefully read both the name and description to ensure that this mapping is an appropriate fit. Do not try to 'force' a mapping to a lower-level Base/Variant simply to comply with this preferred level of abstraction.

**Reasons:** Acceptable-Use

### Notes

**Maintenance:** As of CWE 4.20, the relationship between IDOR and BOLA needs to be investigated more closely, including research into how these terms are used in the industry. The CWE team suspects that IDOR can be a part of BOLA, but BOLA expands on the weakness inherent to IDOR in that it is not only about objects that are being directly referenced.

### Memberships

Categories and views this entry belongs to (for example OWASP Top Ten and earlier CWE Top 25 lists).

| Type | ID | Name |
|---|---|---|
| Category | 715 | OWASP Top Ten 2007 Category A4 - Insecure Direct Object Reference |
| Category | 723 | OWASP Top Ten 2004 Category A2 - Broken Access Control |
| Category | 813 | OWASP Top Ten 2010 Category A4 - Insecure Direct Object References |
| Category | 840 | Business Logic Errors |
| Category | 932 | OWASP Top Ten 2013 Category A4 - Insecure Direct Object References |
| Category | 945 | SFP Secondary Cluster: Insecure Resource Access |
| Category | 1011 | Authorize Actors |
| Category | 1031 | OWASP Top Ten 2017 Category A5 - Broken Access Control |
| Category | 1212 | Authorization Errors |
| Category | 1345 | OWASP Top Ten 2021 Category A01:2021 - Broken Access Control |
| Category | 1396 | Comprehensive Categorization: Access Control |
| View | 1435 | Weaknesses in the 2025 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1436 | OWASP Top Ten 2025 Category A01:2025 - Broken Access Control |

### References

- [REF-1496] OWASP. "Insecure Direct Object Reference Prevention Cheat Sheet", 2025. https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
- [REF-1497] MDN. "Insecure Direct Object Reference (IDOR)", 2025. https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/IDOR
- [REF-1498] Imperva. "Insecure Direct Object Reference". https://www.imperva.com/learn/application-security/insecure-direct-object-reference-idor/
- [REF-1521] Mateus Pantoja. "Unraveling Vulnerabilities: Understanding the difference between IDOR, BAC and BOLA", 2024. https://medium.com/@0ta/unraveling-vulnerabilities-understanding-the-difference-between-idor-bac-and-bola-0bc52cbc6dde

### Content history (summary)

- Submitted: 2008-01-30 by Cigital
- Modified 27 times; latest: 2026-10-28
- Previous names: "Access Control Bypass Through User-Controlled Key" (until 2011-03-29)
- Full history: https://cwe.mitre.org/data/definitions/639.html#Content_History

---

*Part 2 is taken from the MITRE CWE List, version 5.0 (2026-10-28), https://cwe.mitre.org. Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation. Used under the CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html). Part 1 was written for the Providus Bank Secure Coding programme by Training Heights.*
