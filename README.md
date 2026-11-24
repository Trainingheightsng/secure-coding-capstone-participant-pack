# Capstone project: build a Claude security reviewer for Providus code

**Providus Bank · Secure Coding and AI-Assisted Software Development · Training Heights**

---

## 1. What you are building

By the end of today, any Providus developer should be able to give Claude some code and ask *"Is this safe?"*. Claude will then check it for all 25 dangerous mistakes from MITRE's 2025 CWE Top 25, the ones you studied on Days 2 and 3, and report exactly what it finds.

You will do this by building a **skill**. A skill is a small folder of instructions that you install in Claude. Think of it as training a new staff member to check code:

| The new staff member needs… | In your skill this is… | Who makes it |
|---|---|---|
| A textbook on the 25 mistakes | The 25 **reference files** in `references/` | Already done. They are in your pack. |
| Work instructions: what to check, in what order, how to report | **SKILL.md** | Your team writes it today |
| A quick checklist to work through | **checklist.md** | Your team writes it today |
| Practice on work where the answers are known | The **test files** in `tests/` | Already done. They are in your pack. |

Each team builds **its own skill** for its own code:

- **Backend team** (Java and C#) builds `cwe-top25-backend`
- **Frontend team** (React and Node.js/Next.js) builds `cwe-top25-frontend`

At the end, the two skills are tested on the same kind of code and presented to the class.

---

## 2. Your team and who does what

There are two teams of five. Every member owns **five** of the 25 weaknesses. One member is also the **team lead**.

| Member | Topic | Your five CWEs |
|---|---|---|
| **1** | Injection | 79 Cross-site scripting · 89 SQL injection · 78 OS command injection · 77 Command injection · 94 Code injection |
| **2** | Access control | 862 Missing authorization · 863 Incorrect authorization · 284 Improper access control · 639 Authorization bypass through user-controlled key (IDOR) · 306 Missing authentication |
| **3** | Input, files and requests | 20 Improper input validation · 22 Path traversal · 434 Dangerous file upload · 918 Server-side request forgery (SSRF) · 352 Cross-site request forgery (CSRF) |
| **4** (team lead) | Memory: buffers | 787 Out-of-bounds write · 125 Out-of-bounds read · 120 Classic buffer overflow · 121 Stack-based overflow · 122 Heap-based overflow |
| **5** | Memory, data and resources | 416 Use after free · 476 NULL pointer dereference · 502 Deserialization · 200 Sensitive information exposure · 770 No resource limits |

**Why member 4 is the team lead:** buffer-overflow mistakes are rare in Java, C# and React code, so member 4 has the lightest review work and the most time for the lead's jobs.

**The team lead's extra jobs:**

1. Writes **SKILL.md** and **checklist.md**, with input from everyone (Step 2).
2. Collects the five members' improved reference files into the skill folder.
3. Packages and installs the skill, and keeps the team's scoring sheet.

**A note for the frontend team.** Your stack is React in the browser *and* the Node.js/Next.js code behind it. Many of the 25 mistakes (SQL injection, command injection, SSRF, file upload) happen in that server code, not in the React components, so look there too. Buffer overflows (120, 121, 122) and use after free (416) can only happen in WebAssembly or native Node modules; member 4 and member 5 focus on those.

---

## 3. What is in your pack

```
capstone-participant-pack/
├── README.md                  ← this file
├── references/                ← the 25 reference files (the textbook)
├── templates/
│   ├── SKILL-template.md      ← fill-in-the-blanks starting point for SKILL.md
│   └── scoring-sheet.csv      ← record your test results here
└── tests/
    ├── backend/               ← test code for the backend team (Java and C#)
    └── frontend/              ← test code for the frontend team (React and Node.js)
```

**About each reference file.** Every file has two parts:

- **Part 1, review guide:** what the mistake is in plain words; how to spot it in Java, C# and React/Node; safe code that looks similar but isn't a problem; how to tell it apart from similar mistakes; bad and fixed code; how to check a fix; and how serious it is for a bank. **This is the part you will improve.**
- **Part 2, MITRE's complete entry:** the official description, all mitigations, real-world examples and so on. **Don't change Part 2.**

**About the test files.** The backend folder has 55 files (Java and C#) and the frontend folder has 28 (React and Node.js). Most contain one deliberately planted mistake; a few contain several (one of those was written by an AI assistant); and some contain no mistake at all, to check your skill doesn't raise false alarms. The frontend set has no tests for 120, 121 and 122, because those buffer overflows can't occur in React or Node.js code. The file names (B01, B02 … and F01, F02 …) don't tell you what is wrong. Your trainer holds the answer key and reveals it only after you have run your tests. **Don't open the test files to look for the answers yourself**: the point is to see what *your skill* finds.

---

## 4. Step by step

### Step 1: Set up your skill folder (30 minutes, team lead with everyone watching)

1. Make a folder named exactly after your skill:
   - backend: `cwe-top25-backend`
   - frontend: `cwe-top25-frontend`
2. Copy the `references/` folder into it.
3. Copy `templates/SKILL-template.md` into it and rename it **`SKILL.md`**.
4. Create an empty file named **`checklist.md`**.

Your folder should look like this:

```
cwe-top25-backend/
├── SKILL.md
├── checklist.md
└── references/   (25 files)
```

**Done when:** the folder has the right name and the three items above.

---

### Step 2: Write the work instructions (1 hour 30 minutes, team lead, with input from everyone)

SKILL.md tells Claude **when** to act as the reviewer and **how** to do the review. Open the template; it explains each section. You can ask Claude to draft it, then improve the draft together.

**What to say to Claude** (attach the 25 reference files, and fill in the parts in brackets):

> I'm building a Claude skill called [cwe-top25-backend / cwe-top25-frontend] for Providus Bank developers who write [Java Spring Boot and C# .NET / React and Next.js]. It must review code for the 25 weaknesses in the attached reference files. Using the attached template, write SKILL.md. The description must be under 200 characters and must make the skill switch on when someone asks for a code review, a pull-request review, a security check, or "is this code safe?". The workflow must say: check every item on checklist.md, every time; for anything suspicious, open the matching reference file and read Part 1 first; report every finding with the CWE number, the line numbers, the severity, why it's dangerous, and the fixed code. Then write checklist.md: one yes/no question for each of the 25 CWEs, based on each file's "How to spot it" section for our languages.

Then check the draft as a team:

- [ ] The `name` at the top is exactly the folder name.
- [ ] The description is **under 200 characters** (count them) and says *when* to use the skill.
- [ ] The workflow says to check **all 25** every time, not stop at the first problem.
- [ ] Every reference file name in SKILL.md's list matches a real file in `references/`.
- [ ] The report format asks for line numbers (without them, the finding can't be checked).
- [ ] checklist.md has exactly 25 questions, written for your languages.

**Done when:** all six boxes are ticked.

---

### Step 3: Make your five reference files fit Providus (1 hour 30 minutes, every member, at the same time as Step 2)

Open your five reference files. **Work only on Part 1, and only on the sections for your team's languages**: Java and C# for backend, React / Node.js for frontend.

For each file, check and improve:

1. **"How to spot it":** does it describe how the mistake would look in *Providus* code? Add the frameworks, internal libraries and coding habits your team actually uses. This is the most important section, because it is what Claude compares the code against.
2. **"Not this weakness":** add safe code from your own experience that could be mistaken for this mistake. This stops false alarms.
3. **The code examples:** would they compile on our versions? Does the fixed version really remove the problem?
4. **"Severity guide":** does it match how Providus rates risk?

**What to say to Claude** (attach your five files):

> These are reference files for CWE-[your five numbers] in a code-review skill. Our team writes [Spring Boot 3 and .NET 8 / React 18 and Next.js 14] and uses [list your main libraries, for example Spring Data JPA, Entity Framework Core, Prisma, NextAuth]. Review Part 1 only, for [Java and C# / React and Node.js]. Suggest additions to "How to spot it" and "Not this weakness" for our stack, check the code examples are correct for our versions, and point out anything unclear. Show each change as before and after. Don't change Part 2.

Read Claude's suggestions critically: **you** are the expert on Providus code. Accept only what is right, then save the file.

**Done when:** each of your five files has been reviewed and saved, and you've handed them to the team lead.

---

### Step 4: Test your skill (1 hour, whole team)

**4a. Install it (team lead).**
- **Claude.ai:** zip the skill folder itself, so that the ZIP contains `cwe-top25-backend/SKILL.md`, not `SKILL.md` on its own. Then go to **Settings › Capabilities › Skills**, upload the ZIP and switch it on.
- **Claude Code:** copy the folder into `~/.claude/skills/`.

**4b. Check it switches on by itself.** Open a **new chat**, attach one test file, and type, without mentioning the skill:

> Can you review this code before I merge it?

Claude should show that it's using your skill. If it doesn't, your description in SKILL.md needs better wording. Fix it, re-install and try again.

**4c. Run the tests.** Share out your team's test files: each member takes a batch of about 8. For each batch:

1. Open a **new chat** (so earlier answers don't influence later ones).
2. Attach the files.
3. Type exactly this, every time:

> Review each of these files for security vulnerabilities. For each file, list every finding with its line numbers.

4. In `scoring-sheet.csv`, write down for each file: the CWE(s) Claude reported, and the line numbers. If it found nothing, write "none".

**4d. Score it.** When every file has been tested, your trainer gives you the answer key. For each file:

| Result | Points |
|---|---|
| Found the right line **and** named the right CWE | 2 |
| Right line, wrong CWE (or right CWE, wrong line) | 1 |
| Missed it | 0 |
| A clean file (no planted mistake) where Claude reported a serious problem | minus 1 (a false alarm) |

Your **detection rate** is the number of planted mistakes found correctly, divided by the total. **Target: at least 90%, and no more than one false alarm.**

**Done when:** the scoring sheet is complete and you know your detection rate.

---

### Step 5: Improve and test again (45 minutes, whole team)

Look at every miss and every false alarm. Each one tells you which file to fix:

| What happened | What to fix |
|---|---|
| Claude missed the mistake completely | That CWE's **"How to spot it"**: add the exact pattern it missed |
| Right line, wrong CWE | Both CWEs' **"How to tell it apart"** sections |
| A false alarm on safe code | That CWE's **"Not this weakness"**: add the safe pattern |
| Claude stopped after finding one problem | **SKILL.md**: make the workflow insist on all 25 checks |
| The skill didn't switch on | The **description** in SKILL.md |

The owner of that CWE fixes the file. The team lead re-installs the skill. Then re-test **only the files that failed**, using the same prompt, and update the scoring sheet.

**What to say to Claude** to understand a miss (attach the reference file and the test file):

> My skill missed a problem in this file: line [number] has CWE-[number]. Here is the reference file for that CWE. Explain why the "How to spot it" section didn't catch it, and suggest the exact text to add.

**Done when:** you have a second score that is better than the first.

---

### Step 6: Package and present (1 hour)

**Package (team lead):** check the folder name matches the `name` in SKILL.md, zip the folder as in 4a, and name it with a version, for example `cwe-top25-backend-v1.0.zip`.

**Present (10 minutes per team):**

1. **What it does** (1 minute): in one sentence.
2. **One thing you improved** (2 minutes): show one change to a reference file, and the miss or false alarm it fixed.
3. **Your scores** (2 minutes): first round and second round, detection rate and false alarms.
4. **Live review** (4 minutes): run your skill on code your trainer has approved. For each finding, say honestly whether you think it is real.
5. **What you'd add next** (1 minute).

---

## 5. How your team is scored

| What | Points |
|---|---|
| Your reference-file improvements (useful, correct, written for your stack) | 30 |
| SKILL.md and checklist.md (complete, clear, all six boxes in Step 2 ticked) | 20 |
| Final detection rate and false alarms | 20 |
| Improvement from the first test round to the second | 10 |
| Presentation | 15 |
| The skill installs first time from your ZIP | 5 |

---

## 6. Rules

- **Never paste secrets, passwords, keys, connection strings or customer data into Claude**, not even for testing.
- Use real Providus code only if your trainer has approved it for the live demo.
- Don't edit Part 2 of the reference files (MITRE's text).
- Use a **new chat** for every test batch.
- Treat Claude's findings as suggestions to check, not as final answers. The skill helps you review; it does not replace your judgement.
