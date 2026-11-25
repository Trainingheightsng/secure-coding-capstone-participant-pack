# CWE Top 25 — Frontend security checklist (React / Next.js)

Work through every question for every file. Answer Yes or No. For any Yes, open the matching reference file, read Part 1, and report a finding.

---

## Injection

**CWE-79 · Cross-site Scripting**
Does any React component use `dangerouslySetInnerHTML` with a value that is not sanitised by DOMPurify, or does any code set `element.innerHTML`, `outerHTML`, `document.write`, or `insertAdjacentHTML` with user-controlled data, or is an `href`/`src` attribute set from input without blocking `javascript:` URLs, or does a Next.js page embed user data inside a `<script>` tag without escaping?

**CWE-89 · SQL Injection**
Does any Node.js or Next.js API route build a SQL string by concatenating or interpolating request parameters — for example `` pool.query(`...${req.query.id}`) `` or `knex.raw` with an interpolated value — or pass a sort/filter field from the request straight into SQL without an allow-list?

**CWE-78 · OS Command Injection**
Does any server-side code call `child_process.exec` or `execSync` with a template string that includes request data, or use `spawn` with `{ shell: true }` and user-supplied arguments?

**CWE-77 · Command Injection**
Does any server-side code call `execFile` or `spawn` (without a shell) and pass a user-supplied value that could start with `--` or `-`, for example a repository URL or file path passed to `git`, `curl`, or similar CLI tools?

**CWE-94 · Code Injection**
Does any code call `eval`, `new Function`, or `vm.runInContext` with a string derived from user input, or pass user data as a string argument to `setTimeout` or `setInterval`, or execute AI-generated code without a sandbox?

---

## Access control

**CWE-862 · Missing Authorization**
Does any Express or Next.js API route check that `req.user` exists but never check the user's role before performing a privileged action, or does a React component hide admin buttons with a client-side condition (`{isAdmin && <Button/>}`) without a matching server-side role check?

**CWE-863 · Incorrect Authorization**
Does any server-side route trust a role or permission value from `req.body`, `req.headers`, or the query string instead of reading it from the server-side session, or does an approval route fail to prevent a user from approving their own request?

**CWE-284 · Improper Access Control**
Does the application expose an admin panel, management route, or S3/Firebase storage with no server-side access control, or is a CORS policy configured with `credentials: true` and a wildcard or reflected `Origin`?

**CWE-639 · Authorization Bypass Through User-Controlled Key (IDOR)**
Does any API route fetch a record using an ID taken from `req.params` or `req.query` — for example `Statement.findByPk(req.params.id)` — without also filtering by the authenticated user's ID or checking ownership of the returned record?

**CWE-306 · Missing Authentication**
Does any Next.js API route handle sensitive operations (transfers, settings, data export) without checking the session at all, or does a webhook endpoint accept and act on requests without verifying a signature?

---

## Input, files and requests

**CWE-20 · Improper Input Validation**
Does any API route use `req.body` fields directly in business logic without first validating them against a server-side schema (zod, Joi, yup, or similar), or are `parseInt`/`Number` results used without checking for `NaN` or enforcing a valid range?

**CWE-22 · Path Traversal**
Does any code build a file path by joining a directory with a value from `req.query` or `req.params` — for example `path.join(dir, req.query.file)` — without resolving the absolute path and confirming it stays inside the allowed base directory?

**CWE-434 · Unrestricted Upload of Dangerous File Type**
Does any file upload handler (Multer `diskStorage` or Next.js route) keep the original file name, save to a folder inside `public/`, or validate the file type using only the client-supplied MIME type or the file extension without reading the file's magic bytes?

**CWE-918 · Server-Side Request Forgery (SSRF)**
Does any server-side code call `fetch`, `axios`, or another HTTP client with a URL taken from the request (`req.query.url`, `req.body.url`), or is the Next.js image optimiser `remotePatterns` set to `**` or an overly broad wildcard?

**CWE-352 · Cross-Site Request Forgery (CSRF)**
Does any Express or Next.js application use cookie-based sessions without a CSRF token on state-changing routes (POST, PUT, DELETE), or is the session cookie `sameSite` attribute set to `'none'` or left unset in an older stack?

---

## Memory: buffers (WebAssembly / native add-ons only)

**CWE-787 · Out-of-bounds Write**
Does any WebAssembly module receive data from JavaScript (via a `Uint8Array` view over `wasm.memory.buffer` or a function call) without checking that the data fits within the allocated block, or does any native Node add-on write into a buffer without a bounds check?

**CWE-125 · Out-of-bounds Read**
Does any code call `Buffer.allocUnsafe(n)` with `n` from user input and then send the buffer before it is fully overwritten, or does any WebAssembly module read from an offset derived from input without checking the offset stays within the module's memory?

**CWE-120 · Classic Buffer Overflow**
Is there a WebAssembly module compiled from C/C++ that copies user-supplied data using `strcpy`, `memcpy`, or similar functions without checking that the source fits in the destination buffer?

**CWE-121 · Stack-based Buffer Overflow**
Is there a WebAssembly module compiled from C/C++ that declares a fixed-size local array and copies user-supplied data into it without checking the length first?

**CWE-122 · Heap-based Buffer Overflow**
Is there a WebAssembly module that calls `malloc` with a size computed from user input (for example `count * itemSize`) without checking for integer overflow before allocating, and then writes `count * itemSize` bytes into the resulting buffer?

---

## Memory, data and resources

**CWE-416 · Use After Free**
Is there a WebAssembly module or native Node add-on that calls `free` on a pointer and then reads or writes through that pointer again, or does JavaScript code use a `detach`-ed or transferred `ArrayBuffer` after transfer?

**CWE-476 · NULL Pointer Dereference**
Does any server-side code access a property chain on a value that could be `null` or `undefined` — such as `req.user.profile.role` — without optional chaining or an explicit null check, or does a catch block treat a crash as success (effectively letting a null dereference open an authorisation gate)?

**CWE-502 · Deserialization of Untrusted Data**
Does any code call `node-serialize`'s `unserialize`, evaluate the output of `serialize-javascript` with `eval` or `new Function`, or pass untrusted input to a YAML loader that supports custom constructor types?

**CWE-200 · Sensitive Information Exposure**
Does any API route return a full database object (`res.json(user)`) that includes fields such as password hashes, BVNs, or internal flags, are secrets stored in `NEXT_PUBLIC_` or `VITE_` environment variables that end up in the client bundle, or are source maps published in production?

**CWE-770 · Allocation of Resources Without Limits or Throttling**
Is `express.json()` or any body parser configured without a size `limit`, is there an API route that accepts an unbounded `page`, `size`, or `limit` parameter, is `Promise.all` called over a user-supplied list of arbitrary length, or are sensitive routes (login, OTP, transfer) exposed without rate limiting?
