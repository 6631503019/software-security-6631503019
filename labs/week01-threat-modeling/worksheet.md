# Worksheet 1 — Security Mindset & Threat Modeling (3 hrs)

> **Course:** Software Security (KOSEN69) · **Week 1**
> **Aligned to:** OWASP 2025 A06 Insecure Design · CWE-501 (Trust Boundary Violation)
> **Signature game:** "Elevation of Privilege" (Microsoft STRIDE card deck)

> **Ethics note:** This week is *modeling only* — you analyze design, you do **not** attack the app. Run the sample app only on your own VM/localhost. Never apply these techniques to systems you do not own or lack written permission to test.

## Part 1 — Student Information
| Name | Student ID | Date | Group |
|---|---|---|---|
|Nararat Kritphet | 6631503110 | 3/9/2569 | |

## Part 2 — Lecture Questions
Answer in your own words (2–4 sentences each).
1. Define the CIA triad and give one concrete failure example for each of the three properties.
2. What is a *trust boundary*, and why does data crossing one deserve extra scrutiny?
3. Explain "attack surface." Name two things that increase it in a web app.
4. What does each STRIDE letter map to, and which security property does each threat violate?
5. What does "Secure by Design" (CISA) mean, and how does it differ from bolting security on after release?

## Part 3 — Hands-on Lab (180 min)
**Learning goals:** build a data-flow diagram (DFD), apply STRIDE to a real Flask app, rank risks, and propose mitigations.
**Prerequisites:** Docker + Docker Compose in your VM; a drawing tool (draw.io / paper + photo); the Elevation of Privilege deck (print or virtual) — free print-and-play PDF at [github.com/adamshostack/eop](https://github.com/adamshostack/eop).

**Environment setup**
```bash
cd labs/week01-threat-modeling
docker compose up --build           # starts sample-app on http://localhost:8080
curl -s -X POST localhost:8080/notes -H 'Content-Type: application/json' \
     -d '{"owner":"alice","body":"hello"}'   # observe behavior, do not attack
curl -s localhost:8080/notes

echo "demo file" > demo.txt
curl -s -X POST localhost:8080/upload -F "file=@demo.txt"   # observe behavior, do not attack
curl -s localhost:8080/files/demo.txt
```

Source to model lives in `sample-app/app.py`. Template to fill: `THREAT-MODEL-TEMPLATE.md` (copy it, do not edit the original).

**What to submit per task:** the threat/element identified + a screenshot (DFD, table, or running app) + a 2–3 sentence mitigation.

**Task 0 — Onboarding (5 min)** · *Goal:* prove the environment works. *Steps:* `docker compose up`, hit `/notes` and `/files/<name>`, read `sample-app/app.py`. *Deliverable:* screenshot of the running app + the JSON response.

**Task 1 — Draw the DFD (25 min)** · *Goal:* map the system. *Steps:* identify the external entity (web client), the process (Flask app), the data store (`notes.db` SQLite), the `uploads/` store, and the flows for `/notes`, `/upload`, `/files/<name>`; mark the Internet→app trust boundary with a dashed line. *Deliverable:* DFD image embedded in your copy of the template.

[DFD](img/wk01.drawio.png)

**Task 2 — STRIDE the elements (30 min)** · *Goal:* enumerate threats per element. *Steps:* for each element fill the S/T/R/I/D/E grid. Ground it in real code: `/notes` accepts a client-supplied `owner` with no auth (Spoofing); `/upload` saves raw `f.filename` — arbitrary-file-write (Tampering) — and echoes the resolved save path back in its response (Information disclosure); `/files/<name>` reads it back but is comparatively defended (see Task 5); no logging anywhere (Repudiation). *Deliverable:* completed STRIDE table.

**Task 3 — Elevation of Privilege game (20 min)** · *Goal:* find threats you missed. *Steps:* play the EoP deck against your DFD; each card you can tie to a real element/flow scores a point; record every valid threat. No printer or scissors? Draw from the digital deck below instead — same 78 cards, same rule. *Deliverable:* list of carded threats + score.

```sim
eop-deck
```

**Task 3b — Systems-level pass (25 min) 🔭** · *Goal:* find what the per-element grid cannot see. Tasks 2 and 3 enumerate threats **one element at a time**, and that is exactly where threat models are known to stop short — students taught STRIDE alone reliably identify component threats and *discount system-level ones* ([Joshi et al., ASEE 2024](https://arxiv.org/abs/2404.16632)). So do a second pass over the **whole** diagram:
![Three trust zones — public internet, application tier, data tier — with the two boundaries a request crosses between them](img/trust-boundaries.svg)

- **Trust boundaries end-to-end.** Follow one request from the client to `notes.db` and back. List every boundary it crosses. Which crossing has no check on it?
- **Assume one element is fully owned.** Pick the Flask process, then the `uploads/` store. For each: what does the attacker now *reach* — not what is it, but where does it get them?
- **Chain two "low" findings.** Find two threats you or the EoP deck rated minor that combine into something you would not accept. Write the chain as `A → B → consequence`.
- **One-line system claim.** Finish: "Even if every element-level mitigation in Task 8 is implemented, this system still fails if ___."

Use the simulation below before you start — toggle a component to attacker-controlled and watch what it reaches:

```sim
trust-boundary
```

*Deliverable:* the boundary list, two owned-element reachability notes, one written chain, and the system claim.


**Trust boundaries end-to-end**

1. Web Client → Flask App: Internet → Application Tier
2. Flask App → `notes.db`: Application Tier → Data Tier
3. `notes.db` → Flask App: Data Tier → Application Tier
4. Flask App → Web Client: Application Tier → Internet

The Internet → Application Tier crossing does not have a consistent authorization check. Some endpoints require authentication, but authenticated users are not always checked for authorization to access a specific resource, such as `/api/notes/<nid>`.

**Owned-element reachability**

- **Flask process:** An attacker who fully controls the Flask process can reach the application's database and other resources available to the process. This includes reading or modifying `notes.db`, accessing application secrets such as `SECRET`, and potentially executing commands with the privileges of the container process.

- **`uploads/` store:** An attacker who controls the `uploads/` store can modify or replace files that the application may later serve through `/files/<name>`. This could allow the attacker to alter content delivered to users and potentially use the application as a path to distribute malicious files.

**Threat chain**

`Weak password hashing (MD5) → stolen/cracked credentials → unauthorized access to user accounts and notes`

**System claim**

Even if every element-level mitigation in Task 8 is implemented, this system still fails if authorization is not enforced consistently across trust boundaries and users can access resources that do not belong to them.

**Task 4 — Abuse cases & attacker personas (20 min)** · *Goal:* think like specific adversaries. *Steps:* define 2 personas (e.g. a curious logged-in user; an anonymous internet attacker) and write 2 abuse cases each against the sample app, tied to DFD elements. *Deliverable:* 4 abuse cases.

Persona 1: Malicious User
Abuse Case 1: Spoof another user's owner value through /notes.
Abuse Case 2: Upload many or very large files through /upload to exhaust server resources.

Persona 2: Anonymous Internet Attacker
Abuse Case 3: Use path traversal such as ../ in /upload to write files outside the uploads/ directory.
Abuse Case 4: Access uploaded files through /files/<name> without authentication or authorization.

**Task 5 — Path-traversal deep-dive (25 min)** · *Goal:* analyze the riskiest flow. *Steps:* trace `/upload` → `/files/<name>`; explain how `../` in a filename escapes `uploads/`; sketch the secure design (`secure_filename`, store outside web root, allow-list extensions). *Deliverable:* the data flow + secure-design note.

### Data flow

Web Client
  → POST /upload
  → Flask App
  → uploads/
  → GET /files/<name>
  → Web Client

The Web Client sends a file to the Flask App through /upload. The application uses the client-supplied filename when saving the file into uploads/. The file can later be accessed through /files/<name>.

### Path-traversal risk

The /upload endpoint directly uses the client-supplied filename when constructing the file path. A filename containing ../ can refer to a parent directory and escape the intended uploads/ directory, creating an arbitrary file-write/path-traversal risk.

### Secure design

Use secure_filename() to sanitize filenames and generate server-side filenames instead of trusting the original filename. Store uploaded files outside the web root and allow-list permitted file extensions.



**Task 6 — Threat-model the project target (30 min)** · *Goal:* kick off your term project. *Steps:* stop the sample-app first (`docker compose down` — both apps bind host port 8080), then run **NoteVault** (`cd ../../project/starter-app && docker compose up`), draw a quick DFD, and list the top 3 STRIDE threats you'd investigate. *Deliverable:* NoteVault DFD + top-3 threats (reuse these in your project report — `project/REPORT-TEMPLATE.md` in the repo root).

[DFD]

Top 3 STRIDE Threats:

1. Elevation of Privilege — /register
The registration endpoint accepts a client-controlled role value without authorization checks, allowing a user to potentially register with an elevated role.

2. Tampering / Elevation of Privilege — /login
The login endpoint builds an SQL query using user-controlled input, creating a SQL injection risk that could affect authentication and database integrity.

3. Tampering / Elevation of Privilege — /export
The export endpoint passes the user-controlled fmt parameter into a shell command with shell=True, creating a command-injection risk.

**Task 7 — Security requirements (15 min)** · *Goal:* turn threats into testable requirements. *Steps:* write 3 security requirements as acceptance criteria ("the system must … so that …"), each mapped to a threat from Task 2 or Task 6. *Deliverable:* 3 testable security requirements.

| # | Security Requirement                                                                                                                                                                       | Mapped Threat                        |
| - | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------ |
| 1 | **The system must assign the `user` role to every newly registered account by default and ignore any client-supplied role value, so that users cannot register with elevated privileges.** | Elevation of Privilege — `/register` |
| 2 | **The system must use parameterized SQL queries for all user-controlled input, so that malicious input cannot alter SQL statements or bypass authentication.**                             | SQL Injection — `/login`             |
| 3 | **The system must not pass user-controlled input directly to a shell command, so that requests cannot execute unintended operating-system commands.**                                      | Command Injection — `/export`        |


**Task 8 — Defend / fix it: rank & mitigate (25 min) 🛡️** · *Goal:* turn threats into action you can prove. *Steps:* rank the top 5 threats by likelihood × impact; propose one concrete mitigation each (e.g., auth on `/notes`, `secure_filename()` + allowlist for `/upload`, request logging for Repudiation, size/rate limits for DoS). Then **pick one and actually implement it** in your fork.

*Deliverable — the top-5 table, plus for the one you implemented:*
1. the **diff** (commit hash on your `wk01` branch),
2. **evidence it works**: the request that succeeded before your change and is refused after — both outputs,
3. **why it closes the class, not the instance** (2–3 sentences). `secure_filename()` on one endpoint is an instance fix; *"no user-supplied string ever becomes a path component"* is a class fix. Say which yours is, and if it's an instance fix, say what the class fix would be.

> **Why this is weighted.** Fewer than half of working developers can spot a security hole in code, and being shown vulnerabilities does not by itself teach you to find or close them. Exploiting is the half that feels like progress; defending is the half that transfers to your job.

| Rank | Threat                                     | Likelihood | Impact | Mitigation                                                                                                                                               |
| ---- | ------------------------------------------ | ---------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | **Command Injection — `/export`**          | High       | High   | Do not pass user-controlled input directly to a shell. Remove `shell=True` and use a safe implementation with an allow-list of permitted export formats. |
| 2    | **SQL Injection — `/login`**               | High       | High   | Use parameterized SQL queries instead of concatenating user-controlled input into the SQL statement.                                                     |
| 3    | **Elevation of Privilege — `/register`**   | High       | High   | Do not accept `role` from the client. Always assign the default `user` role during registration.                                                         |
| 4    | **Weak Password Hashing — user passwords** | High       | Medium | Replace MD5 password hashing with a password-hashing function designed for passwords, such as Argon2id, bcrypt, or scrypt.                               |
| 5    | **Information Disclosure — `/admin`**      | Medium     | High   | Restrict the admin endpoint to properly authenticated and authorized administrators and avoid exposing password hashes in the response.                  |

Implemented mitigation: SQL Injection in /login
Changed the login query from string concatenation to a parameterized SQL query.
Commit: 4106596 — Fix SQL injection in login
Branch: wk01

Diff
- q = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (
-     username, hashlib.md5((password or "").encode()).hexdigest())
- row = con.execute(q).fetchone()
+ password_hash = hashlib.md5((password or "").encode()).hexdigest()
+ q = "SELECT * FROM users WHERE username = ? AND password = ?"
+ row = con.execute(q, (username, password_hash)).fetchone()

Before the fix:
A normal login request using alice / alicepw succeeded and returned the authenticated NoteVault page.

After the fix:
A login request using ' as the username and wrong as the password was refused and returned "login failed".
[image](img/Screenshot%202026-09-03%20090015.png)
[image](img/Screenshot%202026-09-03%20090155.png)

This is a class-level fix because the SQL query no longer concatenates user-controlled input into the SQL statement. Parameterized queries treat user input as data rather than executable SQL syntax, preventing SQL injection through the login username or password fields. The same parameterized-query approach should be applied to all other database queries that use user-controlled input, such as /search.


## Part 4 — Reflection
1. Map your top finding to a CWE and to OWASP A06 (Insecure Design); explain the mapping in one sentence.

SQL Injection in /login maps to CWE-89 (Improper Neutralization of Special Elements used in an SQL Command) and OWASP A06 (Insecure Design) because the application design directly concatenates user-controlled input into an SQL query instead of treating it as data through parameterized queries.

2. Name one real-world breach caused by a design flaw (not a missing patch) and what design control would have prevented it.

The 2018 British Airways data breach was partly caused by weaknesses in the design of its web infrastructure that allowed attackers to redirect users to a malicious domain and capture payment information; stronger security controls around trusted domains and client-side data flows could have reduced this risk.

3. Of your five mitigations, which gives the most risk reduction per unit of effort, and why?

Parameterized SQL queries give the most risk reduction per unit of effort because they are relatively easy to implement and protect an entire class of SQL injection vulnerabilities wherever user-controlled input is used in SQL queries. This provides a strong security improvement without requiring major changes to the application's architecture.

## Grading rubric (100)
| Criterion | Points |
|---|---|
| Lecture questions (Part 2) | 20 |
| Exploitation + evidence (DFD + STRIDE table + EoP findings + screenshots) | 40 |
| Defense (top-5 ranking + mitigations) | 25 |
| Reflection (CWE/OWASP mapping + breach + best mitigation) | 15 |

**Assessed within the rows above** (they are not extra points — they are what those points are for):
- **Systems-level reasoning** (inside *Exploitation + evidence*, Task 3b): does the model reach past single elements to boundaries, reachability and chains? Scored with the STRIDE + systems-thinking rubrics of [Joshi et al. 2024](https://arxiv.org/abs/2404.16632).
- **Defensive proof** (inside *Defense*, Task 8): a claimed mitigation with no before/after evidence scores at most half. A mitigation you can show closing a *class* scores full.
- **Adversarial thinking** (across the whole sheet): do the abuse cases, personas and chains show you reasoning as an attacker with goals and constraints — or just listing categories? This is the course's central disposition and it is assessed, not assumed.

---

## Evidence & Integrity (required)

- **Identity proof:** every screenshot/diagram must show a terminal running `printf '%s | %s | ' "$(whoami)" '<YOUR-STUDENT-ID>'; date '+%F %T %Z'` **in the
  same image as the evidence**. When the evidence is a browser page, a DevTools panel or a
  rendered response, put that terminal **beside the browser and capture the whole screen** — a
  cropped window carries nothing that identifies you, and the lab's own output is
  byte-identical for the whole cohort *by design*, so the stamp is the only thing that makes
  the shot yours. Generic or borrowed evidence is not accepted.
- **Personalized flag (if this lab issues one):** ____________________
  *Flags are unique per student — submitting another student's flag is a violation. How to submit: **learn.zcr.ai/submit** (full guide: `SUBMISSION.md` in the repo root).*
- **Explain in your own words** *(graded on your reasoning, not copied text):*
  1. What did you do, and **why did the vulnerability work**?
  I tested the /login endpoint and found that the username was inserted directly into the SQL query using string concatenation. The vulnerability worked because user input was treated as part of the SQL command, allowing special SQL characters to change the meaning of the query instead of being treated as ordinary data.

  2. **Why does your fix actually stop it** — and what could still break it?
  I replaced the SQL string concatenation with a parameterized query, so SQLite treats the username and password values as data rather than SQL syntax. This stops SQL injection in /login, but the same vulnerability could still exist in other endpoints, such as /search, if they continue to construct SQL queries using string concatenation.

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.

Implemented mitigation: SQL Injection in /login

Changed the login query from string concatenation to a parameterized SQL query.

- q = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (
-     username, hashlib.md5((password or "").encode()).hexdigest())
- row = con.execute(q).fetchone()
+ password_hash = hashlib.md5((password or "").encode()).hexdigest()
+ q = "SELECT * FROM users WHERE username = ? AND password = ?"
+ row = con.execute(q, (username, password_hash)).fetchone()

This is a class-level fix because the SQL query no longer concatenates user-controlled input into the SQL statement. Parameterized queries treat user input as data rather than executable SQL syntax, preventing SQL injection through the login username or password fields. The same parameterized-query approach should be applied to all other database queries that use user-controlled input, such as /search.


2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).

The AI's fix correctly prevents SQL injection in /login, but it is incomplete at the application level because /search still constructs SQL using string concatenation.

q = "SELECT id,title,body FROM notes WHERE owner='%s' AND body LIKE '%%%s%%'" % (user, term)

This means the same SQL injection class can still exist in another endpoint even after /login is fixed. The AI correctly mentioned /search, but it did not actually fix or verify that endpoint.

3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.

Correct verified version:
The /login query should use a parameterized SQLite query:

password_hash = hashlib.md5((password or "").encode()).hexdigest()
q = "SELECT * FROM users WHERE username = ? AND password = ?"
row = con.execute(q, (username, password_hash)).fetchone()

I verified that alice / alicepw still logs in successfully after the change, while a login attempt using ' as the username and an incorrect password is refused with login failed (HTTP 401).

Why the AI output was insufficient

The AI's /login fix was correct, but it only fixes one instance of the SQL injection problem. A complete class-level defense requires all SQL queries that contain user-controlled input, including /search, to use parameterized queries, followed by testing of each affected endpoint.

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.

The /login endpoint checks whether the submitted username and password match a user in the database before creating a session. It was exploitable because the username was inserted directly into the SQL query, so specially crafted input could change the query instead of being treated as normal login data.

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*

**Final prompt:**

Review the `/login` function in this Flask application for SQL injection. Replace any string concatenation or formatting of user-controlled values in the SQL query with a parameterized SQLite query. Preserve the existing password hashing and login behavior, and do not modify unrelated vulnerabilities or endpoints. Provide the exact code replacement and explain why the change prevents SQL injection. The fix must still allow the valid account alice / alicepw to log in successfully and must reject invalid or specially crafted usernames instead of changing the SQL query.

**Verified result:**

I implemented the parameterized query in `/login` and committed the change as `4106596` on the `wk01` branch.

After the fix, a normal login using `alice / alicepw` still succeeded, while a login attempt using `'` as the username with an incorrect password was refused with `login failed` (HTTP 401). Therefore, the tested SQL injection against `/login` no longer succeeds after the fix.
