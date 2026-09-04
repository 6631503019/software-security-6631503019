# Threat Model — <app Sample App>

## 1. Data-flow diagram
[DFD](img/wk01.drawio.png)

## 2. Elements & trust boundaries
| Element | Type (process/store/entity/flow) | Trust boundary crossed? |
|---|---|---|
| Web client | external entity | yes (Internet → app) |
| Flask app | process | |
| SQLite DB (`notes.db`) | data store | |
| `uploads/` store | data store | |

## 3. STRIDE analysis
| Element | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| /notes | Client can spoof the `owner` value because there is no authentication | Client can create/modify note data through the endpoint | No logging makes actions difficult to trace | Notes are returned without access control | An attacker could send many requests to consume resources | No authorization boundary prevents misuse of the endpoint |
| /upload | No user authentication is enforced | Raw `f.filename` is used when saving the file, allowing attacker-controlled file paths | No logging of upload activity | The application echoes the saved filename/path | An attacker could upload many or very large files | Uploaded content is accepted without authorization controls |
| /files/<name> |No authentication is required to request a file | — | No access logging | Files in `uploads/` can be requested by name | Repeated file requests could consume resources | — |

## 4. Top 5 risks (likelihood × impact) + mitigation
1.**Tampering — `/upload` allows attacker-controlled filenames**
   - Likelihood: High
   - Impact: High
   - Mitigation: Use `secure_filename()` and generate server-side filenames. Store uploaded files outside the web root and allow-list permitted file extensions.

2.**Spoofing — `/notes` accepts a client-controlled `owner`**
   - Likelihood: High
   - Impact: Medium
   - Mitigation: Require authentication and derive the owner identity from the authenticated session instead of trusting the client-supplied `owner`.

3.**Information Disclosure — uploaded files can be accessed without authorization**
   - Likelihood: Medium
   - Impact: High
   - Mitigation: Require authorization before serving files and restrict access to files belonging to the requesting user.

4.**Repudiation — security-relevant actions are not logged**
   - Likelihood: Medium
   - Impact: Medium
   - Mitigation: Add security logging for note creation, file uploads, and file access.
   
5. **Denial of Service — unrestricted file uploads**
   - Likelihood: Medium
   - Impact: High
   - Mitigation: Enforce file-size limits, upload quotas, and rate limiting.
