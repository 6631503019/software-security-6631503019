# Threat Model — <app name>
![alt text](image-1.png)
## 1. Data-flow diagram
![alt text](image.png)

## 2. Elements & trust boundaries
| Element | Type (process/store/entity/flow) | Trust boundary crossed? |
|---|---|---|
| Web client | external entity | yes (Internet → app) |
| Flask app | process | yes (app boundary to SQLite and uploads) |
| SQLite DB (`notes.db`) | data store | yes (process → DB) |
| `uploads/` store | data store | yes (process → file store) |
| `/notes` request flow | flow | yes (client → app → DB) |
| `/upload` request flow | flow | yes (client → app → uploads) |
| `/files/<name>` request flow | flow | yes (client → app → uploads) |

## 3. STRIDE analysis
| Element | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| /notes | Spoofing: any client can set `owner` and create a note without auth | Tampering: note contents are inserted directly into SQLite with no validation | Repudiation: no audit log shows who created which note | Information disclosure: note list is returned to any caller | Denial of service: large payloads or repeated inserts can fill the DB | Elevation of privilege: unauthenticated client can impersonate another owner |
| /upload | Spoofing: attacker can choose arbitrary file names | Tampering: raw user-controlled filename is saved to disk without validation | Repudiation: no trace of who uploaded each file | Information disclosure: server echoes the chosen filename and serves files directly | Denial of service: attacker can upload huge or many files to fill disk | Elevation of privilege: unsafe file names may overwrite or reach sensitive paths |
| /files/<name> | Spoofing: attacker can request any file name they know | Tampering: path traversal may allow access outside `uploads/` | Repudiation: no logging for file access | Information disclosure: file contents are exposed directly to the web client | Denial of service: repeated requests can exhaust bandwidth or disk | Elevation of privilege: if path traversal works, attacker can reach files outside the intended upload directory |

## 4. Top 5 risks (likelihood × impact) + mitigation
1. Unauthenticated file upload with user-controlled filename (`/upload`) enables arbitrary file write/path abuse. Likelihood: High, Impact: High. Mitigation: enforce authentication/authorization on upload, generate server-side filenames (UUID), sanitize with `secure_filename`, reject path separators, and store outside web root.
2. No request size/rate controls on `/upload` and `/notes` can exhaust disk/DB (DoS). Likelihood: High, Impact: High. Mitigation: set `MAX_CONTENT_LENGTH`, add per-IP rate limiting, cap note body length, and apply storage quotas with monitoring alerts.
3. `/notes` has no auth and trusts client-supplied `owner`, allowing spoofing/impersonation and data tampering. Likelihood: High, Impact: Medium-High. Mitigation: require login/session, bind owner to authenticated identity server-side, ignore client `owner` field, and enforce authorization checks on read/write.
4. No audit logging for note creation/upload/access causes repudiation and weak incident response. Likelihood: Medium-High, Impact: Medium-High. Mitigation: add structured audit logs (timestamp, user, IP, action, target), integrity-protect logs, and define log retention/review.
5. Public file retrieval (`/files/<name>`) can expose uploaded content to unauthorized users if names are guessable. Likelihood: Medium, Impact: Medium-High. Mitigation: require auth on download, use unguessable object IDs, enforce per-owner access control, and serve files with strict content-type/disposition policies.
