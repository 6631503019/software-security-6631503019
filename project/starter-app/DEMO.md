# NoteVault secure-build demo

Run only from `project/starter-app` against the local container.

```powershell
$env:APP_SECRET = "local-only-demo-secret-change-me"
$env:TEAM_ID = "TSC"
docker compose up --build -d
```

1. **SQL injection (F-01/F-02):** request `POST /login` with username
   `' OR '1'='1` and an invalid password, then request `/search?q=' OR 1=1 --`.
   Before remediation these values were interpolated into SQL; after remediation the
   login fails and search returns only the authenticated user's notes.
2. **Stored/reflected XSS (F-03):** submit
   `<img src=x onerror=alert(1)>` as a note body. The fixed home and search views
   render escaped text; no script executes.
3. **IDOR and privilege escalation (F-04/F-05):** log in as `alice`, request
   `/api/notes/2`, and attempt registration with `role=admin`. The API returns 404
   and registration always creates a `user`.
4. **Command injection and disclosure (F-06/F-07):** request
   `/export?fmt=txt;cat%20/etc/passwd`. The fixed endpoint returns 400, exports only
   the current user's notes, and the admin response contains no password field.
5. **Session/CSRF:** omit the CSRF token from a login or note request. The fixed
   endpoint returns 403. Inspect the session cookie: it is HttpOnly and SameSite=Lax.

Retest automatically:

```powershell
python -m pytest -q test_app.py
docker compose down
```

Cosign signing and GitHub provenance require a registry, GitHub Actions OIDC, and
authorized repository permissions; those are not claimed as locally completed.
