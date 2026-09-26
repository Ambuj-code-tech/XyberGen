# XyberGen

## Run locally

Install the dependencies:

```powershell
python -m pip install -r requirements.txt
```

Start the app:

```powershell
python main.py
```

On a fresh database, open `http://127.0.0.1:8000/` and create the first administrator. This setup is available only while there is no active administrator. The app stores data in `xybergen.sqlite3` beside `main.py` by default.

After setup, users can register at `/register`. Every self-registered account is assigned the `viewer` role. Administrators can promote or demote accounts from **User access**; only administrators can access that control. The application prevents demoting the last active administrator. Admin-created accounts also start as viewers.

For automated or managed deployments, the first administrator can optionally be bootstrapped before startup using `XYBERGEN_ADMIN_USERNAME` and `XYBERGEN_ADMIN_PASSWORD`. The password must be at least 12 characters, and both variables must be set together.

For HTTPS deployments, set `XYBERGEN_COOKIE_SECURE=1`. Keep it unset for local HTTP development. Store the database on persistent storage and restrict access to it; it contains password hashes and active session records.

## Roles

| Role | Permissions |
| --- | --- |
| Viewer | Workspace overview |
| Analyst | Workspace overview and reports |
| Admin | Overview, reports, and account creation |

Passwords are stored as salted PBKDF2 hashes. Sessions use random opaque tokens stored as hashes in SQLite, expire after eight hours, and are invalidated on sign-out. Sign-in, registration, user provisioning, role changes, and sign-out use CSRF tokens.