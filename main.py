import hashlib
import hmac
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates


BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = Path(os.environ.get("XYBERGEN_DATABASE", BASE_DIR / "xybergen.sqlite3"))
SESSION_COOKIE = "xybergen_session"
LOGIN_CSRF_COOKIE = "xybergen_login_csrf"
SESSION_LIFETIME = timedelta(hours=8)
PASSWORD_ITERATIONS = 600_000
ROLE_PERMISSIONS = {
    "admin": {"dashboard:view", "reports:view", "users:manage"},
    "analyst": {"dashboard:view", "reports:view"},
    "viewer": {"dashboard:view"},
}

app = FastAPI()
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PASSWORD_ITERATIONS)
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = encoded.split("$", maxsplit=3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


DUMMY_PASSWORD_HASH = hash_password(secrets.token_urlsafe(32))


def initialize_database() -> None:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS roles (
                name TEXT PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS permissions (
                name TEXT PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS role_permissions (
                role_name TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
                permission_name TEXT NOT NULL REFERENCES permissions(name) ON DELETE CASCADE,
                PRIMARY KEY (role_name, permission_name)
            );
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role_name TEXT NOT NULL REFERENCES roles(name),
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                csrf_token TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            """
        )
        for role, permissions in ROLE_PERMISSIONS.items():
            connection.execute("INSERT OR IGNORE INTO roles (name) VALUES (?)", (role,))
            for permission in permissions:
                connection.execute(
                    "INSERT OR IGNORE INTO permissions (name) VALUES (?)", (permission,)
                )
                connection.execute(
                    "INSERT OR IGNORE INTO role_permissions (role_name, permission_name) VALUES (?, ?)",
                    (role, permission),
                )

        admin_username = os.environ.get("XYBERGEN_ADMIN_USERNAME", "").strip()
        admin_password = os.environ.get("XYBERGEN_ADMIN_PASSWORD", "")
        if bool(admin_username) != bool(admin_password):
            raise RuntimeError(
                "Set both XYBERGEN_ADMIN_USERNAME and XYBERGEN_ADMIN_PASSWORD to bootstrap an admin."
            )
        if admin_username:
            if len(admin_password) < 12:
                raise RuntimeError("XYBERGEN_ADMIN_PASSWORD must be at least 12 characters.")
            connection.execute(
                """INSERT OR IGNORE INTO users
                   (username, password_hash, role_name, created_at) VALUES (?, ?, 'admin', ?)""",
                (admin_username, hash_password(admin_password), datetime.now(timezone.utc).isoformat()),
            )


initialize_database()


def get_user_session(request: Request) -> tuple[sqlite3.Row, str] | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = datetime.now(timezone.utc).isoformat()
    with get_connection() as connection:
        row = connection.execute(
            """SELECT users.id, users.username, users.role_name, sessions.csrf_token
               FROM sessions JOIN users ON users.id = sessions.user_id
               WHERE sessions.token_hash = ? AND sessions.expires_at > ? AND users.is_active = 1""",
            (token_hash, now),
        ).fetchone()
    return (row, token_hash) if row else None


def user_has_permission(user_id: int, permission: str) -> bool:
    with get_connection() as connection:
        result = connection.execute(
            """SELECT 1 FROM users
               JOIN role_permissions ON role_permissions.role_name = users.role_name
               WHERE users.id = ? AND role_permissions.permission_name = ? AND users.is_active = 1""",
            (user_id, permission),
        ).fetchone()
    return result is not None


def render_template(
    request: Request,
    name: str,
    context: dict[str, Any] | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name=name,
        context=context or {},
        status_code=status_code,
    )


def render_login(
    request: Request,
    context: dict[str, Any],
    status_code: int = 200,
) -> HTMLResponse:
    csrf_token = secrets.token_urlsafe(32)
    context["csrf_token"] = csrf_token
    response = render_template(request, "index.html", context, status_code)
    response.headers["Cache-Control"] = "no-store"
    response.set_cookie(
        key=LOGIN_CSRF_COOKIE,
        value=csrf_token,
        httponly=True,
        secure=os.environ.get("XYBERGEN_COOKIE_SECURE", "0") == "1",
        samesite="strict",
        path="/",
    )
    return response


def user_context(request: Request, user: sqlite3.Row) -> dict[str, Any]:
    with get_connection() as connection:
        users = []
        if user["role_name"] == "admin":
            users = connection.execute(
                """SELECT users.id, users.username, users.role_name, users.created_at
                   FROM users ORDER BY users.username COLLATE NOCASE"""
            ).fetchall()
        permissions = connection.execute(
            """SELECT permission_name FROM role_permissions
               WHERE role_name = ? ORDER BY permission_name""",
            (user["role_name"],),
        ).fetchall()
    session = get_user_session(request)
    return {
        "username": user["username"],
        "role": user["role_name"],
        "permissions": [row["permission_name"] for row in permissions],
        "users": users if user["role_name"] == "admin" else [],
        "csrf_token": session[0]["csrf_token"] if session else "",
    }


def csrf_is_valid(request: Request, submitted_token: str) -> bool:
    session = get_user_session(request)
    return bool(session and hmac.compare_digest(session[0]["csrf_token"], submitted_token))


def session_cookie_settings(response: RedirectResponse, token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=int(SESSION_LIFETIME.total_seconds()),
        httponly=True,
        secure=os.environ.get("XYBERGEN_COOKIE_SECURE", "0") == "1",
        samesite="lax",
        path="/",
    )


def create_authenticated_response(request: Request, user_id: int) -> RedirectResponse:
    token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = datetime.now(timezone.utc)
    expires_at = (now + SESSION_LIFETIME).isoformat()
    with get_connection() as connection:
        previous_token = request.cookies.get(SESSION_COOKIE)
        if previous_token:
            connection.execute(
                "DELETE FROM sessions WHERE token_hash = ?",
                (hashlib.sha256(previous_token.encode()).hexdigest(),),
            )
        connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (now.isoformat(),))
        connection.execute(
            "INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)",
            (token_hash, user_id, csrf_token, expires_at),
        )
    response = RedirectResponse("/dashboard", status_code=303)
    session_cookie_settings(response, token)
    response.delete_cookie(LOGIN_CSRF_COOKIE, path="/", httponly=True, samesite="strict")
    return response


def valid_username(username: str) -> bool:
    return (
        3 <= len(username) <= 64
        and username.replace("_", "").replace("-", "").isalnum()
    )


@app.get("/", response_class=HTMLResponse)
async def read_home(request: Request):
    if get_user_session(request):
        return RedirectResponse("/dashboard", status_code=303)
    with get_connection() as connection:
        admin_exists = connection.execute(
            "SELECT 1 FROM users WHERE role_name = 'admin' AND is_active = 1 LIMIT 1"
        ).fetchone()
    if not admin_exists:
        return RedirectResponse("/setup", status_code=303)
    return render_login(
        request,
        {
            "error": request.query_params.get("error"),
            "mode": "login",
        },
    )


@app.get("/register", response_class=HTMLResponse)
async def registration_page(request: Request):
    if get_user_session(request):
        return RedirectResponse("/dashboard", status_code=303)
    with get_connection() as connection:
        admin_exists = connection.execute(
            "SELECT 1 FROM users WHERE role_name = 'admin' AND is_active = 1 LIMIT 1"
        ).fetchone()
    if not admin_exists:
        return RedirectResponse("/setup", status_code=303)
    return render_login(request, {"mode": "register"})


@app.post("/register", response_class=HTMLResponse)
async def register(request: Request):
    form = await request.form()
    submitted_csrf = str(form.get("csrf_token", ""))
    cookie_csrf = request.cookies.get(LOGIN_CSRF_COOKIE, "")
    if not cookie_csrf or not hmac.compare_digest(cookie_csrf, submitted_csrf):
        return render_login(
            request,
            {"mode": "register", "error": "The form expired. Please try again."},
            status_code=403,
        )

    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))
    confirmation = str(form.get("password_confirmation", ""))
    if not valid_username(username):
        return render_login(
            request,
            {"mode": "register", "error": "Use 3-64 letters, numbers, underscores, or hyphens."},
            status_code=400,
        )
    if len(password) < 12:
        return render_login(
            request,
            {"mode": "register", "error": "Choose a password with at least 12 characters."},
            status_code=400,
        )
    if password != confirmation:
        return render_login(
            request,
            {"mode": "register", "error": "The passwords do not match."},
            status_code=400,
        )

    try:
        with get_connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            admin_exists = connection.execute(
                "SELECT 1 FROM users WHERE role_name = 'admin' AND is_active = 1 LIMIT 1"
            ).fetchone()
            if not admin_exists:
                return RedirectResponse("/setup", status_code=303)
            cursor = connection.execute(
                """INSERT INTO users (username, password_hash, role_name, created_at)
                   VALUES (?, ?, 'viewer', ?)""",
                (username, hash_password(password), datetime.now(timezone.utc).isoformat()),
            )
            user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        return render_login(
            request,
            {"mode": "register", "error": "That username is already in use."},
            status_code=409,
        )
    return create_authenticated_response(request, user_id)


@app.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request):
    if get_user_session(request):
        return RedirectResponse("/dashboard", status_code=303)
    with get_connection() as connection:
        admin_exists = connection.execute(
            "SELECT 1 FROM users WHERE role_name = 'admin' AND is_active = 1 LIMIT 1"
        ).fetchone()
    if admin_exists:
        return RedirectResponse("/", status_code=303)
    return render_login(request, {"mode": "setup"})


@app.post("/setup", response_class=HTMLResponse)
async def setup_first_admin(request: Request):
    form = await request.form()
    submitted_csrf = str(form.get("csrf_token", ""))
    cookie_csrf = request.cookies.get(LOGIN_CSRF_COOKIE, "")
    if not cookie_csrf or not hmac.compare_digest(cookie_csrf, submitted_csrf):
        return render_login(
            request,
            {"mode": "setup", "error": "The form expired. Please try again."},
            status_code=403,
        )

    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))
    confirmation = str(form.get("password_confirmation", ""))
    if not valid_username(username) or len(password) < 12 or password != confirmation:
        error = "Check the username, use a password with at least 12 characters, and confirm it correctly."
        return render_login(request, {"mode": "setup", "error": error}, status_code=400)

    try:
        with get_connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            admin_exists = connection.execute(
                "SELECT 1 FROM users WHERE role_name = 'admin' AND is_active = 1 LIMIT 1"
            ).fetchone()
            if admin_exists:
                return RedirectResponse("/", status_code=303)
            cursor = connection.execute(
                """INSERT INTO users (username, password_hash, role_name, created_at)
                   VALUES (?, ?, 'admin', ?)""",
                (username, hash_password(password), datetime.now(timezone.utc).isoformat()),
            )
            user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        return render_login(
            request,
            {"mode": "setup", "error": "That username is already in use. Choose another."},
            status_code=409,
        )
    return create_authenticated_response(request, user_id)


@app.post("/login", response_class=HTMLResponse)
async def login(request: Request):
    form = await request.form()
    submitted_csrf = str(form.get("csrf_token", ""))
    cookie_csrf = request.cookies.get(LOGIN_CSRF_COOKIE, "")
    if not cookie_csrf or not hmac.compare_digest(cookie_csrf, submitted_csrf):
        return render_login(
            request,
            {"mode": "login", "error": "Your sign-in form expired. Please try again."},
            status_code=403,
        )
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))
    with get_connection() as connection:
        user = connection.execute(
            "SELECT id, username, password_hash, is_active FROM users WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()
    password_hash = user["password_hash"] if user else DUMMY_PASSWORD_HASH
    authenticated = verify_password(password, password_hash)
    if not user or not user["is_active"] or not authenticated:
        return render_login(
            request,
            {"mode": "login", "error": "The username or password is incorrect."},
            status_code=401,
        )
    return create_authenticated_response(request, user["id"])


@app.post("/logout")
async def logout(request: Request):
    form = await request.form()
    if not csrf_is_valid(request, str(form.get("csrf_token", ""))):
        return HTMLResponse("Invalid request token.", status_code=403)
    session = get_user_session(request)
    if session:
        with get_connection() as connection:
            connection.execute("DELETE FROM sessions WHERE token_hash = ?", (session[1],))
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, samesite="lax")
    return response


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    session = get_user_session(request)
    if not session:
        return RedirectResponse("/?error=Sign+in+to+continue", status_code=303)
    user = session[0]
    if not user_has_permission(user["id"], "dashboard:view"):
        return HTMLResponse("You do not have permission to view this page.", status_code=403)
    context = user_context(request, user)
    context["page"] = "dashboard"
    return render_template(request, "dashboard.html", context)


@app.get("/reports", response_class=HTMLResponse)
async def reports(request: Request):
    session = get_user_session(request)
    if not session:
        return RedirectResponse("/?error=Sign+in+to+continue", status_code=303)
    user = session[0]
    if not user_has_permission(user["id"], "reports:view"):
        return HTMLResponse("Your account does not have report access.", status_code=403)
    context = user_context(request, user)
    context["page"] = "reports"
    return render_template(request, "dashboard.html", context)


@app.get("/admin/users", response_class=HTMLResponse)
async def admin_users(request: Request):
    session = get_user_session(request)
    if not session:
        return RedirectResponse("/?error=Sign+in+to+continue", status_code=303)
    user = session[0]
    if not user_has_permission(user["id"], "users:manage"):
        return HTMLResponse("Administrator permission is required.", status_code=403)
    context = user_context(request, user)
    context.update({"page": "admin", "error": request.query_params.get("error"), "success": request.query_params.get("success")})
    return render_template(request, "dashboard.html", context)


@app.post("/admin/users")
async def create_user(request: Request):
    session = get_user_session(request)
    if not session:
        return RedirectResponse("/?error=Sign+in+to+continue", status_code=303)
    user = session[0]
    if not user_has_permission(user["id"], "users:manage"):
        return HTMLResponse("Administrator permission is required.", status_code=403)
    form = await request.form()
    if not csrf_is_valid(request, str(form.get("csrf_token", ""))):
        return HTMLResponse("Invalid request token.", status_code=403)
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))
    if not valid_username(username):
        return RedirectResponse("/admin/users?error=Use+3-64+letters,+numbers,+underscores+or+hyphens", status_code=303)
    if len(password) < 12:
        return RedirectResponse("/admin/users?error=Passwords+must+be+at+least+12+characters", status_code=303)
    try:
        with get_connection() as connection:
            connection.execute(
                """INSERT INTO users (username, password_hash, role_name, created_at)
                   VALUES (?, ?, 'viewer', ?)""",
                (username, hash_password(password), datetime.now(timezone.utc).isoformat()),
            )
    except sqlite3.IntegrityError:
        return RedirectResponse("/admin/users?error=That+username+already+exists", status_code=303)
    return RedirectResponse("/admin/users?success=Account+created", status_code=303)


@app.post("/admin/users/{target_user_id}/role")
async def update_user_role(target_user_id: int, request: Request):
    session = get_user_session(request)
    if not session:
        return RedirectResponse("/?error=Sign+in+to+continue", status_code=303)
    actor = session[0]
    if not user_has_permission(actor["id"], "users:manage"):
        return HTMLResponse("Administrator permission is required.", status_code=403)

    form = await request.form()
    if not csrf_is_valid(request, str(form.get("csrf_token", ""))):
        return HTMLResponse("Invalid request token.", status_code=403)
    new_role = str(form.get("role", ""))
    if new_role not in ROLE_PERMISSIONS:
        return RedirectResponse("/admin/users?error=Choose+a+valid+role", status_code=303)

    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        target = connection.execute(
            "SELECT id, role_name FROM users WHERE id = ?", (target_user_id,)
        ).fetchone()
        if not target:
            return RedirectResponse("/admin/users?error=Account+not+found", status_code=303)
        if target["role_name"] == "admin" and new_role != "admin":
            admin_count = connection.execute(
                "SELECT COUNT(*) FROM users WHERE role_name = 'admin' AND is_active = 1"
            ).fetchone()[0]
            if admin_count <= 1:
                return RedirectResponse(
                    "/admin/users?error=At+least+one+administrator+must+remain", status_code=303
                )
        connection.execute(
            "UPDATE users SET role_name = ? WHERE id = ?", (new_role, target_user_id)
        )
    return RedirectResponse("/admin/users?success=Role+updated", status_code=303)


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)