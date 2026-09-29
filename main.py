import hashlib
import hmac
import importlib.util
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from typing import Any, Iterator
from xml.sax.saxutils import escape

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

BASE_DIR = Path(__file__).resolve().parent


def load_environment() -> None:
    env_path = BASE_DIR / ".env"
    load_dotenv(env_path, override=True)
    for key in ("GROQ_API_KEY", "OPENAI_API_KEY", "XYBERGEN_MODEL", "XYBERGEN_ADMIN_USERNAME", "XYBERGEN_ADMIN_PASSWORD"):
        if key in os.environ:
            os.environ[key] = str(os.environ[key]).strip().strip('"\'')


load_environment()
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

_AGENT_PATH = BASE_DIR / "backend" / "agent.py"
generate_document_output = None
if _AGENT_PATH.exists():
    spec = importlib.util.spec_from_file_location("xybergen_agent", _AGENT_PATH)
    if spec and spec.loader:
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        generate_document_output = getattr(module, "generate_document_output", None)


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
CONTEXT_OPTIONS = ["emergency", "announcement", "casual"]
DOCUMENT_TYPE_OPTIONS = {"document", "scan", "audio", "video"}
REPORT_CATEGORIES = ("Infographics", "X Posts", "Storyboards")
OUTPUT_FORMAT_OPTIONS = [
    "LinkedIn post",
    "X post",
    "Summary",
    "Presentation",
    "Script",
    "Image",
    "Document",
    "Custom",
]
ALLOWED_UPLOAD_MIME_TYPES = {
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "image/jpeg",
    "image/png",
    "image/webp",
    "image/gif",
    "audio/mpeg",
    "audio/mp3",
    "audio/wav",
    "audio/x-wav",
    "audio/mp4",
    "audio/m4a",
    "video/mp4",
    "video/webm",
    "video/quicktime",
}


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
            CREATE TABLE IF NOT EXISTS uploaded_documents (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                original_name TEXT NOT NULL,
                document_type TEXT NOT NULL DEFAULT 'document',
                description TEXT NOT NULL DEFAULT '',
                mime_type TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                file_data BLOB NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS document_output_options (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                document_id INTEGER NOT NULL REFERENCES uploaded_documents(id) ON DELETE CASCADE,
                context TEXT,
                target_audience TEXT,
                output_formats TEXT,
                custom_outputs TEXT,
                output_format_1 TEXT,
                output_format_2 TEXT,
                output_format_3 TEXT,
                output_format_4 TEXT,
                custom_output_1 TEXT,
                custom_output_2 TEXT,
                custom_output_3 TEXT,
                custom_output_4 TEXT,
                created_at TEXT NOT NULL,
                UNIQUE(user_id, document_id)
            );
            CREATE TABLE IF NOT EXISTS memory_documents (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS verified_reports (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                document_id INTEGER NOT NULL REFERENCES uploaded_documents(id) ON DELETE CASCADE,
                category TEXT NOT NULL CHECK(category IN ('Infographics', 'X Posts', 'Storyboards')),
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                is_verified INTEGER NOT NULL DEFAULT 0 CHECK(is_verified IN (0, 1)),
                is_rehydrated INTEGER NOT NULL DEFAULT 0 CHECK(is_rehydrated IN (0, 1)),
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS generated_outputs (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                document_id INTEGER NOT NULL REFERENCES uploaded_documents(id) ON DELETE CASCADE,
                output_format TEXT NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                is_verified INTEGER NOT NULL DEFAULT 0 CHECK(is_verified IN (0, 1)),
                is_rehydrated INTEGER NOT NULL DEFAULT 0 CHECK(is_rehydrated IN (0, 1)),
                created_at TEXT NOT NULL
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


def ensure_document_output_schema() -> None:
    with get_connection() as connection:
        document_columns = [row[1] for row in connection.execute("PRAGMA table_info(uploaded_documents)").fetchall()]
        if "document_type" not in document_columns:
            connection.execute("ALTER TABLE uploaded_documents ADD COLUMN document_type TEXT NOT NULL DEFAULT 'document'")
        if "description" not in document_columns:
            connection.execute("ALTER TABLE uploaded_documents ADD COLUMN description TEXT NOT NULL DEFAULT ''")
        columns = [row[1] for row in connection.execute("PRAGMA table_info(document_output_options)").fetchall()]
        if "context" not in columns:
            connection.execute("ALTER TABLE document_output_options ADD COLUMN context TEXT")
        if "target_audience" not in columns:
            connection.execute("ALTER TABLE document_output_options ADD COLUMN target_audience TEXT")
        if "output_formats" not in columns:
            connection.execute("ALTER TABLE document_output_options ADD COLUMN output_formats TEXT")
        if "custom_outputs" not in columns:
            connection.execute("ALTER TABLE document_output_options ADD COLUMN custom_outputs TEXT")


def build_summary_pdf(title: str, summary_text: str) -> bytes:
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
    except ImportError:  # pragma: no cover - optional dependency path
        raise RuntimeError("reportlab is required to generate PDF exports")

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.8 * inch,
        leftMargin=0.8 * inch,
        topMargin=0.8 * inch,
        bottomMargin=0.8 * inch,
        pageCompression=0,
    )
    story = []

    title_text = (title or "Executive Summary").strip() or "Executive Summary"
    story.append(
        Paragraph(
            title_text,
            ParagraphStyle(name="TitleStyle", fontName="Helvetica-Bold", fontSize=22, leading=26, spaceAfter=18),
        )
    )

    body = summary_text.strip() or "Executive summary content is unavailable."
    for block in body.split("\n\n") or [body]:
        paragraph_text = block.strip()
        if not paragraph_text:
            story.append(Spacer(1, 0.12 * inch))
            continue
        story.append(
            Paragraph(
                paragraph_text,
                ParagraphStyle(
                    name="BodyStyle",
                    fontName="Helvetica",
                    fontSize=12,
                    leading=18,
                    alignment=0,
                    spaceAfter=12,
                ),
            )
        )

    doc.build(story)
    return buffer.getvalue()


ensure_document_output_schema()


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


def get_uploaded_documents(user_id: int, limit: int = 10) -> list[sqlite3.Row]:
    with get_connection() as connection:
        return connection.execute(
            """SELECT d.id, d.title, d.original_name, d.document_type, d.description,
                      d.mime_type, d.size_bytes, d.created_at,
                      o.context, o.target_audience, o.output_formats, o.custom_outputs,
                      o.output_format_1, o.output_format_2, o.output_format_3, o.output_format_4,
                      o.custom_output_1, o.custom_output_2, o.custom_output_3, o.custom_output_4
               FROM uploaded_documents d
               LEFT JOIN document_output_options o ON o.document_id = d.id AND o.user_id = d.user_id
               WHERE d.user_id = ?
               ORDER BY d.created_at DESC, d.id DESC
               LIMIT ?""",
            (user_id, limit),
        ).fetchall()


def get_verified_reports(
    user_id: int,
    category: str = "all",
    query: str = "",
) -> list[dict[str, Any]]:
    conditions = ["r.user_id = ?", "r.is_verified = 1", "r.is_rehydrated = 1"]
    parameters: list[Any] = [user_id]
    if category in REPORT_CATEGORIES:
        conditions.append("r.category = ?")
        parameters.append(category)
    if query:
        conditions.append("(r.title LIKE ? OR d.title LIKE ? OR d.original_name LIKE ?)")
        search = f"%{query}%"
        parameters.extend((search, search, search))

    with get_connection() as connection:
        rows = connection.execute(
            f"""SELECT r.id, r.document_id, r.category, r.title, r.content, r.created_at,
                       d.title AS document_title, d.original_name
                FROM verified_reports r
                JOIN uploaded_documents d ON d.id = r.document_id AND d.user_id = r.user_id
                WHERE {' AND '.join(conditions)}
                ORDER BY d.created_at DESC, r.created_at DESC, r.id DESC
                LIMIT 200""",
            parameters,
        ).fetchall()
    return [dict(row) for row in rows]


def get_pending_outputs(user_id: int, limit: int = 100) -> list[sqlite3.Row]:
    with get_connection() as connection:
        return connection.execute(
            """SELECT o.id, o.document_id, o.output_format, o.title, o.created_at,
                      d.title AS document_title
               FROM generated_outputs o
               JOIN uploaded_documents d ON d.id = o.document_id AND d.user_id = o.user_id
               WHERE o.user_id = ? AND (o.is_verified = 0 OR o.is_rehydrated = 0)
               ORDER BY o.created_at DESC, o.id DESC
               LIMIT ?""",
            (user_id, limit),
        ).fetchall()


def get_memory_documents(user_id: int, limit: int = 10) -> list[sqlite3.Row]:
    return get_uploaded_documents(user_id, limit)


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
    context.update({
        "page": "dashboard",
        "uploaded_documents": get_uploaded_documents(user["id"]),
        "error": request.query_params.get("error"),
        "success": request.query_params.get("success"),
    })
    return render_template(request, "dashboard.html", context)


@app.get("/dashboard/upload", response_class=HTMLResponse)
async def upload_dashboard(request: Request):
    session = get_user_session(request)
    if not session:
        return RedirectResponse("/?error=Sign+in+to+continue", status_code=303)
    user = session[0]
    if not user_has_permission(user["id"], "dashboard:view"):
        return HTMLResponse("You do not have permission to view this page.", status_code=403)
    context = user_context(request, user)
    context.update({
        "page": "upload",
        "error": request.query_params.get("error"),
        "success": request.query_params.get("success"),
        "uploaded_documents": get_uploaded_documents(user["id"]),
    })
    return render_template(request, "dashboard.html", context)


@app.get("/dashboard/memory", response_class=HTMLResponse)
async def memory_dashboard(request: Request):
    return RedirectResponse("/dashboard/upload", status_code=303)


@app.post("/dashboard/upload")
async def save_uploaded_document(request: Request):
    session = get_user_session(request)
    if not session:
        return RedirectResponse("/?error=Sign+in+to+continue", status_code=303)
    user = session[0]
    if not user_has_permission(user["id"], "dashboard:view"):
        return HTMLResponse("You do not have permission to view this page.", status_code=403)

    form = await request.form()
    if not csrf_is_valid(request, str(form.get("csrf_token", ""))):
        return HTMLResponse("Invalid request token.", status_code=403)

    title = str(form.get("title", "")).strip()
    document_type = str(form.get("document_type", "")).strip().lower()
    description = str(form.get("description", "")).strip()
    uploaded_file = form.get("document")
    if len(title) > 200:
        return RedirectResponse("/dashboard/upload?error=Title+must+be+200+characters+or+less", status_code=303)
    if len(description) > 1000:
        return RedirectResponse("/dashboard/upload?error=Description+must+be+1000+characters+or+less", status_code=303)
    if uploaded_file is None or getattr(uploaded_file, "filename", "") == "":
        return RedirectResponse("/dashboard/upload?error=Choose+a+supported+document,+image,+audio+or+video+file", status_code=303)

    filename = str(getattr(uploaded_file, "filename", "")).strip()
    mime_type = str(getattr(uploaded_file, "content_type", "") or "application/octet-stream").strip().lower()
    if not title:
        title = Path(filename).stem[:200] or filename[:200]
    if not document_type:
        if mime_type.startswith("audio/"):
            document_type = "audio"
        elif mime_type.startswith("video/"):
            document_type = "video"
        elif mime_type.startswith("image/"):
            document_type = "scan"
        else:
            document_type = "document"
    if document_type not in DOCUMENT_TYPE_OPTIONS:
        return RedirectResponse("/dashboard/upload?error=Choose+a+valid+document+type", status_code=303)
    file_data = await uploaded_file.read()
    if not filename:
        return RedirectResponse("/dashboard/upload?error=Choose+a+supported+document,+image,+audio+or+video+file", status_code=303)
    if mime_type not in ALLOWED_UPLOAD_MIME_TYPES and not filename.lower().endswith(
        (".pdf", ".doc", ".docx", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp3", ".wav", ".m4a", ".mp4", ".mov", ".webm", ".xls", ".xlsx")
    ):
        return RedirectResponse("/dashboard/upload?error=Only+docs,+PDF,+images,+audio,+and+video+files+are+allowed", status_code=303)
    if not file_data:
        return RedirectResponse("/dashboard/upload?error=The+selected+file+is+empty", status_code=303)

    with get_connection() as connection:
        cursor = connection.execute(
            """INSERT INTO uploaded_documents (
                   user_id, title, original_name, document_type, description, mime_type,
                   size_bytes, file_data, created_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                user["id"], title, filename, document_type, description, mime_type,
                len(file_data), file_data, datetime.now(timezone.utc).isoformat(),
            ),
        )
        document_id = cursor.lastrowid
    if str(form.get("source", "")) == "overview":
        return RedirectResponse("/dashboard?success=Document+saved+to+your+submission+history", status_code=303)
    return RedirectResponse(f"/dashboard/upload/{document_id}/configure?success=Upload+saved", status_code=303)


@app.post("/dashboard/upload/{document_id}/delete")
async def delete_uploaded_document(document_id: int, request: Request):
    session = get_user_session(request)
    if not session:
        return RedirectResponse("/?error=Sign+in+to+continue", status_code=303)
    user = session[0]
    if not user_has_permission(user["id"], "dashboard:view"):
        return HTMLResponse("You do not have permission to delete this document.", status_code=403)

    form = await request.form()
    if not csrf_is_valid(request, str(form.get("csrf_token", ""))):
        return HTMLResponse("Invalid request token.", status_code=403)

    with get_connection() as connection:
        cursor = connection.execute(
            "DELETE FROM uploaded_documents WHERE id = ? AND user_id = ?",
            (document_id, user["id"]),
        )
    if cursor.rowcount == 0:
        return RedirectResponse("/dashboard?error=Document+not+found", status_code=303)
    return RedirectResponse("/dashboard?success=Document+deleted", status_code=303)


@app.get("/dashboard/upload/{document_id}/configure", response_class=HTMLResponse)
async def configure_uploaded_document(document_id: int, request: Request):
    session = get_user_session(request)
    if not session:
        return RedirectResponse("/?error=Sign+in+to+continue", status_code=303)
    user = session[0]
    if not user_has_permission(user["id"], "dashboard:view"):
        return HTMLResponse("You do not have permission to view this page.", status_code=403)

    with get_connection() as connection:
        document = connection.execute(
            """SELECT d.id, d.title, d.original_name, d.mime_type, d.created_at,
                      o.context, o.target_audience, o.output_formats, o.custom_outputs
               FROM uploaded_documents d
               LEFT JOIN document_output_options o ON o.document_id = d.id AND o.user_id = d.user_id
               WHERE d.id = ? AND d.user_id = ?""",
            (document_id, user["id"]),
        ).fetchone()
        if not document:
            return RedirectResponse("/dashboard/upload?error=Upload+not+found", status_code=303)

    context = user_context(request, user)
    context.update({
        "page": "upload-configure",
        "document": document,
        "context_options": CONTEXT_OPTIONS,
        "output_format_options": OUTPUT_FORMAT_OPTIONS,
        "error": request.query_params.get("error"),
        "success": request.query_params.get("success"),
        "selected_output_formats": (document["output_formats"] or "").split(", ") if document["output_formats"] else [],
    })
    return render_template(request, "dashboard.html", context)


@app.post("/dashboard/upload/{document_id}/configure")
async def save_document_output_options(document_id: int, request: Request):
    session = get_user_session(request)
    if not session:
        return RedirectResponse("/?error=Sign+in+to+continue", status_code=303)
    user = session[0]
    if not user_has_permission(user["id"], "dashboard:view"):
        return HTMLResponse("You do not have permission to view this page.", status_code=403)

    form = await request.form()
    if not csrf_is_valid(request, str(form.get("csrf_token", ""))):
        return HTMLResponse("Invalid request token.", status_code=403)

    context = str(form.get("context", "")).strip().lower()
    target_audience = str(form.get("target_audience", "")).strip()
    output_formats = form.getlist("output_formats") or ["Executive Summary"]
    custom_outputs = str(form.get("custom_outputs", "")).strip()

    if context not in CONTEXT_OPTIONS:
        return RedirectResponse(f"/dashboard/upload/{document_id}/configure?error=Choose+a+valid+context", status_code=303)
    if not target_audience:
        return RedirectResponse(f"/dashboard/upload/{document_id}/configure?error=Add+a+target+audience", status_code=303)

    with get_connection() as connection:
        document = connection.execute(
            "SELECT id FROM uploaded_documents WHERE id = ? AND user_id = ?",
            (document_id, user["id"]),
        ).fetchone()
        if not document:
            return RedirectResponse("/dashboard/upload?error=Upload+not+found", status_code=303)

        connection.execute(
            """INSERT INTO document_output_options (
                   user_id, document_id, context, target_audience, output_formats, custom_outputs,
                   created_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(user_id, document_id)
               DO UPDATE SET
                   context = excluded.context,
                   target_audience = excluded.target_audience,
                   output_formats = excluded.output_formats,
                   custom_outputs = excluded.custom_outputs,
                   created_at = excluded.created_at""",
            (
                user["id"],
                document_id,
                context,
                target_audience,
                ", ".join(output_formats),
                custom_outputs,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
    return RedirectResponse(f"/dashboard/upload/{document_id}/configure?success=Details+saved", status_code=303)


@app.post("/dashboard/upload/{document_id}/generate")
async def generate_document_output_for_user(document_id: int, request: Request):
    session = get_user_session(request)
    if not session:
        return JSONResponse({"error": "Sign in to continue."}, status_code=401)
    user = session[0]
    if not user_has_permission(user["id"], "dashboard:view"):
        return JSONResponse({"error": "Permission denied."}, status_code=403)

    form = await request.form()
    if not csrf_is_valid(request, str(form.get("csrf_token", ""))):
        return JSONResponse({"error": "Invalid request token."}, status_code=403)

    with get_connection() as connection:
        document_profile = connection.execute(
            """SELECT d.id, d.title, d.original_name, d.mime_type,
                      o.context, o.target_audience, o.output_formats, o.custom_outputs
               FROM uploaded_documents d
               LEFT JOIN document_output_options o ON o.document_id = d.id AND o.user_id = d.user_id
               WHERE d.id = ? AND d.user_id = ?""",
            (document_id, user["id"]),
        ).fetchone()

    if not document_profile:
        return JSONResponse({"error": "No uploaded document found."}, status_code=404)

    report_title = str(form.get("report_title", "")).strip()
    if not report_title:
        report_title = f"{document_profile['title']} Executive Summary".strip()[:200]
    if len(report_title) > 200:
        return JSONResponse({"error": "Report title must be 200 characters or less."}, status_code=400)

    context = str(form.get("context", "") or document_profile["context"] or "announcement").strip().lower()
    target_audience = str(form.get("target_audience", "") or document_profile["target_audience"] or "general audience").strip()
    custom_outputs = str(form.get("custom_outputs", "") or document_profile["custom_outputs"] or "").strip()
    user_prompt = str(form.get("user_prompt", "") or form.get("summary_prompt", "") or "").strip()
    output_format = str(form.get("output_format", "Executive Summary")).strip() or "Executive Summary"

    if context not in CONTEXT_OPTIONS:
        context = "announcement"
    if not target_audience:
        target_audience = "general audience"
    if not user_prompt:
        user_prompt = (
            f"Create an executive summary for '{document_profile['title']}' "
            f"for the {target_audience} audience. "
            f"Use the {context} context and focus on the most important points."
        )
        if custom_outputs:
            user_prompt = f"{user_prompt} Additional guidance: {custom_outputs}."

    with get_connection() as connection:
        connection.execute(
            """INSERT INTO document_output_options (
                   user_id, document_id, context, target_audience, output_formats, custom_outputs,
                   created_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(user_id, document_id)
               DO UPDATE SET
                   context = excluded.context,
                   target_audience = excluded.target_audience,
                   output_formats = excluded.output_formats,
                   custom_outputs = excluded.custom_outputs,
                   created_at = excluded.created_at""",
            (
                user["id"],
                document_id,
                context,
                target_audience,
                "Executive Summary",
                custom_outputs,
                datetime.now(timezone.utc).isoformat(),
            ),
        )

        document_profile = connection.execute(
            """SELECT d.id, d.title, d.original_name, d.mime_type,
                      o.context, o.target_audience, o.output_formats, o.custom_outputs
               FROM uploaded_documents d
               LEFT JOIN document_output_options o ON o.document_id = d.id AND o.user_id = d.user_id
               WHERE d.id = ? AND d.user_id = ?""",
            (document_id, user["id"]),
        ).fetchone()

    if generate_document_output is None:
        return JSONResponse({"error": "Agent workflow is not available."}, status_code=503)

    result = generate_document_output(
        {
            "document_id": document_profile["id"],
            "title": document_profile["title"],
            "original_name": document_profile["original_name"],
            "mime_type": document_profile["mime_type"],
            "context": document_profile["context"],
            "target_audience": document_profile["target_audience"],
            "output_formats": document_profile["output_formats"],
            "custom_outputs": document_profile["custom_outputs"],
        },
        user_prompt,
        output_format,
    )

    safe_title = "".join(
        ch if ch.isascii() and (ch.isalnum() or ch in ("-", "_")) else "-"
        for ch in report_title
    ).strip("-") or "report"

    try:
        pdf_bytes = build_summary_pdf(escape(report_title), result)
    except RuntimeError:
        pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<<>>\n%%EOF"

    generated_content = str(result or "").strip()
    if generated_content:
        with get_connection() as connection:
            connection.execute(
                """INSERT INTO generated_outputs (
                       user_id, document_id, output_format, title, content, created_at
                   ) VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    user["id"],
                    document_id,
                    output_format,
                    report_title,
                    generated_content,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'inline; filename="{safe_title}.pdf"',
            "Cache-Control": "no-store",
        },
    )


@app.post("/dashboard/upload/{document_id}/options")
async def save_legacy_output_options(document_id: int, request: Request):
    return await save_document_output_options(document_id, request)


@app.post("/dashboard/memory")
async def save_memory_document(request: Request):
    return await save_uploaded_document(request)


@app.get("/reports", response_class=HTMLResponse)
async def reports(request: Request):
    session = get_user_session(request)
    if not session:
        return RedirectResponse("/?error=Sign+in+to+continue", status_code=303)
    user = session[0]
    if not user_has_permission(user["id"], "reports:view"):
        return HTMLResponse("Your account does not have report access.", status_code=403)
    context = user_context(request, user)
    category = request.query_params.get("category", "all")
    if category not in (*REPORT_CATEGORIES, "all"):
        category = "all"
    query = request.query_params.get("q", "").strip()[:100]
    reports = get_verified_reports(user["id"], category, query)
    pending_outputs = get_pending_outputs(user["id"])
    grouped_reports: dict[int, dict[str, Any]] = {}
    for report in reports:
        group = grouped_reports.setdefault(report["document_id"], {
            "title": report["document_title"],
            "original_name": report["original_name"],
            "outputs": [],
        })
        group["outputs"].append(report)
    context.update({
        "page": "reports",
        "report_categories": REPORT_CATEGORIES,
        "report_category": category,
        "report_query": query,
        "report_documents": list(grouped_reports.values()),
        "report_count": len(reports),
        "pending_outputs": pending_outputs,
    })
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