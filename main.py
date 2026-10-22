import asyncio
import calendar
import hashlib
import hmac
import importlib.util
import logging
import os
import secrets
import sqlite3
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from typing import Any, AsyncGenerator, Iterator
from urllib.parse import quote
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
MAX_PROFILE_PICTURE_BYTES = 2 * 1024 * 1024
MAX_CHAT_ATTACHMENT_BYTES = 10 * 1024 * 1024
MAX_CHAT_MESSAGE_LENGTH = 4000
MAX_CHAT_MEMBERS = 20
ACCOUNT_RETENTION_MONTHS = 3
ACCOUNT_CLEANUP_INTERVAL_SECONDS = 60 * 60
LOGGER = logging.getLogger(__name__)
ROLE_PERMISSIONS = {
    "admin": {"dashboard:view", "documents:upload", "reports:view", "users:manage", "chat:access"},
    "analyst": {"dashboard:view", "documents:upload", "reports:view", "chat:access"},
    "viewer": {"dashboard:view"},
}
ADMIN_USER_FILTERS = {
    "all": "All accounts",
    "active": "Active",
    "flagged": "Flagged",
    "deregistered": "Deregistered",
    "scheduled": "Deletion scheduled",
    "retained": "Data retained",
}

@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
    cleanup_task = asyncio.create_task(expired_account_cleanup_loop())
    try:
        yield
    finally:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass


app = FastAPI(lifespan=lifespan)
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


def add_calendar_months(value: datetime, months: int) -> datetime:
    month_index = value.month - 1 + months
    year = value.year + month_index // 12
    month = month_index % 12 + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


def purge_expired_deregistered_users(now: datetime | None = None) -> int:
    cutoff = (now or datetime.now(timezone.utc)).isoformat()
    with get_connection() as connection:
        cursor = connection.execute(
            """DELETE FROM users
               WHERE is_active = 0 AND keep_data = 0
                 AND purge_after IS NOT NULL AND purge_after <= ?""",
            (cutoff,),
        )
        return cursor.rowcount


async def expired_account_cleanup_loop() -> None:
    while True:
        try:
            await asyncio.to_thread(purge_expired_deregistered_users)
        except sqlite3.Error:
            LOGGER.exception("Failed to purge expired deregistered accounts.")
        await asyncio.sleep(ACCOUNT_CLEANUP_INTERVAL_SECONDS)


def has_active_admin(connection: sqlite3.Connection) -> bool:
    return connection.execute(
        """SELECT 1 FROM users
           WHERE role_name = 'admin' AND is_active = 1 AND is_suspended = 0
           LIMIT 1"""
    ).fetchone() is not None


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
                is_suspended INTEGER NOT NULL DEFAULT 0,
                deregistered_at TEXT,
                purge_after TEXT,
                keep_data INTEGER NOT NULL DEFAULT 0,
                profile_picture BLOB,
                profile_picture_mime_type TEXT,
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
            CREATE TABLE IF NOT EXISTS chat_access_grants (
                user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                granted_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                granted_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS chats (
                id INTEGER PRIMARY KEY,
                chat_type TEXT NOT NULL CHECK(chat_type IN ('direct', 'group')),
                title TEXT NOT NULL DEFAULT '',
                created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS chat_members (
                chat_id INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                added_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                joined_at TEXT NOT NULL,
                PRIMARY KEY (chat_id, user_id)
            );
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY,
                chat_id INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
                sender_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                body TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS chat_attachments (
                id INTEGER PRIMARY KEY,
                message_id INTEGER NOT NULL REFERENCES chat_messages(id) ON DELETE CASCADE,
                shared_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                file_name TEXT NOT NULL,
                mime_type TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                file_data BLOB NOT NULL,
                source_type TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS chat_members_user_idx ON chat_members(user_id, chat_id);
            CREATE INDEX IF NOT EXISTS chat_messages_chat_idx ON chat_messages(chat_id, id);
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
        user_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(users)").fetchall()
        }
        if "is_suspended" not in user_columns:
            connection.execute(
                "ALTER TABLE users ADD COLUMN is_suspended INTEGER NOT NULL DEFAULT 0"
            )
        if "profile_picture" not in user_columns:
            connection.execute("ALTER TABLE users ADD COLUMN profile_picture BLOB")
        if "profile_picture_mime_type" not in user_columns:
            connection.execute("ALTER TABLE users ADD COLUMN profile_picture_mime_type TEXT")
        if "deregistered_at" not in user_columns:
            connection.execute("ALTER TABLE users ADD COLUMN deregistered_at TEXT")
        if "purge_after" not in user_columns:
            connection.execute("ALTER TABLE users ADD COLUMN purge_after TEXT")
        if "keep_data" not in user_columns:
            connection.execute(
                "ALTER TABLE users ADD COLUMN keep_data INTEGER NOT NULL DEFAULT 0"
            )
        legacy_deregistered = connection.execute(
            """SELECT id FROM users
               WHERE is_active = 0 AND deregistered_at IS NULL"""
        ).fetchall()
        for account in legacy_deregistered:
            deregistered_at = datetime.now(timezone.utc)
            purge_after = add_calendar_months(deregistered_at, ACCOUNT_RETENTION_MONTHS)
            connection.execute(
                """UPDATE users SET deregistered_at = ?, purge_after = ?
                   WHERE id = ?""",
                (deregistered_at.isoformat(), purge_after.isoformat(), account["id"]),
            )
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
            """SELECT users.id, users.username, users.role_name,
                      users.profile_picture_mime_type, sessions.csrf_token
               FROM sessions JOIN users ON users.id = sessions.user_id
               WHERE sessions.token_hash = ? AND sessions.expires_at > ?
                 AND users.is_active = 1 AND users.is_suspended = 0""",
            (token_hash, now),
        ).fetchone()
    return (row, token_hash) if row else None


def user_has_permission(user_id: int, permission: str) -> bool:
    with get_connection() as connection:
        result = connection.execute(
            """SELECT 1 FROM users
               JOIN role_permissions ON role_permissions.role_name = users.role_name
               WHERE users.id = ? AND role_permissions.permission_name = ?
                 AND users.is_active = 1 AND users.is_suspended = 0""",
            (user_id, permission),
        ).fetchone()
    return result is not None


def user_can_chat(user_id: int) -> bool:
    if user_has_permission(user_id, "chat:access"):
        return True
    with get_connection() as connection:
        grant = connection.execute(
            """SELECT 1 FROM chat_access_grants
               JOIN users ON users.id = chat_access_grants.user_id
               WHERE users.id = ? AND users.is_active = 1 AND users.is_suspended = 0""",
            (user_id,),
        ).fetchone()
    return grant is not None


def get_chat_sources(user_id: int) -> list[dict[str, Any]]:
    with get_connection() as connection:
        documents = connection.execute(
            """SELECT id, title, original_name, mime_type, size_bytes
               FROM uploaded_documents WHERE user_id = ?
               ORDER BY created_at DESC, id DESC LIMIT 100""",
            (user_id,),
        ).fetchall()
        outputs = connection.execute(
            """SELECT id, title, output_format, created_at
               FROM generated_outputs
               WHERE user_id = ? AND is_verified = 1 AND is_rehydrated = 1
               ORDER BY created_at DESC, id DESC LIMIT 100""",
            (user_id,),
        ).fetchall()
        reports = connection.execute(
            """SELECT id, title, category, created_at
               FROM verified_reports
               WHERE user_id = ? AND is_verified = 1 AND is_rehydrated = 1
               ORDER BY created_at DESC, id DESC LIMIT 100""",
            (user_id,),
        ).fetchall()
    sources = [
        {
            "key": f"document:{row['id']}",
            "label": f"Document: {row['title']} ({row['original_name']})",
            "source_type": "document",
            "source_id": row["id"],
        }
        for row in documents
    ]
    sources.extend(
        {
            "key": f"output:{row['id']}",
            "label": f"Verified {row['output_format']}: {row['title']}",
            "source_type": "output",
            "source_id": row["id"],
        }
        for row in outputs
    )
    sources.extend(
        {
            "key": f"report:{row['id']}",
            "label": f"Verified {row['category']}: {row['title']}",
            "source_type": "report",
            "source_id": row["id"],
        }
        for row in reports
    )
    return sources


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
                """SELECT users.id, users.username, users.role_name, users.created_at,
                          users.profile_picture_mime_type,
                          users.is_active, users.is_suspended, users.deregistered_at,
                          users.purge_after, users.keep_data,
                          CASE WHEN users.role_name IN ('admin', 'analyst') THEN 1
                               WHEN chat_access_grants.user_id IS NOT NULL THEN 1
                               ELSE 0 END AS chat_enabled
                   FROM users
                   LEFT JOIN chat_access_grants ON chat_access_grants.user_id = users.id
                   ORDER BY users.is_active DESC, users.username COLLATE NOCASE"""
            ).fetchall()
        permissions = connection.execute(
            """SELECT permission_name FROM role_permissions
               WHERE role_name = ? ORDER BY permission_name""",
            (user["role_name"],),
        ).fetchall()
    session = get_user_session(request)
    return {
        "user_id": user["id"],
        "username": user["username"],
        "role": user["role_name"],
        "can_chat": user_can_chat(user["id"]),
        "has_profile_picture": bool(user["profile_picture_mime_type"]),
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


def login_csrf_is_valid(request: Request, submitted_token: str) -> bool:
    cookie_token = request.cookies.get(LOGIN_CSRF_COOKIE, "")
    return bool(cookie_token and hmac.compare_digest(cookie_token, submitted_token))


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


def profile_picture_mime_type(image_data: bytes) -> str | None:
    if image_data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if image_data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if image_data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(image_data) >= 12 and image_data[:4] == b"RIFF" and image_data[8:12] == b"WEBP":
        return "image/webp"
    return None


@app.get("/", response_class=HTMLResponse)
async def read_home(request: Request):
    if get_user_session(request):
        return RedirectResponse("/dashboard", status_code=303)
    with get_connection() as connection:
        admin_exists = has_active_admin(connection)
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
        admin_exists = has_active_admin(connection)
    if not admin_exists:
        return RedirectResponse("/setup", status_code=303)
    return render_login(request, {"mode": "register"})


@app.post("/register", response_class=HTMLResponse)
async def register(request: Request):
    form = await request.form()
    submitted_csrf = str(form.get("csrf_token", ""))
    if not login_csrf_is_valid(request, submitted_csrf):
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
            admin_exists = has_active_admin(connection)
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
        admin_exists = has_active_admin(connection)
    if admin_exists:
        return RedirectResponse("/", status_code=303)
    return render_login(request, {"mode": "setup"})


@app.post("/setup", response_class=HTMLResponse)
async def setup_first_admin(request: Request):
    form = await request.form()
    submitted_csrf = str(form.get("csrf_token", ""))
    if not login_csrf_is_valid(request, submitted_csrf):
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
            admin_exists = has_active_admin(connection)
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
    if not login_csrf_is_valid(request, submitted_csrf):
        return render_login(
            request,
            {"mode": "login", "error": "Your sign-in form expired. Please try again."},
            status_code=403,
        )
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))
    with get_connection() as connection:
        user = connection.execute(
            """SELECT id, username, password_hash, is_active, is_suspended
               FROM users WHERE username = ? COLLATE NOCASE""",
            (username,),
        ).fetchone()
    password_hash = user["password_hash"] if user else DUMMY_PASSWORD_HASH
    authenticated = verify_password(password, password_hash)
    if not user or not user["is_active"] or user["is_suspended"] or not authenticated:
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


@app.get("/account/profile-picture")
async def get_profile_picture(request: Request):
    session = get_user_session(request)
    if not session:
        return Response(status_code=401)
    with get_connection() as connection:
        profile = connection.execute(
            "SELECT profile_picture, profile_picture_mime_type FROM users WHERE id = ?",
            (session[0]["id"],),
        ).fetchone()
    if not profile or not profile["profile_picture"] or not profile["profile_picture_mime_type"]:
        return Response(status_code=404)
    return Response(
        content=profile["profile_picture"],
        media_type=profile["profile_picture_mime_type"],
        headers={"Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff"},
    )


@app.get("/admin/users/{target_user_id}/profile-picture")
async def get_user_profile_picture(target_user_id: int, request: Request):
    session = get_user_session(request)
    if not session:
        return Response(status_code=401)
    if not user_has_permission(session[0]["id"], "users:manage"):
        return Response(status_code=403)
    with get_connection() as connection:
        profile = connection.execute(
            """SELECT profile_picture, profile_picture_mime_type
               FROM users WHERE id = ?""",
            (target_user_id,),
        ).fetchone()
    if not profile or not profile["profile_picture"] or not profile["profile_picture_mime_type"]:
        return Response(status_code=404)
    return Response(
        content=profile["profile_picture"],
        media_type=profile["profile_picture_mime_type"],
        headers={"Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff"},
    )


@app.post("/account/profile")
async def update_profile(request: Request):
    session = get_user_session(request)
    if not session:
        return RedirectResponse("/?error=Sign+in+to+continue", status_code=303)
    form = await request.form()
    if not csrf_is_valid(request, str(form.get("csrf_token", ""))):
        return HTMLResponse("Invalid request token.", status_code=403)

    username = str(form.get("username", "")).strip()
    if not valid_username(username):
        return RedirectResponse(
            "/dashboard?error=Use+3-64+letters,+numbers,+underscores+or+hyphens",
            status_code=303,
        )

    uploaded_picture = form.get("profile_picture")
    filename = str(getattr(uploaded_picture, "filename", "")).strip()
    picture_data: bytes | None = None
    picture_mime_type: str | None = None
    if filename:
        picture_data = await uploaded_picture.read(MAX_PROFILE_PICTURE_BYTES + 1)
        if len(picture_data) > MAX_PROFILE_PICTURE_BYTES:
            return RedirectResponse(
                "/dashboard?error=Profile+picture+must+be+2+MB+or+less",
                status_code=303,
            )
        picture_mime_type = profile_picture_mime_type(picture_data)
        if not picture_mime_type:
            return RedirectResponse(
                "/dashboard?error=Use+a+JPEG,+PNG,+GIF+or+WebP+profile+picture",
                status_code=303,
            )

    remove_picture = str(form.get("remove_profile_picture", "")) == "1"
    try:
        with get_connection() as connection:
            if picture_data is not None:
                connection.execute(
                    """UPDATE users SET username = ?, profile_picture = ?,
                              profile_picture_mime_type = ? WHERE id = ?""",
                    (username, picture_data, picture_mime_type, session[0]["id"]),
                )
            elif remove_picture:
                connection.execute(
                    """UPDATE users SET username = ?, profile_picture = NULL,
                              profile_picture_mime_type = NULL WHERE id = ?""",
                    (username, session[0]["id"]),
                )
            else:
                connection.execute(
                    "UPDATE users SET username = ? WHERE id = ?",
                    (username, session[0]["id"]),
                )
    except sqlite3.IntegrityError:
        return RedirectResponse(
            "/dashboard?error=That+username+already+exists",
            status_code=303,
        )
    return RedirectResponse("/dashboard?success=Profile+updated", status_code=303)


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
    if not user_has_permission(user["id"], "documents:upload"):
        return HTMLResponse("You do not have permission to upload documents.", status_code=403)
    context = user_context(request, user)
    context.update({
        "page": "upload",
        "error": request.query_params.get("error"),
        "success": request.query_params.get("success"),
        "uploaded_documents": get_uploaded_documents(user["id"]),
    })
    return render_template(request, "dashboard.html", context)


@app.get("/dashboard/memory", response_class=HTMLResponse)
async def memory_dashboard():
    return RedirectResponse("/dashboard/upload", status_code=303)


@app.post("/dashboard/upload")
async def save_uploaded_document(request: Request):
    session = get_user_session(request)
    if not session:
        return RedirectResponse("/?error=Sign+in+to+continue", status_code=303)
    user = session[0]
    if not user_has_permission(user["id"], "documents:upload"):
        return HTMLResponse("You do not have permission to upload documents.", status_code=403)

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
    if not user_has_permission(user["id"], "documents:upload"):
        return HTMLResponse("You do not have permission to manage uploaded documents.", status_code=403)

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
    if not user_has_permission(user["id"], "documents:upload"):
        return HTMLResponse("You do not have permission to manage uploaded documents.", status_code=403)

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
    if not user_has_permission(user["id"], "documents:upload"):
        return HTMLResponse("You do not have permission to manage uploaded documents.", status_code=403)

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
    if not user_has_permission(user["id"], "documents:upload"):
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


@app.get("/chat", response_class=HTMLResponse)
async def chat_page(request: Request):
    session = get_user_session(request)
    if not session:
        return RedirectResponse("/?error=Sign+in+to+continue", status_code=303)
    user = session[0]
    if not user_can_chat(user["id"]):
        return HTMLResponse("Chat access has not been granted to this account.", status_code=403)

    with get_connection() as connection:
        available_users = connection.execute(
            """SELECT u.id, u.username, u.role_name
               FROM users u
               WHERE u.id != ? AND u.is_active = 1 AND u.is_suspended = 0
                 AND (
                     EXISTS (
                         SELECT 1 FROM role_permissions rp
                         WHERE rp.role_name = u.role_name
                           AND rp.permission_name = 'chat:access'
                     )
                     OR EXISTS (
                         SELECT 1 FROM chat_access_grants g WHERE g.user_id = u.id
                     )
                 )
               ORDER BY u.username COLLATE NOCASE""",
            (user["id"],),
        ).fetchall()
        chats = connection.execute(
            """SELECT c.id, c.chat_type, c.title, c.created_by, c.created_at,
                      (SELECT m.body FROM chat_messages m
                       WHERE m.chat_id = c.id ORDER BY m.id DESC LIMIT 1) AS last_message,
                      (SELECT m.created_at FROM chat_messages m
                       WHERE m.chat_id = c.id ORDER BY m.id DESC LIMIT 1) AS last_message_at
               FROM chats c
               JOIN chat_members mine ON mine.chat_id = c.id AND mine.user_id = ?
               ORDER BY COALESCE(last_message_at, c.created_at) DESC, c.id DESC""",
            (user["id"],),
        ).fetchall()
        chat_list = []
        for chat in chats:
            names = connection.execute(
                """SELECT u.username FROM chat_members cm
                   JOIN users u ON u.id = cm.user_id
                   WHERE cm.chat_id = ? AND cm.user_id != ?
                   ORDER BY u.username COLLATE NOCASE""",
                (chat["id"], user["id"]),
            ).fetchall()
            chat_list.append({
                **dict(chat),
                "display_title": chat["title"] if chat["chat_type"] == "group"
                    else (", ".join(row["username"] for row in names) or "Direct chat"),
                "participant_names": ", ".join(row["username"] for row in names),
            })

        selected_chat_id = request.query_params.get("chat_id", "")
        selected_chat = None
        messages: list[dict[str, Any]] = []
        member_ids: set[int] = set()
        if selected_chat_id.isdigit():
            selected_chat = connection.execute(
                """SELECT c.id, c.chat_type, c.title, c.created_by, c.created_at
                   FROM chats c JOIN chat_members cm ON cm.chat_id = c.id
                   WHERE c.id = ? AND cm.user_id = ?""",
                (int(selected_chat_id), user["id"]),
            ).fetchone()
            if not selected_chat:
                return HTMLResponse("Conversation not found.", status_code=404)
        if selected_chat:
            member_rows = connection.execute(
                """SELECT u.id, u.username, u.role_name
                   FROM chat_members cm JOIN users u ON u.id = cm.user_id
                   WHERE cm.chat_id = ? ORDER BY u.username COLLATE NOCASE""",
                (selected_chat["id"],),
            ).fetchall()
            member_ids = {row["id"] for row in member_rows}
            rows = connection.execute(
                """SELECT m.id, m.sender_id, COALESCE(u.username, 'Former user') AS sender_name,
                          m.body, m.created_at
                   FROM chat_messages m LEFT JOIN users u ON u.id = m.sender_id
                   WHERE m.chat_id = ? ORDER BY m.id DESC LIMIT 100""",
                (selected_chat["id"],),
            ).fetchall()
            messages = [dict(row) for row in reversed(rows)]
            if messages:
                message_ids = [message["id"] for message in messages]
                placeholders = ",".join("?" for _ in message_ids)
                attachments = connection.execute(
                    f"""SELECT id, message_id, file_name, mime_type, size_bytes, source_type
                        FROM chat_attachments WHERE message_id IN ({placeholders})
                        ORDER BY id""",
                    message_ids,
                ).fetchall()
                by_message: dict[int, list[dict[str, Any]]] = {}
                for attachment in attachments:
                    by_message.setdefault(attachment["message_id"], []).append(dict(attachment))
                for message in messages:
                    message["attachments"] = by_message.get(message["id"], [])
            else:
                for message in messages:
                    message["attachments"] = []
            selected_chat = {
                **dict(selected_chat),
                "participant_names": ", ".join(row["username"] for row in member_rows),
                "members": [dict(row) for row in member_rows],
                "is_manager": user["role_name"] == "admin" or selected_chat["created_by"] == user["id"],
            }

    context = user_context(request, user)
    context.update({
        "page": "chat",
        "can_chat": True,
        "chat_users": [dict(row) for row in available_users],
        "chat_available_users": [
            dict(row) for row in available_users if row["id"] not in member_ids
        ],
        "chats": chat_list,
        "selected_chat": selected_chat,
        "chat_member_ids": member_ids,
        "messages": messages,
        "chat_sources": get_chat_sources(user["id"]),
        "error": request.query_params.get("error"),
        "success": request.query_params.get("success"),
        "chat_message_limit": MAX_CHAT_MESSAGE_LENGTH,
    })
    response = render_template(request, "dashboard.html", context)
    response.headers["Cache-Control"] = "private, no-store"
    return response


@app.post("/chat/create")
async def create_chat(request: Request):
    session = get_user_session(request)
    if not session:
        return RedirectResponse("/?error=Sign+in+to+continue", status_code=303)
    user = session[0]
    if not user_can_chat(user["id"]):
        return HTMLResponse("Chat access has not been granted to this account.", status_code=403)
    form = await request.form()
    if not csrf_is_valid(request, str(form.get("csrf_token", ""))):
        return HTMLResponse("Invalid request token.", status_code=403)

    chat_type = str(form.get("chat_type", "direct")).strip().lower()
    title = str(form.get("title", "")).strip()
    if chat_type not in {"direct", "group"}:
        return RedirectResponse("/chat?error=Choose+a+valid+chat+type", status_code=303)
    if len(title) > 80 or (chat_type == "group" and not title):
        return RedirectResponse("/chat?error=Group+names+must+be+1-80+characters", status_code=303)
    try:
        recipient_ids = sorted({int(value) for value in form.getlist("recipient_ids")})
    except (TypeError, ValueError):
        return RedirectResponse("/chat?error=Choose+valid+chat+members", status_code=303)
    minimum_recipients = 1 if chat_type == "direct" else 2
    if (
        len(recipient_ids) < minimum_recipients
        or (chat_type == "direct" and len(recipient_ids) != 1)
        or len(recipient_ids) + 1 > MAX_CHAT_MEMBERS
        or user["id"] in recipient_ids
    ):
        return RedirectResponse("/chat?error=Choose+valid+chat+members", status_code=303)
    if any(not user_can_chat(recipient_id) for recipient_id in recipient_ids):
        return RedirectResponse("/chat?error=Every+member+must+have+chat+access", status_code=303)

    now = datetime.now(timezone.utc).isoformat()
    with get_connection() as connection:
        if chat_type == "direct":
            existing = connection.execute(
                """SELECT c.id FROM chats c
                   WHERE c.chat_type = 'direct'
                     AND (SELECT COUNT(*) FROM chat_members cm WHERE cm.chat_id = c.id) = 2
                     AND EXISTS (SELECT 1 FROM chat_members cm
                                 WHERE cm.chat_id = c.id AND cm.user_id = ?)
                     AND EXISTS (SELECT 1 FROM chat_members cm
                                 WHERE cm.chat_id = c.id AND cm.user_id = ?)""",
                (user["id"], recipient_ids[0]),
            ).fetchone()
            if existing:
                return RedirectResponse(f"/chat?chat_id={existing['id']}", status_code=303)
        cursor = connection.execute(
            "INSERT INTO chats (chat_type, title, created_by, created_at) VALUES (?, ?, ?, ?)",
            (chat_type, title if chat_type == "group" else "", user["id"], now),
        )
        chat_id = cursor.lastrowid
        connection.executemany(
            """INSERT INTO chat_members (chat_id, user_id, added_by, joined_at)
               VALUES (?, ?, ?, ?)""",
            [(chat_id, member_id, user["id"], now) for member_id in [user["id"], *recipient_ids]],
        )
    return RedirectResponse(f"/chat?chat_id={chat_id}", status_code=303)


@app.get("/chat/api/{chat_id}/updates")
async def get_chat_updates(chat_id: int, request: Request, after: int = 0):
    session = get_user_session(request)
    if not session:
        return JSONResponse({"error": "Sign in to continue."}, status_code=401)
    user = session[0]
    if not user_can_chat(user["id"]):
        return JSONResponse({"error": "Chat access is not enabled."}, status_code=403)
    if after < 0:
        return JSONResponse({"error": "Invalid message cursor."}, status_code=400)
    with get_connection() as connection:
        member = connection.execute(
            "SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?",
            (chat_id, user["id"]),
        ).fetchone()
        if not member:
            return JSONResponse({"error": "Conversation not found."}, status_code=404)
        messages = connection.execute(
            """SELECT m.id, m.sender_id, COALESCE(u.username, 'Former user') AS sender_name,
                      m.body, m.created_at
               FROM chat_messages m LEFT JOIN users u ON u.id = m.sender_id
               WHERE m.chat_id = ? AND m.id > ?
               ORDER BY m.id LIMIT 100""",
            (chat_id, after),
        ).fetchall()
        result = []
        for message in messages:
            attachments = connection.execute(
                """SELECT id, file_name, mime_type, size_bytes, source_type
                   FROM chat_attachments WHERE message_id = ? ORDER BY id""",
                (message["id"],),
            ).fetchall()
            result.append({
                **dict(message),
                "attachments": [dict(attachment) for attachment in attachments],
            })
    response = JSONResponse({"messages": result})
    response.headers["Cache-Control"] = "private, no-store"
    return response


@app.post("/chat/{chat_id}/messages")
async def send_chat_message(chat_id: int, request: Request):
    session = get_user_session(request)
    if not session:
        return RedirectResponse("/?error=Sign+in+to+continue", status_code=303)
    user = session[0]
    if not user_can_chat(user["id"]):
        return HTMLResponse("Chat access has not been granted to this account.", status_code=403)
    form = await request.form()
    if not csrf_is_valid(request, str(form.get("csrf_token", ""))):
        return HTMLResponse("Invalid request token.", status_code=403)

    body = str(form.get("body", "")).strip()
    source_key = str(form.get("source_key", "")).strip()
    if len(body) > MAX_CHAT_MESSAGE_LENGTH:
        return RedirectResponse(f"/chat?chat_id={chat_id}&error=Messages+must+be+{MAX_CHAT_MESSAGE_LENGTH}+characters+or+less", status_code=303)
    if not body and not source_key:
        return RedirectResponse(f"/chat?chat_id={chat_id}&error=Write+a+message+or+choose+a+file", status_code=303)

    with get_connection() as connection:
        member = connection.execute(
            """SELECT 1 FROM chat_members
               WHERE chat_id = ? AND user_id = ?""",
            (chat_id, user["id"]),
        ).fetchone()
        if not member:
            return HTMLResponse("You are not a member of this conversation.", status_code=403)

        attachment_data = None
        if source_key:
            try:
                source_type, source_id_text = source_key.split(":", 1)
                source_id = int(source_id_text)
            except (ValueError, TypeError):
                return RedirectResponse(f"/chat?chat_id={chat_id}&error=Choose+a+valid+file", status_code=303)
            if source_type == "document":
                source = connection.execute(
                    """SELECT original_name, mime_type, size_bytes, length(file_data) AS file_size
                       FROM uploaded_documents WHERE id = ? AND user_id = ?""",
                    (source_id, user["id"]),
                ).fetchone()
                if not source:
                    return RedirectResponse(f"/chat?chat_id={chat_id}&error=That+document+is+not+available+to+you", status_code=303)
                if source["file_size"] > MAX_CHAT_ATTACHMENT_BYTES:
                    return RedirectResponse(f"/chat?chat_id={chat_id}&error=Shared+files+must+be+10+MB+or+smaller", status_code=303)
                file_data = connection.execute(
                    "SELECT file_data FROM uploaded_documents WHERE id = ? AND user_id = ?",
                    (source_id, user["id"]),
                ).fetchone()["file_data"]
                mime_type = (
                    source["mime_type"]
                    if source["mime_type"] in ALLOWED_UPLOAD_MIME_TYPES
                    else "application/octet-stream"
                )
                attachment_data = (
                    source["original_name"], mime_type, source["file_size"],
                    file_data, "uploaded-document",
                )
            elif source_type in {"output", "report"}:
                table = "generated_outputs" if source_type == "output" else "verified_reports"
                source = connection.execute(
                    f"""SELECT title, content FROM {table}
                        WHERE id = ? AND user_id = ? AND is_verified = 1 AND is_rehydrated = 1""",
                    (source_id, user["id"]),
                ).fetchone()
                if not source:
                    return RedirectResponse(f"/chat?chat_id={chat_id}&error=Only+verified+transformed+files+can+be+shared", status_code=303)
                if len(source["content"].encode("utf-8")) > MAX_CHAT_ATTACHMENT_BYTES:
                    return RedirectResponse(f"/chat?chat_id={chat_id}&error=Shared+files+must+be+10+MB+or+smaller", status_code=303)
                pdf_data = build_summary_pdf(
                    escape(source["title"]),
                    escape(source["content"]),
                )
                safe_stem = "".join(
                    character if character.isalnum() or character in "-_" else "-"
                    for character in source["title"]
                ).strip("-_")[:80] or "transformed-file"
                attachment_data = (
                    f"{safe_stem}.pdf", "application/pdf", len(pdf_data), pdf_data,
                    "transformed-output",
                )
            else:
                return RedirectResponse(f"/chat?chat_id={chat_id}&error=Choose+a+valid+file", status_code=303)
            if attachment_data[2] > MAX_CHAT_ATTACHMENT_BYTES:
                return RedirectResponse(f"/chat?chat_id={chat_id}&error=Shared+files+must+be+10+MB+or+smaller", status_code=303)

        now = datetime.now(timezone.utc).isoformat()
        cursor = connection.execute(
            """INSERT INTO chat_messages (chat_id, sender_id, body, created_at)
               VALUES (?, ?, ?, ?)""",
            (chat_id, user["id"], body, now),
        )
        if attachment_data:
            connection.execute(
                """INSERT INTO chat_attachments
                   (message_id, shared_by, file_name, mime_type, size_bytes, file_data,
                    source_type, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (cursor.lastrowid, user["id"], *attachment_data, now),
            )
    return RedirectResponse(f"/chat?chat_id={chat_id}", status_code=303)


@app.post("/chat/{chat_id}/members")
async def manage_chat_member(chat_id: int, request: Request):
    session = get_user_session(request)
    if not session:
        return RedirectResponse("/?error=Sign+in+to+continue", status_code=303)
    user = session[0]
    if not user_can_chat(user["id"]):
        return HTMLResponse("Chat access has not been granted to this account.", status_code=403)
    form = await request.form()
    if not csrf_is_valid(request, str(form.get("csrf_token", ""))):
        return HTMLResponse("Invalid request token.", status_code=403)
    try:
        target_user_id = int(str(form.get("user_id", "")))
    except ValueError:
        return RedirectResponse(f"/chat?chat_id={chat_id}&error=Choose+a+valid+member", status_code=303)
    intent = str(form.get("intent", "")).strip()
    with get_connection() as connection:
        chat = connection.execute(
            """SELECT c.chat_type, c.created_by
               FROM chats c JOIN chat_members cm ON cm.chat_id = c.id
               WHERE c.id = ? AND cm.user_id = ?""",
            (chat_id, user["id"]),
        ).fetchone()
        if not chat or chat["chat_type"] != "group":
            return HTMLResponse("Group chat not found.", status_code=404)
        if user["role_name"] != "admin" and chat["created_by"] != user["id"]:
            return HTMLResponse("Only the group creator or an admin can manage members.", status_code=403)
        if intent == "add":
            if not user_can_chat(target_user_id):
                return RedirectResponse(f"/chat?chat_id={chat_id}&error=That+user+does+not+have+chat+access", status_code=303)
            eligible = connection.execute(
                """SELECT 1 FROM users WHERE id = ? AND is_active = 1 AND is_suspended = 0""",
                (target_user_id,),
            ).fetchone()
            count = connection.execute(
                "SELECT COUNT(*) FROM chat_members WHERE chat_id = ?",
                (chat_id,),
            ).fetchone()[0]
            if not eligible or count >= MAX_CHAT_MEMBERS:
                return RedirectResponse(f"/chat?chat_id={chat_id}&error=Cannot+add+that+member", status_code=303)
            connection.execute(
                """INSERT OR IGNORE INTO chat_members
                   (chat_id, user_id, added_by, joined_at) VALUES (?, ?, ?, ?)""",
                (chat_id, target_user_id, user["id"], datetime.now(timezone.utc).isoformat()),
            )
        elif intent == "remove":
            if target_user_id == user["id"] and chat["created_by"] == user["id"]:
                return RedirectResponse(f"/chat?chat_id={chat_id}&error=Group+creators+cannot+leave+their+own+group", status_code=303)
            connection.execute(
                "DELETE FROM chat_members WHERE chat_id = ? AND user_id = ?",
                (chat_id, target_user_id),
            )
        else:
            return RedirectResponse(f"/chat?chat_id={chat_id}&error=Choose+a+valid+member+action", status_code=303)
    return RedirectResponse(f"/chat?chat_id={chat_id}", status_code=303)


@app.get("/chat/attachments/{attachment_id}")
async def get_chat_attachment(attachment_id: int, request: Request):
    session = get_user_session(request)
    if not session:
        return Response(status_code=401)
    user = session[0]
    if not user_can_chat(user["id"]):
        return Response(status_code=403)
    with get_connection() as connection:
        attachment = connection.execute(
            """SELECT a.file_name, a.mime_type, a.file_data
               FROM chat_attachments a
               JOIN chat_messages m ON m.id = a.message_id
               JOIN chat_members cm ON cm.chat_id = m.chat_id
               WHERE a.id = ? AND cm.user_id = ?""",
            (attachment_id, user["id"]),
        ).fetchone()
    if not attachment:
        return Response(status_code=404)
    download = request.query_params.get("download") == "1"
    if download and user["role_name"] not in {"admin", "analyst"}:
        return Response(status_code=403)
    disposition = "attachment" if download else "inline"
    filename = quote(attachment["file_name"], safe="")
    response = Response(
        content=attachment["file_data"],
        media_type=attachment["mime_type"],
        headers={
            "Cache-Control": "private, no-store",
            "Content-Disposition": f"{disposition}; filename*=UTF-8''{filename}",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "sandbox",
        },
    )
    return response


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
    purge_expired_deregistered_users()
    context = user_context(request, user)
    all_accounts = context["users"]
    account_filter = request.query_params.get("filter", "all")
    if account_filter not in ADMIN_USER_FILTERS:
        account_filter = "all"
    filter_counts = {
        "all": len(all_accounts),
        "active": sum(account["is_active"] and not account["is_suspended"] for account in all_accounts),
        "flagged": sum(account["is_active"] and account["is_suspended"] for account in all_accounts),
        "deregistered": sum(not account["is_active"] for account in all_accounts),
        "scheduled": sum(
            not account["is_active"] and not account["keep_data"] for account in all_accounts
        ),
        "retained": sum(
            not account["is_active"] and account["keep_data"] for account in all_accounts
        ),
    }
    accounts = [
        account
        for account in all_accounts
        if account_filter == "all"
        or (
            account_filter == "active"
            and account["is_active"]
            and not account["is_suspended"]
        )
        or (
            account_filter == "flagged"
            and account["is_active"]
            and account["is_suspended"]
        )
        or (account_filter == "deregistered" and not account["is_active"])
        or (
            account_filter == "scheduled"
            and not account["is_active"]
            and not account["keep_data"]
        )
        or (
            account_filter == "retained"
            and not account["is_active"]
            and account["keep_data"]
        )
    ]
    context.update({
        "page": "admin",
        "error": request.query_params.get("error"),
        "success": request.query_params.get("success"),
        "users": accounts,
        "account_filter": account_filter,
        "account_filter_label": ADMIN_USER_FILTERS[account_filter],
        "account_filter_counts": filter_counts,
        "active_user_count": filter_counts["active"],
        "flagged_user_count": filter_counts["flagged"],
        "deregistered_user_count": filter_counts["deregistered"],
        "scheduled_deletion_count": filter_counts["scheduled"],
        "retained_data_count": filter_counts["retained"],
    })
    return render_template(request, "dashboard.html", context)


@app.post("/admin/users/{target_user_id}/chat-access")
async def update_user_chat_access(target_user_id: int, request: Request):
    session = get_user_session(request)
    if not session:
        return RedirectResponse("/?error=Sign+in+to+continue", status_code=303)
    actor = session[0]
    if not user_has_permission(actor["id"], "users:manage"):
        return HTMLResponse("Administrator permission is required.", status_code=403)
    form = await request.form()
    if not csrf_is_valid(request, str(form.get("csrf_token", ""))):
        return HTMLResponse("Invalid request token.", status_code=403)
    intent = str(form.get("intent", "")).strip()
    if intent not in {"grant", "revoke"}:
        return RedirectResponse("/admin/users?error=Choose+a+valid+chat+access+action", status_code=303)
    with get_connection() as connection:
        target = connection.execute(
            """SELECT role_name, is_active, is_suspended FROM users WHERE id = ?""",
            (target_user_id,),
        ).fetchone()
        if not target or target["role_name"] != "viewer":
            return RedirectResponse("/admin/users?error=Chat+access+grants+are+only+for+viewers", status_code=303)
        if intent == "grant" and (not target["is_active"] or target["is_suspended"]):
            return RedirectResponse("/admin/users?error=Only+active+viewers+can+receive+chat+access", status_code=303)
        if intent == "grant":
            connection.execute(
                """INSERT INTO chat_access_grants (user_id, granted_by, granted_at)
                   VALUES (?, ?, ?)
                   ON CONFLICT(user_id) DO UPDATE SET
                       granted_by = excluded.granted_by,
                       granted_at = excluded.granted_at""",
                (target_user_id, actor["id"], datetime.now(timezone.utc).isoformat()),
            )
        else:
            connection.execute(
                "DELETE FROM chat_access_grants WHERE user_id = ?",
                (target_user_id,),
            )
            connection.execute(
                "DELETE FROM chat_members WHERE user_id = ?",
                (target_user_id,),
            )
    action = "granted" if intent == "grant" else "revoked"
    return RedirectResponse(f"/admin/users?success=Chat+access+{action}", status_code=303)


@app.post("/admin/users/create")
async def create_user_by_admin(request: Request):
    session = get_user_session(request)
    if not session:
        return RedirectResponse("/?error=Sign+in+to+continue", status_code=303)
    actor = session[0]
    if not user_has_permission(actor["id"], "users:manage"):
        return HTMLResponse("Administrator permission is required.", status_code=403)

    form = await request.form()
    if not csrf_is_valid(request, str(form.get("csrf_token", ""))):
        return HTMLResponse("Invalid request token.", status_code=403)

    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))
    password_confirmation = str(form.get("password_confirmation", ""))
    role_name = str(form.get("role", "viewer")).strip().lower()
    if not valid_username(username):
        return RedirectResponse(
            "/admin/users?error=Use+3-64+letters,+numbers,+underscores,+or+hyphens",
            status_code=303,
        )
    if len(password) < 12:
        return RedirectResponse(
            "/admin/users?error=Password+must+contain+at+least+12+characters",
            status_code=303,
        )
    if password != password_confirmation:
        return RedirectResponse(
            "/admin/users?error=Passwords+do+not+match",
            status_code=303,
        )
    if role_name not in ROLE_PERMISSIONS:
        return RedirectResponse("/admin/users?error=Choose+a+valid+role", status_code=303)

    try:
        with get_connection() as connection:
            connection.execute(
                """INSERT INTO users (username, password_hash, role_name, created_at)
                   VALUES (?, ?, ?, ?)""",
                (
                    username,
                    hash_password(password),
                    role_name,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
    except sqlite3.IntegrityError:
        return RedirectResponse(
            "/admin/users?error=That+username+is+already+in+use",
            status_code=303,
        )
    return RedirectResponse(
        "/admin/users?success=Account+created+with+the+selected+role",
        status_code=303,
    )


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
            "SELECT id, role_name, is_active, is_suspended FROM users WHERE id = ?",
            (target_user_id,),
        ).fetchone()
        if not target:
            return RedirectResponse("/admin/users?error=Account+not+found", status_code=303)
        if not target["is_active"]:
            return RedirectResponse("/admin/users?error=Account+is+deregistered", status_code=303)
        if (
            target["role_name"] == "admin"
            and new_role != "admin"
            and not target["is_suspended"]
            and connection.execute(
                """SELECT COUNT(*) FROM users
                   WHERE role_name = 'admin' AND is_active = 1 AND is_suspended = 0"""
            ).fetchone()[0] <= 1
        ):
            return RedirectResponse(
                "/admin/users?error=At+least+one+active+administrator+must+remain",
                status_code=303,
            )
        connection.execute(
            "UPDATE users SET role_name = ? WHERE id = ?",
            (new_role, target_user_id),
        )
    return RedirectResponse("/admin/users?success=Role+updated", status_code=303)


@app.post("/admin/users/{target_user_id}/flag")
async def flag_user(target_user_id: int, request: Request):
    session = get_user_session(request)
    if not session:
        return RedirectResponse("/?error=Sign+in+to+continue", status_code=303)
    actor = session[0]
    if not user_has_permission(actor["id"], "users:manage"):
        return HTMLResponse("Administrator permission is required.", status_code=403)
    form = await request.form()
    if not csrf_is_valid(request, str(form.get("csrf_token", ""))):
        return HTMLResponse("Invalid request token.", status_code=403)
    if target_user_id == actor["id"]:
        return RedirectResponse("/admin/users?error=You+cannot+red-flag+your+own+account", status_code=303)

    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        target = connection.execute(
            "SELECT id, role_name, is_active, is_suspended FROM users WHERE id = ?",
            (target_user_id,),
        ).fetchone()
        if not target:
            return RedirectResponse("/admin/users?error=Account+not+found", status_code=303)
        if not target["is_active"]:
            return RedirectResponse("/admin/users?error=Account+is+deregistered", status_code=303)
        if target["is_suspended"]:
            connection.execute(
                "UPDATE users SET is_suspended = 0 WHERE id = ?", (target_user_id,)
            )
            message = "Red+flag+cleared"
        else:
            if target["role_name"] == "admin" and connection.execute(
                """SELECT COUNT(*) FROM users
                   WHERE role_name = 'admin' AND is_active = 1 AND is_suspended = 0"""
            ).fetchone()[0] <= 1:
                return RedirectResponse(
                    "/admin/users?error=At+least+one+active+administrator+must+remain",
                    status_code=303,
                )
            connection.execute(
                "UPDATE users SET is_suspended = 1 WHERE id = ?", (target_user_id,)
            )
            connection.execute("DELETE FROM sessions WHERE user_id = ?", (target_user_id,))
            message = "Account+red-flagged+and+suspended"
    return RedirectResponse(f"/admin/users?success={message}", status_code=303)


@app.post("/admin/users/{target_user_id}/restore")
async def restore_deregistered_user(target_user_id: int, request: Request):
    session = get_user_session(request)
    if not session:
        return RedirectResponse("/?error=Sign+in+to+continue", status_code=303)
    actor = session[0]
    if not user_has_permission(actor["id"], "users:manage"):
        return HTMLResponse("Administrator permission is required.", status_code=403)
    form = await request.form()
    if not csrf_is_valid(request, str(form.get("csrf_token", ""))):
        return HTMLResponse("Invalid request token.", status_code=403)

    purge_expired_deregistered_users()
    with get_connection() as connection:
        cursor = connection.execute(
            """UPDATE users
               SET is_active = 1, is_suspended = 0, deregistered_at = NULL,
                   purge_after = NULL, keep_data = 0
               WHERE id = ? AND is_active = 0""",
            (target_user_id,),
        )
        if cursor.rowcount == 0:
            return RedirectResponse(
                "/admin/users?error=No+deregistered+account+found",
                status_code=303,
            )
        connection.execute("DELETE FROM sessions WHERE user_id = ?", (target_user_id,))
    return RedirectResponse(
        "/admin/users?success=Account+restored+and+deletion+canceled",
        status_code=303,
    )


@app.post("/admin/users/{target_user_id}/retention")
async def update_deregistered_account_retention(target_user_id: int, request: Request):
    session = get_user_session(request)
    if not session:
        return RedirectResponse("/?error=Sign+in+to+continue", status_code=303)
    actor = session[0]
    if not user_has_permission(actor["id"], "users:manage"):
        return HTMLResponse("Administrator permission is required.", status_code=403)
    form = await request.form()
    if not csrf_is_valid(request, str(form.get("csrf_token", ""))):
        return HTMLResponse("Invalid request token.", status_code=403)

    intent = str(form.get("intent", ""))
    if intent not in {"keep", "schedule"}:
        return RedirectResponse(
            "/admin/users?error=Choose+a+valid+data+retention+action",
            status_code=303,
        )
    purge_expired_deregistered_users()
    with get_connection() as connection:
        account = connection.execute(
            "SELECT id, is_active FROM users WHERE id = ?", (target_user_id,)
        ).fetchone()
        if not account or account["is_active"]:
            return RedirectResponse(
                "/admin/users?error=No+deregistered+account+found",
                status_code=303,
            )
        if intent == "keep":
            connection.execute(
                "UPDATE users SET keep_data = 1, purge_after = NULL WHERE id = ?",
                (target_user_id,),
            )
            message = "Data+retained+indefinitely"
        else:
            purge_after = add_calendar_months(
                datetime.now(timezone.utc), ACCOUNT_RETENTION_MONTHS
            )
            connection.execute(
                "UPDATE users SET keep_data = 0, purge_after = ? WHERE id = ?",
                (purge_after.isoformat(), target_user_id),
            )
            message = "Three-month+deletion+schedule+restarted"
    return RedirectResponse(f"/admin/users?success={message}", status_code=303)


@app.post("/admin/users/{target_user_id}/deregister")
async def deregister_user(target_user_id: int, request: Request):
    session = get_user_session(request)
    if not session:
        return RedirectResponse("/?error=Sign+in+to+continue", status_code=303)
    actor = session[0]
    if not user_has_permission(actor["id"], "users:manage"):
        return HTMLResponse("Administrator permission is required.", status_code=403)
    form = await request.form()
    if not csrf_is_valid(request, str(form.get("csrf_token", ""))):
        return HTMLResponse("Invalid request token.", status_code=403)
    if target_user_id == actor["id"]:
        return RedirectResponse("/admin/users?error=You+cannot+deregister+your+own+account", status_code=303)

    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        target = connection.execute(
            "SELECT id, role_name, is_active, is_suspended FROM users WHERE id = ?",
            (target_user_id,),
        ).fetchone()
        if not target:
            return RedirectResponse("/admin/users?error=Account+not+found", status_code=303)
        if not target["is_active"]:
            return RedirectResponse("/admin/users?error=Account+is+already+deregistered", status_code=303)
        if (
            target["role_name"] == "admin"
            and not target["is_suspended"]
            and connection.execute(
                """SELECT COUNT(*) FROM users
                   WHERE role_name = 'admin' AND is_active = 1 AND is_suspended = 0"""
            ).fetchone()[0] <= 1
        ):
            return RedirectResponse(
                "/admin/users?error=At+least+one+active+administrator+must+remain",
                status_code=303,
            )
        deregistered_at = datetime.now(timezone.utc)
        purge_after = add_calendar_months(
            deregistered_at, ACCOUNT_RETENTION_MONTHS
        )
        connection.execute(
            """UPDATE users
               SET is_active = 0, deregistered_at = ?, purge_after = ?, keep_data = 0
               WHERE id = ?""",
            (
                deregistered_at.isoformat(),
                purge_after.isoformat(),
                target_user_id,
            ),
        )
        connection.execute("DELETE FROM sessions WHERE user_id = ?", (target_user_id,))
    return RedirectResponse(
        "/admin/users?success=Account+deregistered+and+scheduled+for+deletion+in+3+months",
        status_code=303,
    )


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)