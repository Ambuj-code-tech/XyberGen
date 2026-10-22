import hashlib
import os
import sqlite3
import time
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

os.environ["XYBERGEN_DATABASE"] = os.path.join(
    os.path.dirname(__file__), "test_user_controls.sqlite3"
)

from fastapi.testclient import TestClient

import main


class UserControlTests(unittest.TestCase):
    @contextmanager
    def db_connection(self):
        connection = sqlite3.connect(main.DATABASE_PATH)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def setUp(self):
        if os.path.exists(os.environ["XYBERGEN_DATABASE"]):
            os.remove(os.environ["XYBERGEN_DATABASE"])
        main.DATABASE_PATH = main.Path(os.environ["XYBERGEN_DATABASE"])
        main.initialize_database()

        with self.db_connection() as connection:
            for username, role in (
                ("admin_user", "admin"),
                ("analyst_user", "analyst"),
                ("regular_user", "viewer"),
            ):
                connection.execute(
                    """INSERT INTO users (username, password_hash, role_name, created_at)
                       VALUES (?, ?, ?, ?)""",
                    (
                        username,
                        main.hash_password("TestPassword!123"),
                        role,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
            users = connection.execute("SELECT id, username FROM users").fetchall()
            self.user_ids = {username: user_id for user_id, username in users}
            self.tokens = {
                "admin_user": "admin-session",
                "analyst_user": "analyst-session",
                "regular_user": "regular-session",
            }
            for username, user_id in self.user_ids.items():
                connection.execute(
                    """INSERT INTO sessions
                       (token_hash, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)""",
                    (
                        hashlib.sha256(self.tokens[username].encode()).hexdigest(),
                        user_id,
                        f"csrf-{username}",
                        (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(),
                    ),
                )

        self.admin_client = TestClient(main.app)
        self.admin_client.cookies.set(main.SESSION_COOKIE, self.tokens["admin_user"])
        self.analyst_client = TestClient(main.app)
        self.analyst_client.cookies.set(main.SESSION_COOKIE, self.tokens["analyst_user"])
        self.user_client = TestClient(main.app)
        self.user_client.cookies.set(main.SESSION_COOKIE, self.tokens["regular_user"])

    def tearDown(self):
        self.admin_client.close()
        self.analyst_client.close()
        self.user_client.close()
        if os.path.exists(os.environ["XYBERGEN_DATABASE"]):
            os.remove(os.environ["XYBERGEN_DATABASE"])

    def test_admin_directory_only_offers_red_flag_and_deregister_actions(self):
        response = self.admin_client.get("/admin/users")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Red-flag", response.text)
        self.assertIn("Deregister", response.text)
        self.assertIn("Active accounts", response.text)
        self.assertIn("Red-flagged", response.text)
        self.assertIn('aria-controls="workspace-sidebar"', response.text)
        self.assertIn('class="role-edit-form"', response.text)
        self.assertIn('aria-label="Save role for regular_user"', response.text)
        self.assertIn('class="panel-index">03</span>', response.text)
        self.assertNotIn('class="panel-index">3</span>', response.text)
        self.assertNotIn("Create viewer account", response.text)
        self.assertIn('name="role"', response.text)
        self.assertNotIn(
            f'action="/admin/users/{self.user_ids["admin_user"]}/flag"',
            response.text,
        )

    def test_admin_can_create_accounts_with_selected_or_default_viewer_role(self):
        for username, role in (("new_analyst", "analyst"), ("new_viewer", None)):
            form = {
                "csrf_token": "csrf-admin_user",
                "username": username,
                "password": "StrongPassword!123",
                "password_confirmation": "StrongPassword!123",
            }
            if role:
                form["role"] = role
            response = self.admin_client.post(
                "/admin/users/create",
                data=form,
                follow_redirects=False,
            )
            self.assertEqual(response.status_code, 303)
            with self.db_connection() as connection:
                created = connection.execute(
                    "SELECT role_name, password_hash FROM users WHERE username = ?",
                    (username,),
                ).fetchone()
            self.assertIsNotNone(created)
            self.assertEqual(created[0], role or "viewer")
            self.assertTrue(main.verify_password("StrongPassword!123", created[1]))

    def test_user_creation_rejects_non_admins_invalid_fields_and_bad_csrf(self):
        form = {
            "csrf_token": "csrf-admin_user",
            "username": "new_user",
            "password": "StrongPassword!123",
            "password_confirmation": "StrongPassword!123",
        }
        for client in (self.analyst_client, self.user_client):
            response = client.post("/admin/users/create", data=form)
            self.assertEqual(response.status_code, 403)

        invalid_csrf = dict(form, csrf_token="invalid")
        response = self.admin_client.post("/admin/users/create", data=invalid_csrf)
        self.assertEqual(response.status_code, 403)

        invalid_forms = (
            dict(form, username="x"),
            dict(form, password="short", password_confirmation="short"),
            dict(form, password_confirmation="DifferentPassword!123"),
            dict(form, role="superuser"),
        )
        for invalid_form in invalid_forms:
            response = self.admin_client.post(
                "/admin/users/create",
                data=invalid_form,
                follow_redirects=False,
            )
            self.assertEqual(response.status_code, 303)
            self.assertIn("error=", response.headers["location"])

        duplicate = dict(form, username="regular_user")
        response = self.admin_client.post(
            "/admin/users/create",
            data=duplicate,
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertIn("already+in+use", response.headers["location"])
        with self.db_connection() as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM users WHERE username = 'new_user'"
            ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_admin_can_filter_accounts_by_flagged_and_deregistered_status(self):
        now = datetime.now(timezone.utc)
        with self.db_connection() as connection:
            connection.execute(
                "UPDATE users SET is_suspended = 1 WHERE username = 'regular_user'"
            )
            connection.execute(
                """INSERT INTO users
                   (username, password_hash, role_name, is_active, deregistered_at,
                    purge_after, created_at)
                   VALUES ('scheduled_user', 'hash', 'viewer', 0, ?, ?, ?)""",
                (
                    now.isoformat(),
                    main.add_calendar_months(now, 3).isoformat(),
                    now.isoformat(),
                ),
            )
            connection.execute(
                """INSERT INTO users
                   (username, password_hash, role_name, is_active, deregistered_at,
                    purge_after, keep_data, created_at)
                   VALUES ('retained_user', 'hash', 'viewer', 0, ?, NULL, 1, ?)""",
                (now.isoformat(), now.isoformat()),
            )

        flagged_response = self.admin_client.get("/admin/users?filter=flagged")
        self.assertEqual(flagged_response.status_code, 200)
        self.assertIn("regular_user", flagged_response.text)
        self.assertNotIn("scheduled_user", flagged_response.text)
        self.assertNotIn("retained_user", flagged_response.text)
        self.assertIn('aria-current="page"', flagged_response.text)

        deregistered_response = self.admin_client.get("/admin/users?filter=deregistered")
        self.assertEqual(deregistered_response.status_code, 200)
        self.assertIn("scheduled_user", deregistered_response.text)
        self.assertIn("retained_user", deregistered_response.text)
        self.assertNotIn("regular_user", deregistered_response.text)

        scheduled_response = self.admin_client.get("/admin/users?filter=scheduled")
        self.assertIn("scheduled_user", scheduled_response.text)
        self.assertNotIn("retained_user", scheduled_response.text)

        retained_response = self.admin_client.get("/admin/users?filter=retained")
        self.assertIn("retained_user", retained_response.text)
        self.assertNotIn("scheduled_user", retained_response.text)

    def test_profile_view_shows_identity_and_update_controls(self):
        response = self.user_client.get("/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Profile settings", response.text)
        self.assertIn("SIGNED IN AS", response.text)
        self.assertIn('name="username"', response.text)
        self.assertIn('name="profile_picture"', response.text)
        self.assertIn('class="panel-index">01</span>', response.text)
        self.assertNotIn('class="panel-index">1</span>', response.text)
        self.assertIn("Save changes", response.text)

    def test_admin_grants_and_revokes_chat_access_for_viewer(self):
        self.assertEqual(self.user_client.get("/chat").status_code, 403)
        grant = self.admin_client.post(
            f"/admin/users/{self.user_ids['regular_user']}/chat-access",
            data={"csrf_token": "csrf-admin_user", "intent": "grant"},
            follow_redirects=False,
        )
        self.assertEqual(grant.status_code, 303)
        viewer_chat_page = self.user_client.get("/chat")
        self.assertEqual(viewer_chat_page.status_code, 200)
        self.assertIn('type="checkbox" name="recipient_ids"', viewer_chat_page.text)
        self.assertNotIn('name="recipient_ids" multiple', viewer_chat_page.text)
        self.admin_client.post(
            "/chat/create",
            data={
                "csrf_token": "csrf-admin_user",
                "chat_type": "direct",
                "recipient_ids": str(self.user_ids["regular_user"]),
            },
            follow_redirects=False,
        )

        revoke = self.admin_client.post(
            f"/admin/users/{self.user_ids['regular_user']}/chat-access",
            data={"csrf_token": "csrf-admin_user", "intent": "revoke"},
            follow_redirects=False,
        )
        self.assertEqual(revoke.status_code, 303)
        self.assertEqual(self.user_client.get("/chat").status_code, 403)
        with self.db_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM chat_members WHERE user_id = ?",
                    (self.user_ids["regular_user"],),
                ).fetchone()[0],
                0,
            )

    def test_chat_messages_and_shared_files_are_member_scoped(self):
        self.admin_client.post(
            f"/admin/users/{self.user_ids['regular_user']}/chat-access",
            data={"csrf_token": "csrf-admin_user", "intent": "grant"},
        )
        create = self.admin_client.post(
            "/chat/create",
            data={
                "csrf_token": "csrf-admin_user",
                "chat_type": "direct",
                "recipient_ids": str(self.user_ids["regular_user"]),
            },
            follow_redirects=False,
        )
        self.assertEqual(create.status_code, 303)
        chat_id = int(create.headers["location"].split("chat_id=")[1])

        with self.db_connection() as connection:
            cursor = connection.execute(
                """INSERT INTO uploaded_documents
                   (user_id, title, original_name, mime_type, size_bytes, file_data, created_at)
                   VALUES (?, 'Shared memo', 'memo.txt', 'text/plain', 12, ?, ?)""",
                (
                    self.user_ids["regular_user"],
                    b"private copy",
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            document_id = cursor.lastrowid

        sent = self.user_client.post(
            f"/chat/{chat_id}/messages",
            data={
                "csrf_token": "csrf-regular_user",
                "body": "Sharing the memo",
                "source_key": f"document:{document_id}",
            },
            follow_redirects=False,
        )
        self.assertEqual(sent.status_code, 303)
        updates = self.user_client.get(f"/chat/api/{chat_id}/updates?after=0")
        self.assertEqual(updates.status_code, 200)
        self.assertEqual(updates.json()["messages"][0]["body"], "Sharing the memo")
        viewer_chat = self.user_client.get(f"/chat?chat_id={chat_id}")
        self.assertEqual(viewer_chat.status_code, 200)
        self.assertIn("Sharing the memo", viewer_chat.text)
        self.assertIn("memo.txt", viewer_chat.text)
        attachment_id = int(
            viewer_chat.text.split("/chat/attachments/")[1].split('"')[0]
        )
        self.assertNotIn(
            f'href="/chat/attachments/{attachment_id}?download=1"',
            viewer_chat.text,
        )
        view = self.user_client.get(f"/chat/attachments/{attachment_id}")
        self.assertEqual(view.status_code, 200)
        self.assertEqual(view.content, b"private copy")
        self.assertEqual(
            self.user_client.get(f"/chat/attachments/{attachment_id}?download=1").status_code,
            403,
        )
        admin_download = self.admin_client.get(
            f"/chat/attachments/{attachment_id}?download=1"
        )
        self.assertEqual(admin_download.status_code, 200)
        self.assertIn("attachment;", admin_download.headers["content-disposition"])

        self.assertEqual(
            self.analyst_client.get(f"/chat?chat_id={chat_id}").status_code,
            404,
        )
        self.assertNotIn("Sharing the memo", self.analyst_client.get("/chat").text)

    def test_group_chat_membership_controls(self):
        self.admin_client.post(
            f"/admin/users/{self.user_ids['regular_user']}/chat-access",
            data={"csrf_token": "csrf-admin_user", "intent": "grant"},
        )
        created = self.analyst_client.post(
            "/chat/create",
            data={
                "csrf_token": "csrf-analyst_user",
                "chat_type": "group",
                "title": "Project team",
                "recipient_ids": [
                    str(self.user_ids["admin_user"]),
                    str(self.user_ids["regular_user"]),
                ],
            },
            follow_redirects=False,
        )
        self.assertEqual(created.status_code, 303)
        chat_id = int(created.headers["location"].split("chat_id=")[1])
        group_page = self.analyst_client.get(f"/chat?chat_id={chat_id}")
        self.assertEqual(group_page.status_code, 200)
        self.assertIn("People in this group", group_page.text)
        self.assertIn("Project team", group_page.text)
        self.assertIn("Everyone with chat access is already in this group.", group_page.text)

        denied = self.user_client.post(
            f"/chat/{chat_id}/members",
            data={
                "csrf_token": "csrf-regular_user",
                "intent": "remove",
                "user_id": str(self.user_ids["admin_user"]),
            },
            follow_redirects=False,
        )
        self.assertEqual(denied.status_code, 403)

        removed = self.admin_client.post(
            f"/chat/{chat_id}/members",
            data={
                "csrf_token": "csrf-admin_user",
                "intent": "remove",
                "user_id": str(self.user_ids["regular_user"]),
            },
            follow_redirects=False,
        )
        self.assertEqual(removed.status_code, 303)
        self.assertEqual(self.user_client.get(f"/chat?chat_id={chat_id}").status_code, 404)

    def test_chat_shares_verified_transformed_files_as_copies(self):
        self.admin_client.post(
            f"/admin/users/{self.user_ids['regular_user']}/chat-access",
            data={"csrf_token": "csrf-admin_user", "intent": "grant"},
        )
        created = self.admin_client.post(
            "/chat/create",
            data={
                "csrf_token": "csrf-admin_user",
                "chat_type": "direct",
                "recipient_ids": str(self.user_ids["regular_user"]),
            },
            follow_redirects=False,
        )
        chat_id = int(created.headers["location"].split("chat_id=")[1])
        with self.db_connection() as connection:
            document_cursor = connection.execute(
                """INSERT INTO uploaded_documents
                   (user_id, title, original_name, mime_type, size_bytes, file_data, created_at)
                   VALUES (?, 'Campus source', 'campus.txt', 'text/plain', 6, ?, ?)""",
                (
                    self.user_ids["admin_user"],
                    b"source",
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            cursor = connection.execute(
                """INSERT INTO generated_outputs
                   (user_id, document_id, output_format, title, content,
                    is_verified, is_rehydrated, created_at)
                   VALUES (?, ?, 'Summary', 'Campus update', 'Verified transformed text',
                           1, 1, ?)""",
                (
                    self.user_ids["admin_user"],
                    document_cursor.lastrowid,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            output_id = cursor.lastrowid

        sent = self.admin_client.post(
            f"/chat/{chat_id}/messages",
            data={
                "csrf_token": "csrf-admin_user",
                "source_key": f"output:{output_id}",
            },
            follow_redirects=False,
        )
        self.assertEqual(sent.status_code, 303)
        viewer_chat = self.user_client.get(f"/chat?chat_id={chat_id}")
        self.assertIn("Campus-update.pdf", viewer_chat.text)
        attachment_id = int(
            viewer_chat.text.split("/chat/attachments/")[1].split('"')[0]
        )
        shared_file = self.user_client.get(f"/chat/attachments/{attachment_id}")
        self.assertEqual(shared_file.status_code, 200)
        self.assertEqual(shared_file.headers["content-type"], "application/pdf")
        self.assertTrue(shared_file.content.startswith(b"%PDF"))
        self.assertIn(b"Verified transformed text", shared_file.content)

    def test_analyst_has_chat_access_by_default(self):
        self.assertEqual(self.analyst_client.get("/chat").status_code, 200)

    def test_admin_can_change_another_users_role(self):
        response = self.admin_client.post(
            f"/admin/users/{self.user_ids['regular_user']}/role",
            data={"csrf_token": "csrf-admin_user", "role": "analyst"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertIn("Role+updated", response.headers["location"])
        with self.db_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT role_name FROM users WHERE username = 'regular_user'"
                ).fetchone()[0],
                "analyst",
            )

    def test_admin_cannot_demote_last_active_admin(self):
        response = self.admin_client.post(
            f"/admin/users/{self.user_ids['admin_user']}/role",
            data={"csrf_token": "csrf-admin_user", "role": "viewer"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertIn(
            "At+least+one+active+administrator+must+remain",
            response.headers["location"],
        )
        with self.db_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT role_name FROM users WHERE username = 'admin_user'"
                ).fetchone()[0],
                "admin",
            )

    def test_admin_can_suspend_and_clear_flag_but_cannot_flag_self(self):
        response = self.admin_client.post(
            f"/admin/users/{self.user_ids['regular_user']}/flag",
            data={"csrf_token": "csrf-admin_user"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        with self.db_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT is_suspended FROM users WHERE username = 'regular_user'"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM sessions WHERE user_id = ?",
                    (self.user_ids["regular_user"],),
                ).fetchone()[0],
                0,
            )
        self.assertEqual(
            self.user_client.get("/dashboard", follow_redirects=False).status_code,
            303,
        )

        response = self.admin_client.post(
            f"/admin/users/{self.user_ids['regular_user']}/flag",
            data={"csrf_token": "csrf-admin_user"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        with self.db_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT is_suspended FROM users WHERE username = 'regular_user'"
                ).fetchone()[0],
                0,
            )

        response = self.admin_client.post(
            f"/admin/users/{self.user_ids['admin_user']}/flag",
            data={"csrf_token": "csrf-admin_user"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertIn("cannot+red-flag+your+own+account", response.headers["location"])

    def test_deregister_preserves_user_data_and_revokes_sessions(self):
        with self.db_connection() as connection:
            connection.execute(
                """INSERT INTO uploaded_documents
                   (user_id, title, original_name, mime_type, size_bytes, file_data, created_at)
                   VALUES (?, 'Keep data', 'keep.pdf', 'application/pdf', 4, ?, ?)""",
                (
                    self.user_ids["regular_user"],
                    b"data",
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

        response = self.admin_client.post(
            f"/admin/users/{self.user_ids['regular_user']}/deregister",
            data={"csrf_token": "csrf-admin_user"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        with self.db_connection() as connection:
            user = connection.execute(
                """SELECT is_active, deregistered_at, purge_after, keep_data
                   FROM users WHERE username = 'regular_user'"""
            ).fetchone()
            self.assertEqual(user[0], 0)
            self.assertIsNotNone(user[1])
            self.assertEqual(
                datetime.fromisoformat(user[2]).date(),
                main.add_calendar_months(datetime.fromisoformat(user[1]), 3).date(),
            )
            self.assertEqual(user[3], 0)
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM uploaded_documents WHERE user_id = ?",
                    (self.user_ids["regular_user"],),
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM sessions WHERE user_id = ?",
                    (self.user_ids["regular_user"],),
                ).fetchone()[0],
                0,
            )

    def test_restore_cancels_deletion_and_reactivates_account(self):
        with self.db_connection() as connection:
            connection.execute(
                """UPDATE users SET is_active = 0, is_suspended = 1,
                          deregistered_at = ?, purge_after = ?, keep_data = 0
                   WHERE username = 'regular_user'""",
                (
                    datetime.now(timezone.utc).isoformat(),
                    (datetime.now(timezone.utc) + timedelta(days=90)).isoformat(),
                ),
            )
        response = self.admin_client.post(
            f"/admin/users/{self.user_ids['regular_user']}/restore",
            data={"csrf_token": "csrf-admin_user"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        with self.db_connection() as connection:
            user = connection.execute(
                """SELECT is_active, is_suspended, deregistered_at,
                          purge_after, keep_data
                   FROM users WHERE username = 'regular_user'"""
            ).fetchone()
        self.assertEqual(user[:2], (1, 0))
        self.assertEqual(user[2:], (None, None, 0))

    def test_admin_can_choose_restore_or_keep_data_for_deregistered_user(self):
        purge_after = main.add_calendar_months(datetime.now(timezone.utc), 3)
        with self.db_connection() as connection:
            connection.execute(
                """UPDATE users SET is_active = 0, deregistered_at = ?,
                          purge_after = ?, keep_data = 0
                   WHERE username = 'regular_user'""",
                (datetime.now(timezone.utc).isoformat(), purge_after.isoformat()),
            )
        response = self.admin_client.get("/admin/users")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Delete after", response.text)
        self.assertIn("Restore account", response.text)
        self.assertIn("Keep data", response.text)

    def test_cleanup_permanently_removes_expired_account_and_dependent_data(self):
        now = datetime.now(timezone.utc)
        with self.db_connection() as connection:
            document_cursor = connection.execute(
                """INSERT INTO uploaded_documents
                   (user_id, title, original_name, mime_type, size_bytes, file_data, created_at)
                   VALUES (?, 'Expired source', 'source.pdf', 'application/pdf', 4, ?, ?)""",
                (
                    self.user_ids["regular_user"],
                    b"data",
                    now.isoformat(),
                ),
            )
            document_id = document_cursor.lastrowid
            connection.execute(
                """INSERT INTO document_output_options
                   (user_id, document_id, created_at)
                   VALUES (?, ?, ?)""",
                (self.user_ids["regular_user"], document_id, now.isoformat()),
            )
            connection.execute(
                """INSERT INTO verified_reports
                   (user_id, document_id, category, title, content, created_at)
                   VALUES (?, ?, 'X Posts', 'Expired report', 'report data', ?)""",
                (self.user_ids["regular_user"], document_id, now.isoformat()),
            )
            connection.execute(
                """INSERT INTO generated_outputs
                   (user_id, document_id, output_format, title, content, created_at)
                   VALUES (?, ?, 'Summary', 'Expired output', 'output data', ?)""",
                (self.user_ids["regular_user"], document_id, now.isoformat()),
            )
            connection.execute(
                """INSERT INTO memory_documents (user_id, title, content, created_at)
                   VALUES (?, 'Legacy memory', 'memory data', ?)""",
                (self.user_ids["regular_user"], now.isoformat()),
            )
            connection.execute(
                """UPDATE users SET is_active = 0, deregistered_at = ?,
                          purge_after = ?, keep_data = 0
                   WHERE id = ?""",
                (
                    (now - timedelta(days=91)).isoformat(),
                    (now - timedelta(seconds=1)).isoformat(),
                    self.user_ids["regular_user"],
                ),
            )

        deleted = main.purge_expired_deregistered_users(now)
        self.assertEqual(deleted, 1)
        with self.db_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM users WHERE username = 'regular_user'"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM uploaded_documents"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM document_output_options"
                ).fetchone()[0],
                0,
            )
            for table in (
                "document_output_options",
                "verified_reports",
                "generated_outputs",
                "memory_documents",
            ):
                self.assertEqual(
                    connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0],
                    0,
                )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM sessions WHERE user_id = ?",
                    (self.user_ids["regular_user"],),
                ).fetchone()[0],
                0,
            )

    def test_app_lifespan_automatically_purges_expired_accounts(self):
        now = datetime.now(timezone.utc)
        with self.db_connection() as connection:
            connection.execute(
                """UPDATE users SET is_active = 0, deregistered_at = ?,
                          purge_after = ?, keep_data = 0
                   WHERE id = ?""",
                (
                    (now - timedelta(days=92)).isoformat(),
                    (now - timedelta(seconds=1)).isoformat(),
                    self.user_ids["regular_user"],
                ),
            )

        with TestClient(main.app):
            for _ in range(20):
                with self.db_connection() as connection:
                    user = connection.execute(
                        "SELECT id FROM users WHERE id = ?",
                        (self.user_ids["regular_user"],),
                    ).fetchone()
                if not user:
                    break
                time.sleep(0.05)
        self.assertIsNone(user)

    def test_keep_data_cancels_purge_and_schedule_restarts_three_month_window(self):
        now = datetime.now(timezone.utc)
        with self.db_connection() as connection:
            connection.execute(
                """UPDATE users SET is_active = 0, deregistered_at = ?,
                          purge_after = ?, keep_data = 0
                   WHERE id = ?""",
                (
                    (now - timedelta(days=89)).isoformat(),
                    (now + timedelta(days=1)).isoformat(),
                    self.user_ids["regular_user"],
                ),
            )

        response = self.admin_client.post(
            f"/admin/users/{self.user_ids['regular_user']}/retention",
            data={"csrf_token": "csrf-admin_user", "intent": "keep"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(
            main.purge_expired_deregistered_users(now + timedelta(days=2)),
            0,
        )

        response = self.admin_client.post(
            f"/admin/users/{self.user_ids['regular_user']}/retention",
            data={"csrf_token": "csrf-admin_user", "intent": "schedule"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        with self.db_connection() as connection:
            user = connection.execute(
                "SELECT keep_data, purge_after FROM users WHERE id = ?",
                (self.user_ids["regular_user"],),
            ).fetchone()
        self.assertEqual(user[0], 0)
        deadline = datetime.fromisoformat(user[1])
        self.assertEqual(
            deadline.date(),
            main.add_calendar_months(datetime.now(timezone.utc), 3).date(),
        )

    def test_non_admin_cannot_manage_users_but_can_update_own_profile(self):
        upload_page = self.user_client.get("/dashboard/upload")
        self.assertEqual(upload_page.status_code, 403)

        upload_response = self.user_client.post(
            "/dashboard/upload",
            data={"csrf_token": "csrf-regular_user"},
        )
        self.assertEqual(upload_response.status_code, 403)

        dashboard = self.user_client.get("/dashboard")
        self.assertEqual(dashboard.status_code, 200)
        self.assertNotIn('href="/dashboard/upload"', dashboard.text)
        self.assertNotIn('class="overview-intake"', dashboard.text)
        self.assertNotIn("documents:upload", dashboard.text)

        picture_response = self.user_client.get(
            f"/admin/users/{self.user_ids['admin_user']}/profile-picture"
        )
        self.assertEqual(picture_response.status_code, 403)

        response = self.user_client.post(
            f"/admin/users/{self.user_ids['admin_user']}/deregister",
            data={"csrf_token": "csrf-regular_user"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 403)

        response = self.user_client.post(
            "/account/profile",
            data={"csrf_token": "csrf-regular_user", "username": "new_regular"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        with self.db_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT username FROM users WHERE id = ?",
                    (self.user_ids["regular_user"],),
                ).fetchone()[0],
                "new_regular",
            )

    def test_profile_picture_upload_is_validated_and_served(self):
        response = self.user_client.post(
            "/account/profile",
            data={"csrf_token": "csrf-regular_user", "username": "regular_user"},
            files={"profile_picture": ("avatar.jpg", b"\xff\xd8\xffimage", "image/jpeg")},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        picture = self.user_client.get("/account/profile-picture")
        self.assertEqual(picture.status_code, 200)
        self.assertEqual(picture.headers["content-type"], "image/jpeg")
        self.assertEqual(picture.content, b"\xff\xd8\xffimage")

        admin_picture = self.admin_client.get(
            f"/admin/users/{self.user_ids['regular_user']}/profile-picture"
        )
        self.assertEqual(admin_picture.status_code, 200)
        self.assertEqual(admin_picture.content, b"\xff\xd8\xffimage")
        self.assertEqual(admin_picture.headers["cache-control"], "private, no-store")
        directory = self.admin_client.get("/admin/users")
        self.assertIn(
            f'src="/admin/users/{self.user_ids["regular_user"]}/profile-picture"',
            directory.text,
        )

        response = self.user_client.post(
            "/account/profile",
            data={"csrf_token": "csrf-regular_user", "username": "regular_user"},
            files={"profile_picture": ("avatar.jpg", b"not an image", "image/jpeg")},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertIn("Use+a+JPEG", response.headers["location"])


if __name__ == "__main__":
    unittest.main()
