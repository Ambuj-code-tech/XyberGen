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
            for username, role in (("admin_user", "admin"), ("regular_user", "viewer")):
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
            self.tokens = {"admin_user": "admin-session", "regular_user": "regular-session"}
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
        self.user_client = TestClient(main.app)
        self.user_client.cookies.set(main.SESSION_COOKIE, self.tokens["regular_user"])

    def tearDown(self):
        self.admin_client.close()
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
        self.assertNotIn("Create viewer account", response.text)
        self.assertIn('name="role"', response.text)
        self.assertNotIn(
            f'action="/admin/users/{self.user_ids["admin_user"]}/flag"',
            response.text,
        )

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
        self.assertIn("Save changes", response.text)

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
