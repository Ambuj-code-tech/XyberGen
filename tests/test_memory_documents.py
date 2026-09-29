import hashlib
import os
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone

os.environ["XYBERGEN_DATABASE"] = os.path.join(os.path.dirname(__file__), "test_xybergen.sqlite3")

from fastapi.testclient import TestClient

import main


class MemoryDocumentFlowTests(unittest.TestCase):
    def setUp(self):
        if os.path.exists(os.environ["XYBERGEN_DATABASE"]):
            os.remove(os.environ["XYBERGEN_DATABASE"])
        main.DATABASE_PATH = main.Path(os.environ["XYBERGEN_DATABASE"])
        main.initialize_database()

        with sqlite3.connect(main.DATABASE_PATH) as connection:
            connection.execute(
                "INSERT INTO users (username, password_hash, role_name, created_at) VALUES (?, ?, 'viewer', ?)",
                ("memory_user", main.hash_password("Passw0rd!secure"), datetime.now(timezone.utc).isoformat()),
            )
            user_id = connection.execute("SELECT id FROM users WHERE username = 'memory_user'").fetchone()[0]
            token = "session-memory-token"
            connection.execute(
                "INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)",
                (
                    hashlib.sha256(token.encode()).hexdigest(),
                    user_id,
                    "csrf-memory-token",
                    (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(),
                ),
            )

        self.client = TestClient(main.app)
        self.client.cookies.set("xybergen_session", "session-memory-token")

    def tearDown(self):
        if os.path.exists(os.environ["XYBERGEN_DATABASE"]):
            os.remove(os.environ["XYBERGEN_DATABASE"])

    def test_dashboard_upload_page_renders(self):
        self.client.post(
            "/dashboard/upload",
            data={
                "csrf_token": "csrf-memory-token",
                "title": "Family recipe",
            },
            files={"document": ("family_recipe.pdf", b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF", "application/pdf")},
            follow_redirects=False,
        )

        response = self.client.get("/dashboard/upload")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Upload", response.text)
        self.assertIn("Upload a document", response.text)
        self.assertIn("Document type", response.text)
        self.assertIn("Save to history", response.text)

    def test_overview_lists_saved_document_metadata_without_file_contents(self):
        self.client.post(
            "/dashboard/upload",
            data={
                "csrf_token": "csrf-memory-token",
                "document_type": "document",
                "description": "Private source description",
            },
            files={"document": ("private_memo.pdf", b"%PDF-1.4 private-source-marker", "application/pdf")},
            follow_redirects=False,
        )

        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertIn("private_memo", response.text)
        self.assertIn("Private source description", response.text)
        self.assertNotIn("private-source-marker", response.text)

    def test_user_can_submit_file_document(self):
        response = self.client.post(
            "/dashboard/upload",
            data={
                "csrf_token": "csrf-memory-token",
                "title": "Family recipe",
            },
            files={"document": ("family_recipe.pdf", b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF", "application/pdf")},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/dashboard/upload/1/configure?success=Upload+saved")

        with sqlite3.connect(main.DATABASE_PATH) as connection:
            saved = connection.execute(
                "SELECT title, original_name FROM uploaded_documents WHERE title = ?",
                ("Family recipe",),
            ).fetchone()

        self.assertIsNotNone(saved)
        self.assertEqual(saved[1], "family_recipe.pdf")

        configure_response = self.client.get("/dashboard/upload/1/configure")
        self.assertEqual(configure_response.status_code, 200)
        self.assertIn("Context", configure_response.text)
        self.assertIn("Target audience", configure_response.text)
        self.assertIn("Report title", configure_response.text)
        self.assertIn("Generate Executive Summary", configure_response.text)
        self.assertIn("Emergency", configure_response.text)

    def test_agent_generates_output_from_saved_details(self):
        with sqlite3.connect(main.DATABASE_PATH) as connection:
            connection.execute(
                "INSERT INTO uploaded_documents (user_id, title, original_name, mime_type, size_bytes, file_data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    1,
                    "Campus update",
                    "campus.pdf",
                    "application/pdf",
                    200,
                    b"%PDF-1.4",
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            document_id = connection.execute("SELECT id FROM uploaded_documents WHERE title = 'Campus update'").fetchone()[0]
            connection.execute(
                "INSERT INTO document_output_options (user_id, document_id, context, target_audience, output_formats, custom_outputs, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    1,
                    document_id,
                    "announcement",
                    "students",
                    "LinkedIn post, Summary",
                    "launch note",
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

        response = self.client.post(
            f"/dashboard/upload/{document_id}/generate",
            data={
                "csrf_token": "csrf-memory-token",
                "user_prompt": "Write an announcement for the campus launch.",
                "output_format": "LinkedIn post",
                "report_title": "Campus launch brief",
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("application/pdf", response.headers.get("content-type", ""))
        self.assertIn('filename="Campus-launch-brief.pdf"', response.headers.get("content-disposition", ""))
        self.assertTrue(response.content.startswith(b"%PDF"))
        self.assertIn(b"campus", response.content.lower())

        text = response.content.decode("latin-1", errors="ignore")
        self.assertIn("Campus launch brief", text)
        self.assertNotIn("Requested brief:", text)
        self.assertNotIn("Saved output formats:", text)
        self.assertIn("Key", text)
        self.assertIn("points", text.lower())
        self.assertIn("Overall", text)
        self.assertIn("message", text.lower())

        with sqlite3.connect(main.DATABASE_PATH) as connection:
            saved_output = connection.execute(
                "SELECT title, output_format, content, is_verified, is_rehydrated FROM generated_outputs WHERE document_id = ?",
                (document_id,),
            ).fetchone()
        self.assertIsNotNone(saved_output)
        self.assertEqual(saved_output[:2], ("Campus launch brief", "LinkedIn post"))
        self.assertTrue(saved_output[2])
        self.assertEqual(saved_output[3:], (0, 0))

    def test_reports_show_pending_status_but_hide_generated_content(self):
        with sqlite3.connect(main.DATABASE_PATH) as connection:
            connection.execute("UPDATE users SET role_name = 'analyst' WHERE username = 'memory_user'")
            connection.execute(
                "INSERT INTO uploaded_documents (user_id, title, original_name, mime_type, size_bytes, file_data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (1, "Quarterly update", "quarterly.pdf", "application/pdf", 4, b"raw", datetime.now(timezone.utc).isoformat()),
            )
            connection.execute(
                """INSERT INTO generated_outputs
                   (user_id, document_id, output_format, title, content, created_at)
                   VALUES (1, 1, 'Executive Summary', 'Quarterly update', 'secret generated content', ?)""",
                (datetime.now(timezone.utc).isoformat(),),
            )

        response = self.client.get("/reports")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Generated outputs awaiting verification", response.text)
        self.assertIn("Quarterly update", response.text)
        self.assertIn("Awaiting verification", response.text)
        self.assertNotIn("secret generated content", response.text)

    def test_reports_only_show_verified_rehydrated_user_outputs(self):
        with sqlite3.connect(main.DATABASE_PATH) as connection:
            connection.execute("UPDATE users SET role_name = 'analyst' WHERE username = 'memory_user'")
            connection.execute(
                "INSERT INTO uploaded_documents (user_id, title, original_name, mime_type, size_bytes, file_data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (1, "Campus launch", "launch.pdf", "application/pdf", 12, b"raw-document-marker", datetime.now(timezone.utc).isoformat()),
            )
            connection.executemany(
                """INSERT INTO verified_reports
                   (user_id, document_id, category, title, content, is_verified, is_rehydrated, created_at)
                   VALUES (?, 1, ?, ?, ?, ?, ?, ?)""",
                [
                    (1, "X Posts", "Approved post", "Verified and rehydrated output", 1, 1, datetime.now(timezone.utc).isoformat()),
                    (1, "X Posts", "Draft post", "Unverified draft marker", 0, 0, datetime.now(timezone.utc).isoformat()),
                    (1, "Infographics", "Not rehydrated", "Pre-rehydration marker", 1, 0, datetime.now(timezone.utc).isoformat()),
                ],
            )

        response = self.client.get("/reports")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Verified and rehydrated output", response.text)
        self.assertNotIn("Unverified draft marker", response.text)
        self.assertNotIn("Pre-rehydration marker", response.text)
        self.assertNotIn("raw-document-marker", response.text)

        filtered_response = self.client.get("/reports?category=Infographics")
        self.assertEqual(filtered_response.status_code, 200)
        self.assertNotIn("Approved post", filtered_response.text)
        self.assertNotIn("Not rehydrated", filtered_response.text)

    def test_user_can_delete_document_and_dependent_records(self):
        with sqlite3.connect(main.DATABASE_PATH) as connection:
            connection.execute(
                "INSERT INTO uploaded_documents (user_id, title, original_name, mime_type, size_bytes, file_data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (1, "Delete me", "delete-me.pdf", "application/pdf", 4, b"data", datetime.now(timezone.utc).isoformat()),
            )
            connection.execute(
                "INSERT INTO document_output_options (user_id, document_id, created_at) VALUES (?, 1, ?)",
                (1, datetime.now(timezone.utc).isoformat()),
            )
            connection.execute(
                """INSERT INTO verified_reports
                   (user_id, document_id, category, title, content, created_at)
                   VALUES (?, 1, 'X Posts', 'Report', 'Verified content', ?)""",
                (1, datetime.now(timezone.utc).isoformat()),
            )
            connection.execute(
                """INSERT INTO generated_outputs
                   (user_id, document_id, output_format, title, content, created_at)
                   VALUES (?, 1, 'Executive Summary', 'Delete me', 'Pending content', ?)""",
                (1, datetime.now(timezone.utc).isoformat()),
            )

        response = self.client.post(
            "/dashboard/upload/1/delete",
            data={"csrf_token": "csrf-memory-token"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/dashboard?success=Document+deleted")
        with sqlite3.connect(main.DATABASE_PATH) as connection:
            for table in ("uploaded_documents", "document_output_options", "verified_reports", "generated_outputs"):
                self.assertEqual(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], 0)

    def test_document_delete_requires_valid_csrf_token(self):
        with sqlite3.connect(main.DATABASE_PATH) as connection:
            connection.execute(
                "INSERT INTO uploaded_documents (user_id, title, original_name, mime_type, size_bytes, file_data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (1, "Keep me", "keep-me.pdf", "application/pdf", 4, b"data", datetime.now(timezone.utc).isoformat()),
            )

        response = self.client.post(
            "/dashboard/upload/1/delete",
            data={"csrf_token": "invalid-token"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 403)
        with sqlite3.connect(main.DATABASE_PATH) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM uploaded_documents").fetchone()[0], 1)

    def test_user_cannot_delete_another_users_document(self):
        with sqlite3.connect(main.DATABASE_PATH) as connection:
            connection.execute(
                "INSERT INTO users (username, password_hash, role_name, created_at) VALUES (?, ?, 'viewer', ?)",
                ("other_user", main.hash_password("OtherPassw0rd!secure"), datetime.now(timezone.utc).isoformat()),
            )
            connection.execute(
                "INSERT INTO uploaded_documents (user_id, title, original_name, mime_type, size_bytes, file_data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (2, "Other file", "other.pdf", "application/pdf", 4, b"data", datetime.now(timezone.utc).isoformat()),
            )

        response = self.client.post(
            "/dashboard/upload/1/delete",
            data={"csrf_token": "csrf-memory-token"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/dashboard?error=Document+not+found")
        with sqlite3.connect(main.DATABASE_PATH) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM uploaded_documents WHERE user_id = 2").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
