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
        self.assertIn("Upload your source", response.text)
        self.assertIn("Save upload", response.text)

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
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("application/pdf", response.headers.get("content-type", ""))
        self.assertTrue(response.content.startswith(b"%PDF"))
        self.assertIn(b"campus", response.content.lower())

        text = response.content.decode("latin-1", errors="ignore")
        self.assertIn("Campus", text)
        self.assertNotIn("Requested brief:", text)
        self.assertNotIn("Saved output formats:", text)
        self.assertIn("Key", text)
        self.assertIn("points", text.lower())
        self.assertIn("Overall", text)
        self.assertIn("message", text.lower())


if __name__ == "__main__":
    unittest.main()
