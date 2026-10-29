from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.template.loader import render_to_string
from django.test import Client, SimpleTestCase, override_settings


@override_settings(ALLOWED_HOSTS=["testserver"], SECURE_SSL_REDIRECT=False)
class AppTests(SimpleTestCase):
    def test_health_and_scope(self):
        response = self.client.get("/health/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["stage"], "checkpoint-2-draft")
        self.assertContains(self.client.get("/"), "Local checkpoint 2 draft")

    def test_security_headers(self):
        response = self.client.get("/")
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response["X-Frame-Options"], "DENY")
        self.assertIn("script-src 'none'", response["Content-Security-Policy"])
        self.assertIn("form-action 'self'", response["Content-Security-Policy"])

    def test_template_treats_markup_as_text(self):
        html = render_to_string(
            "core/index.html", {"title": '<img src=x onerror="alert(1)">'}
        )
        self.assertNotIn("<img", html)
        self.assertIn("&lt;img", html)

    def test_unknown_host_rejected(self):
        self.assertEqual(
            self.client.get("/", HTTP_HOST="untrusted.invalid").status_code, 400
        )

    def test_no_mutating_health_or_unimplemented_vault(self):
        self.assertEqual(self.client.post("/health/").status_code, 405)
        for path in ("/vault/entries/",):
            self.assertEqual(self.client.get(path).status_code, 404)

    def test_auth_hash_uses_argon2id(self):
        encoded = make_password("local-test-passphrase-only")
        self.assertTrue(encoded.startswith("argon2$argon2id$"))
        self.assertTrue(check_password("local-test-passphrase-only", encoded))
        self.assertFalse(check_password("incorrect", encoded))

    def test_session_cookie_settings(self):
        self.assertTrue(settings.SESSION_COOKIE_HTTPONLY)
        self.assertEqual(settings.SESSION_COOKIE_SAMESITE, "Strict")
        self.assertIsNone(settings.SESSION_COOKIE_DOMAIN)

    @override_settings(SECURE_SSL_REDIRECT=True)
    def test_https_redirect(self):
        self.assertEqual(self.client.get("/").status_code, 301)
        self.assertEqual(self.client.get("/", secure=True).status_code, 200)

    def test_post_requires_csrf(self):
        client = Client(enforce_csrf_checks=True)
        self.assertEqual(client.post("/health/").status_code, 403)


import tempfile
import time
from pathlib import Path

from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase

from .models import AuditEvent, StoredFile, Usage


@override_settings(ALLOWED_HOSTS=["testserver"], SECURE_SSL_REDIRECT=False)
class FileTests(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        key = Path(self.tmp.name) / "master.key"
        key.write_bytes(b"k" * 32)
        self.override = override_settings(FILE_KEY_PATH=str(key))
        self.override.enable()
        self.addCleanup(self.override.disable)
        self.user = User.objects.create_user(
            "alice", password="testing long passphrase"
        )
        self.other = User.objects.create_user("bob", password="another testing phrase")
        self.sign_in()

    def sign_in(self, user="alice", password="testing long passphrase"):
        return self.client.post(
            "/auth/login/", {"username": user, "password": password}
        )

    def upload(self, data=b"private bytes", name="note.txt"):
        return self.client.post(
            "/files/upload/", {"file": SimpleUploadedFile(name, data)}
        )

    def test_roundtrip_encrypted_at_rest(self):
        self.assertEqual(self.upload().status_code, 302)
        item = StoredFile.objects.get()
        self.assertNotIn(b"private bytes", bytes(item.ciphertext))
        result = self.client.post(f"/files/{item.pk}/download/")
        self.assertEqual(result.content, b"private bytes")
        self.assertEqual(result["Content-Type"], "application/octet-stream")
        self.assertIn("attachment", result["Content-Disposition"])

    def test_owner_checks_all_operations(self):
        self.upload()
        item = StoredFile.objects.get()
        self.sign_in("bob", "another testing phrase")
        self.assertNotContains(self.client.get("/files/"), "note.txt")
        for action in ["download", "rename", "delete"]:
            self.assertEqual(
                self.client.post(
                    f"/files/{item.pk}/{action}/", {"name": "changed.txt"}
                ).status_code,
                404,
            )
        self.assertTrue(StoredFile.objects.filter(pk=item.pk).exists())

    def test_denied_operations_log_without_session_secret(self):
        import uuid

        self.upload()
        item = StoredFile.objects.get()
        self.sign_in("bob", "another testing phrase")
        cookie = self.client.cookies[settings.SESSION_COOKIE_NAME].value
        for file_id in (item.pk, uuid.uuid4()):
            for action in ("download", "rename", "delete"):
                self.assertEqual(
                    self.client.post(
                        f"/files/{file_id}/{action}/", {"name": "new.txt"}
                    ).status_code,
                    404,
                )
                event = AuditEvent.objects.latest("pk")
                self.assertEqual(
                    (event.action, event.outcome, event.actor_id),
                    (action, "denied", self.other.pk),
                )
                self.assertEqual(event.object_id, str(file_id))
                self.assertEqual(event.source, "127.0.0.1")
                self.assertEqual(len(event.session_tag), 64)
                self.assertNotIn(cookie, event.session_tag)
        self.assertEqual(
            len(
                set(
                    AuditEvent.objects.filter(outcome="denied").values_list(
                        "session_tag", flat=True
                    )
                )
            ),
            1,
        )
        self.assertTrue(StoredFile.objects.filter(pk=item.pk).exists())

    def test_tamper_rejected_before_plaintext(self):
        self.upload()
        item = StoredFile.objects.get()
        item.ciphertext = bytes(item.ciphertext)[:-1] + bytes(
            [bytes(item.ciphertext)[-1] ^ 1]
        )
        item.save()
        result = self.client.post(f"/files/{item.pk}/download/")
        self.assertEqual(result.status_code, 409)
        self.assertNotIn(b"private bytes", result.content)

    def test_ciphertext_swap_rejected(self):
        self.upload(b"first")
        self.upload(b"second")
        a, b = StoredFile.objects.order_by("created_at")
        a.ciphertext, a.data_nonce = b.ciphertext, b.data_nonce
        a.save()
        self.assertEqual(self.client.post(f"/files/{a.pk}/download/").status_code, 409)

    def test_wrapped_key_swap_rejected(self):
        from unittest.mock import patch

        self.upload(b"first")
        self.upload(b"second")
        first, second = StoredFile.objects.order_by("created_at")
        first.wrapped_key, first.wrap_nonce = second.wrapped_key, second.wrap_nonce
        with patch("core.views.owned_file", return_value=first):
            result = self.client.post(f"/files/{first.pk}/download/")
        self.assertEqual(result.status_code, 409)
        self.assertNotIn(b"first", result.content)
        self.assertNotIn(b"second", result.content)

    def test_owner_metadata_tamper_rejected(self):
        self.upload()
        item = StoredFile.objects.get()
        item.owner = self.other
        item.save()
        self.sign_in("bob", "another testing phrase")
        result = self.client.post(f"/files/{item.pk}/download/")
        self.assertEqual(result.status_code, 409)
        self.assertNotIn(b"private bytes", result.content)

    def test_wrong_valid_master_key_rejected(self):
        self.upload()
        item = StoredFile.objects.get()
        key = Path(self.tmp.name) / "other.key"
        key.write_bytes(b"x" * 32)
        with override_settings(FILE_KEY_PATH=str(key)):
            result = self.client.post(f"/files/{item.pk}/download/")
        self.assertEqual(result.status_code, 409)
        self.assertNotIn(b"private bytes", result.content)
        self.assertEqual(
            self.client.post(f"/files/{item.pk}/download/").content, b"private bytes"
        )

    def test_wrapping_nonce_collision_rolls_back_quota(self):
        import os
        from unittest.mock import patch

        self.upload()
        item = StoredFile.objects.get()
        urandom = os.urandom
        with patch(
            "core.crypto.os.urandom",
            side_effect=lambda size: (
                bytes(item.wrap_nonce) if size == 12 else urandom(size)
            ),
        ):
            result = self.upload(b"second bytes")
        self.assertEqual(result.status_code, 503)
        self.assertEqual(result.content, b"File storage unavailable.")
        self.assertEqual(StoredFile.objects.count(), 1)
        self.assertEqual(Usage.objects.get(owner=self.user).used, len(b"private bytes"))
        self.assertEqual(
            AuditEvent.objects.filter(action="upload", outcome="success").count(), 1
        )

    def test_upload_audit_failure_rolls_back_file_and_quota(self):
        from unittest.mock import patch

        from django.db import OperationalError

        with patch(
            "core.views.audit", side_effect=OperationalError("synthetic audit outage")
        ):
            result = self.upload()
        self.assertEqual(result.status_code, 503)
        self.assertFalse(StoredFile.objects.exists())
        self.assertFalse(Usage.objects.filter(owner=self.user).exists())

    @override_settings(USER_QUOTA_BYTES=6)
    def test_quota_rollback_and_delete(self):
        self.assertEqual(self.upload(b"123456").status_code, 302)
        self.assertEqual(self.upload(b"x").status_code, 400)
        self.assertEqual(StoredFile.objects.count(), 1)
        item = StoredFile.objects.get()
        self.client.post(f"/files/{item.pk}/delete/")
        self.assertEqual(Usage.objects.get(owner=self.user).used, 0)
        self.assertEqual(self.upload(b"123456").status_code, 302)

    @override_settings(MAX_FILE_BYTES=5)
    def test_actual_file_size_enforced(self):
        self.assertEqual(self.upload(b"123456").status_code, 400)
        self.assertEqual(StoredFile.objects.count(), 0)

    def test_unsafe_type_and_path_rejected(self):
        self.assertEqual(self.upload(name="attack.html").status_code, 400)
        self.upload()
        item = StoredFile.objects.get()
        self.assertEqual(
            self.client.post(
                f"/files/{item.pk}/rename/", {"name": "../outside"}
            ).status_code,
            400,
        )

    def test_stored_filename_escaped(self):
        self.upload(name='"<script>alert(1)</script>.txt')
        # UploadedFile strips path components; use an allowed markup name directly.
        item = StoredFile.objects.get()
        item.name = "<img src=x onerror=alert(1)>.txt"
        item.save()
        response = self.client.get("/files/")
        self.assertContains(response, "&lt;img")
        self.assertNotContains(response, "<img")

    def test_csrf_on_upload_and_login(self):
        c = Client(enforce_csrf_checks=True)
        self.assertEqual(
            c.post(
                "/auth/login/",
                {"username": "alice", "password": "testing long passphrase"},
            ).status_code,
            403,
        )
        c.force_login(self.user)
        session = c.session
        session["login_at"] = session["activity_at"] = time.time()
        session.save()
        self.assertEqual(
            c.post(
                "/files/upload/", {"file": SimpleUploadedFile("n.txt", b"x")}
            ).status_code,
            403,
        )

    def test_logout_revokes_old_cookie(self):
        cookie = self.client.cookies[settings.SESSION_COOKIE_NAME].value
        self.client.post("/auth/logout/")
        other = Client()
        other.cookies[settings.SESSION_COOKIE_NAME] = cookie
        self.assertEqual(other.get("/files/").status_code, 302)

    def test_idle_and_absolute_expiry(self):
        for key, seconds in [("activity_at", 901), ("login_at", 28801)]:
            self.sign_in()
            session = self.client.session
            session[key] = time.time() - seconds
            session.save()
            self.assertEqual(self.client.get("/files/").status_code, 302)

    def test_login_throttled(self):
        self.client.post("/auth/logout/")
        for _ in range(5):
            self.sign_in(password="wrong")
        self.assertEqual(self.sign_in().status_code, 200)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_mutations_require_post(self):
        self.upload()
        item = StoredFile.objects.get()
        for action in ["download", "delete", "rename"]:
            self.assertEqual(
                self.client.get(f"/files/{item.pk}/{action}/").status_code, 405
            )

    def test_registration_hash_and_password_validation(self):
        self.client.post(
            "/auth/register/",
            {"username": "new", "password1": "short", "password2": "short"},
        )
        self.assertFalse(User.objects.filter(username="new").exists())
        self.client.post(
            "/auth/register/",
            {
                "username": "new",
                "password1": "A long unusual passphrase 426",
                "password2": "A long unusual passphrase 426",
            },
        )
        self.assertTrue(
            User.objects.get(username="new").password.startswith("argon2$argon2id$")
        )

    def test_overlength_login_identity_is_not_truncated(self):
        username = "a" * 150
        User.objects.create_user(username, password="synthetic long passphrase 426")
        self.client.post("/auth/logout/")
        result = self.sign_in(username + "extra", "synthetic long passphrase 426")
        self.assertEqual(result.status_code, 200)
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertEqual(
            self.sign_in(username, "synthetic long passphrase 426").status_code, 302
        )

    def test_rename_preserves_extension_policy(self):
        self.upload()
        item = StoredFile.objects.get()
        self.assertEqual(
            self.client.post(
                f"/files/{item.pk}/rename/", {"name": "payload.html"}
            ).status_code,
            400,
        )
        item.refresh_from_db()
        self.assertEqual(item.name, "note.txt")
        self.assertEqual(
            self.client.post(
                f"/files/{item.pk}/rename/", {"name": "new.PDF"}
            ).status_code,
            302,
        )

    def test_missing_and_malformed_master_key_fail_closed(self):
        self.upload()
        item = StoredFile.objects.get()
        for key in (
            Path(self.tmp.name) / "absent.key",
            Path(self.tmp.name) / "bad.key",
        ):
            if key.name == "bad.key":
                key.write_bytes(b"bad")
            with override_settings(FILE_KEY_PATH=str(key)):
                self.assertEqual(self.upload().status_code, 503)
                result = self.client.post(f"/files/{item.pk}/download/")
                self.assertEqual(result.status_code, 409)
                self.assertNotIn(b"private bytes", result.content)
        self.assertEqual(StoredFile.objects.count(), 1)
        self.assertEqual(Usage.objects.get(owner=self.user).used, len(b"private bytes"))

    def test_audit_failure_rolls_back_rename_and_delete(self):
        from unittest.mock import patch

        from django.db import OperationalError

        self.upload()
        item = StoredFile.objects.get()
        used = Usage.objects.get(owner=self.user).used
        with patch(
            "core.views.audit", side_effect=OperationalError("synthetic audit outage")
        ):
            self.assertEqual(
                self.client.post(
                    f"/files/{item.pk}/rename/", {"name": "changed.txt"}
                ).status_code,
                503,
            )
            self.assertEqual(
                self.client.post(f"/files/{item.pk}/delete/").status_code, 503
            )
        item.refresh_from_db()
        self.assertEqual(item.name, "note.txt")
        self.assertEqual(Usage.objects.get(owner=self.user).used, used)

    def test_rename_after_concurrent_delete_returns_missing(self):
        from unittest.mock import patch

        self.upload()
        item = StoredFile.objects.get()

        def deleted_after_lookup(*args, **kwargs):
            StoredFile.objects.filter(pk=item.pk).delete()
            Usage.objects.filter(owner=self.user).update(used=0)
            return item

        with patch("core.views.owned_file", side_effect=deleted_after_lookup):
            result = self.client.post(
                f"/files/{item.pk}/rename/", {"name": "changed.txt"}
            )
        self.assertEqual(result.status_code, 404)
        self.assertFalse(StoredFile.objects.filter(pk=item.pk).exists())
        self.assertEqual(Usage.objects.get(owner=self.user).used, 0)
        self.assertTrue(
            AuditEvent.objects.filter(
                action="rename", outcome="denied", object_id=str(item.pk)
            ).exists()
        )

    def test_csrf_on_download_rename_delete_and_logout(self):
        self.upload()
        item = StoredFile.objects.get()
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        session = client.session
        session["login_at"] = session["activity_at"] = time.time()
        session.save()
        for action in ("download", "rename", "delete"):
            self.assertEqual(
                client.post(
                    f"/files/{item.pk}/{action}/", {"name": "changed.txt"}
                ).status_code,
                403,
            )
        self.assertEqual(client.post("/auth/logout/").status_code, 403)
        item.refresh_from_db()
        self.assertEqual(item.name, "note.txt")
