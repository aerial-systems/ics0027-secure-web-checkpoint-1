from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.template.loader import render_to_string
from django.test import Client, SimpleTestCase, override_settings


@override_settings(ALLOWED_HOSTS=["testserver"], SECURE_SSL_REDIRECT=False)
class AppTests(SimpleTestCase):
    def test_health_and_scope(self):
        response = self.client.get("/health/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["stage"], "checkpoint-1")
        self.assertContains(self.client.get("/"), "Checkpoint 1")

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

    def test_no_mutating_or_unimplemented_routes(self):
        self.assertEqual(self.client.post("/health/").status_code, 405)
        for path in ("/auth/login/", "/files/", "/vault/entries/"):
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
