import hashlib
from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from .auth import allowed
from .models import LoginBucket


class LoginLimitTests(TestCase):
    @patch("core.auth.time.time", return_value=9000)
    def test_saturated_ip_does_not_allocate_more_account_rows(self, clock):
        for index in range(20):
            self.assertTrue(allowed(f"user{index}", "192.0.2.10"))
        for index in range(20, 100):
            self.assertFalse(allowed(f"user{index}", "192.0.2.10"))
        self.assertEqual(LoginBucket.objects.count(), 21)
        key = hashlib.sha256(b"10:ip:192.0.2.10").hexdigest()
        self.assertEqual(LoginBucket.objects.get(pk=key).count, 20)

    @patch("core.auth.time.time", return_value=9000)
    def test_expiry_cleanup_retains_current_saturated_bucket(self, clock):
        now = timezone.now()
        old = LoginBucket.objects.create(key="old", count=5)
        recent = LoginBucket.objects.create(key="recent", count=5)
        LoginBucket.objects.filter(pk=old.pk).update(
            created_at=now - timedelta(minutes=31)
        )
        LoginBucket.objects.filter(pk=recent.pk).update(
            created_at=now - timedelta(minutes=29)
        )
        for _ in range(5):
            self.assertTrue(allowed("existing", "192.0.2.10"))
        self.assertFalse(allowed("existing", "192.0.2.11"))
        self.assertFalse(LoginBucket.objects.filter(pk="old").exists())
        self.assertTrue(LoginBucket.objects.filter(pk="recent").exists())

    @patch("core.auth.time.time")
    def test_new_window_resets_limits_without_reusing_old_counts(self, clock):
        clock.return_value = 9000
        for _ in range(5):
            self.assertTrue(allowed("same", "192.0.2.10"))
        self.assertFalse(allowed("same", "192.0.2.10"))
        clock.return_value = 9900
        self.assertTrue(allowed("same", "192.0.2.10"))
