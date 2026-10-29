from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import close_old_connections, connection, connections
from django.test import RequestFactory, TransactionTestCase, override_settings

from . import crypto, views
from .models import AuditEvent, StoredFile, Usage


@override_settings(USER_QUOTA_BYTES=6)
class StorageRaceTests(TransactionTestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        key = Path(self.tmp.name) / "test.key"
        key.write_bytes(b"k" * 32)
        self.settings_override = override_settings(FILE_KEY_PATH=str(key))
        self.settings_override.enable()
        self.addCleanup(self.settings_override.disable)
        self.user = User.objects.create_user("race-user")
        Usage.objects.create(owner=self.user)

    def request(self, path, data=None):
        request = RequestFactory().post(path, data or {})
        request.user = self.user
        request.session = SimpleNamespace(session_key=None)
        return request

    def race(self, operation):
        def worker():
            close_old_connections()
            connection.ensure_connection()
            handle = connection.connection
            try:
                return handle, operation().status_code
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(worker) for _ in range(2)]
            results = [future.result(timeout=15) for future in futures]
        self.assertIsNot(results[0][0], results[1][0])
        return [result[1] for result in results]

    def test_parallel_uploads_do_not_exceed_quota(self):
        encrypt = crypto.encrypt
        barrier = Barrier(2, timeout=5)

        def synchronized_encrypt(record, data):
            encrypt(record, data)
            barrier.wait()

        def upload():
            request = self.request(
                "/files/upload/", {"file": SimpleUploadedFile("race.txt", b"1234")}
            )
            return views.upload(request)

        with patch("core.views.crypto.encrypt", side_effect=synchronized_encrypt):
            statuses = self.race(upload)
        self.assertTrue(all(status in (302, 400, 503) for status in statuses), statuses)
        self.assertLessEqual(statuses.count(302), 1)
        count = StoredFile.objects.count()
        self.assertEqual(count, statuses.count(302))
        self.assertEqual(Usage.objects.get(owner=self.user).used, count * 4)
        self.assertEqual(
            AuditEvent.objects.filter(action="upload", outcome="success").count(), count
        )
        # SQLite contention may reject both writes. A serial retry must still work.
        if not count:
            self.assertEqual(upload().status_code, 302)
        self.assertEqual(upload().status_code, 400)
        self.assertEqual(Usage.objects.get(owner=self.user).used, 4)
        self.assertEqual(StoredFile.objects.count(), 1)

    def test_parallel_deletes_release_quota_once(self):
        record = StoredFile(owner=self.user, name="race.txt", size=4)
        crypto.encrypt(record, b"1234")
        record.save()
        Usage.objects.filter(owner=self.user).update(used=4)
        lookup = views.owned_file
        barrier = Barrier(2, timeout=5)

        def synchronized_lookup(*args, **kwargs):
            item = lookup(*args, **kwargs)
            barrier.wait()
            return item

        def delete():
            return views.delete(self.request(f"/files/{record.pk}/delete/"), record.pk)

        with patch("core.views.owned_file", side_effect=synchronized_lookup):
            statuses = self.race(delete)
        self.assertTrue(all(status in (302, 503) for status in statuses), statuses)
        exists = StoredFile.objects.filter(pk=record.pk).exists()
        self.assertEqual(Usage.objects.get(owner=self.user).used, 4 if exists else 0)
        self.assertEqual(
            AuditEvent.objects.filter(action="delete", outcome="success").count(),
            0 if exists else 1,
        )
        if exists:
            self.assertEqual(delete().status_code, 302)
        self.assertEqual(Usage.objects.get(owner=self.user).used, 0)
        self.assertFalse(StoredFile.objects.exists())
