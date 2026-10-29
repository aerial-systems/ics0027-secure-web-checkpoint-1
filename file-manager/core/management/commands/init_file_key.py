import os
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Create a local encryption key; never overwrite an existing key."

    def handle(self, *args, **options):
        path = Path(settings.FILE_KEY_PATH)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as target:
            target.write(os.urandom(32))
        self.stdout.write("Local key created. Keep it outside database backups.")
