import hashlib
import time
from datetime import timedelta

from django.db import transaction
from django.db.models import F
from django.utils import timezone

from .models import LoginBucket


def allowed(username, address):
    bucket = int(time.time()) // 900
    limits = [(f"ip:{address}", 20), (f"account:{username.lower()}", 5)]
    with transaction.atomic():
        LoginBucket.objects.filter(
            created_at__lt=timezone.now() - timedelta(minutes=30)
        ).delete()
        for identity, limit in limits:
            key = hashlib.sha256(f"{bucket}:{identity}".encode()).hexdigest()
            LoginBucket.objects.get_or_create(key=key)
            if not LoginBucket.objects.filter(key=key, count__lt=limit).update(
                count=F("count") + 1
            ):
                return False
    return True
