import uuid

from django.conf import settings
from django.db import models


class Usage(models.Model):
    owner = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    used = models.PositiveBigIntegerField(default=0)


class StoredFile(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    size = models.PositiveIntegerField()
    ciphertext = models.BinaryField()
    data_nonce = models.BinaryField()
    wrapped_key = models.BinaryField()
    wrap_nonce = models.BinaryField(unique=True)
    created_at = models.DateTimeField(auto_now_add=True)


class LoginBucket(models.Model):
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    key = models.CharField(max_length=64, primary_key=True)
    count = models.PositiveIntegerField(default=0)


class AuditEvent(models.Model):
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL
    )
    action = models.CharField(max_length=24)
    object_id = models.CharField(max_length=36, blank=True)
    outcome = models.CharField(max_length=24)
    source = models.GenericIPAddressField(null=True)
    session_tag = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
