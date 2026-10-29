import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


def master_key():
    key = Path(settings.FILE_KEY_PATH).read_bytes()
    if len(key) != 32:
        raise ImproperlyConfigured("The file key must contain exactly 32 bytes.")
    return key


def aad(record, purpose):
    return f"files:v1:{purpose}:{record.owner_id}:{record.pk}".encode()


def encrypt(record, data):
    key = AESGCM.generate_key(bit_length=256)
    record.data_nonce, record.wrap_nonce = os.urandom(12), os.urandom(12)
    record.ciphertext = AESGCM(key).encrypt(
        record.data_nonce, data, aad(record, "data")
    )
    record.wrapped_key = AESGCM(master_key()).encrypt(
        record.wrap_nonce, key, aad(record, "wrap")
    )


def decrypt(record):
    key = AESGCM(master_key()).decrypt(
        bytes(record.wrap_nonce), bytes(record.wrapped_key), aad(record, "wrap")
    )
    return AESGCM(key).decrypt(
        bytes(record.data_nonce), bytes(record.ciphertext), aad(record, "data")
    )
