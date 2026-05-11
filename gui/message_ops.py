from __future__ import annotations

import base64
import os

from gcm import GCMCipher

from .constants import IV_LEN, MAGIC, TAG_LEN


def encrypt_message_bytes(key: bytes, aad: bytes, plaintext: bytes) -> str:
    iv = os.urandom(IV_LEN)
    cipher = GCMCipher(key, tag_length=TAG_LEN)
    ciphertext, tag = cipher.encrypt_data(plaintext=plaintext, iv=iv, aad=aad)
    return base64.b64encode(MAGIC + iv + tag + ciphertext).decode("ascii")


def decrypt_message_bytes(key: bytes, aad: bytes, payload_b64: str) -> bytes:
    raw = base64.b64decode(payload_b64.strip(), validate=True)
    if len(raw) < len(MAGIC) + IV_LEN + TAG_LEN or raw[: len(MAGIC)] != MAGIC:
        raise ValueError("Invalid message format.")
    offset = len(MAGIC)
    iv = raw[offset:offset + IV_LEN]
    tag = raw[offset + IV_LEN:offset + IV_LEN + TAG_LEN]
    ciphertext = raw[offset + IV_LEN + TAG_LEN:]
    cipher = GCMCipher(key, tag_length=TAG_LEN)
    return cipher.decrypt_data(ciphertext=ciphertext, tag=tag, iv=iv, aad=aad)
