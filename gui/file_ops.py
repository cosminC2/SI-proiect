from __future__ import annotations

import os
from pathlib import Path

from gcm import GCMCipher

from .constants import IV_LEN, MAGIC, TAG_LEN


def encrypt_file_bytes(key: bytes, aad: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(IV_LEN)
    cipher = GCMCipher(key, tag_length=TAG_LEN)
    ciphertext, tag = cipher.encrypt_data(plaintext=plaintext, iv=iv, aad=aad)
    return MAGIC + iv + tag + ciphertext


def decrypt_file_bytes(key: bytes, aad: bytes, raw: bytes) -> bytes:
    if len(raw) < len(MAGIC) + IV_LEN + TAG_LEN or raw[: len(MAGIC)] != MAGIC:
        raise ValueError("Invalid encrypted file format.")
    offset = len(MAGIC)
    iv = raw[offset:offset + IV_LEN]
    tag = raw[offset + IV_LEN:offset + IV_LEN + TAG_LEN]
    ciphertext = raw[offset + IV_LEN + TAG_LEN:]
    cipher = GCMCipher(key, tag_length=TAG_LEN)
    return cipher.decrypt_data(ciphertext=ciphertext, tag=tag, iv=iv, aad=aad)


def validate_input_file(path_str: str) -> Path:
    path = Path(path_str)
    if not path.is_file():
        raise ValueError("Input file does not exist.")
    return path

