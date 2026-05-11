from __future__ import annotations

import os


def parse_hex_key(key_hex: str) -> bytes:
    key_clean = key_hex.strip().replace(" ", "")
    try:
        key = bytes.fromhex(key_clean)
    except ValueError as exc:
        raise ValueError("Key must be valid hex.") from exc
    if len(key) not in (16, 24, 32):
        raise ValueError("Key length must be 16, 24, or 32 bytes (32/48/64 hex chars).")
    return key


def generate_random_key_hex() -> str:
    return os.urandom(32).hex()

