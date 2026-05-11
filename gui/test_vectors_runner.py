from __future__ import annotations

from dataclasses import dataclass

from aes import AESCipher
from gcm import GCMCipher
from test_vectors import read_gcm_test_vectors, read_test_vector


@dataclass
class TestRow:
    suite: str
    index: int
    operation: str
    expected: bytes
    got: bytes
    tag_expected: bytes = b""
    tag_got: bytes = b""

    @property
    def ok(self) -> bool:
        return self.expected == self.got and self.tag_expected == self.tag_got


def run_all_vectors() -> tuple[list[TestRow], int, int]:
    rows: list[TestRow] = []
    total = 0
    passed = 0

    for bits in ("128", "192", "256"):
        entries = read_test_vector(bits)
        for idx, (key, plaintext, ciphertext) in enumerate(entries, start=1):
            cipher = AESCipher(key)

            enc_row = TestRow(
                suite=f"AES-{bits}",
                index=idx,
                operation="Encrypt P->C",
                expected=ciphertext,
                got=cipher.encrypt_block(plaintext),
            )
            rows.append(enc_row)
            total += 1
            passed += 1 if enc_row.ok else 0

            dec_row = TestRow(
                suite=f"AES-{bits}",
                index=idx,
                operation="Decrypt C->P",
                expected=plaintext,
                got=cipher.decrypt_block(ciphertext),
            )
            rows.append(dec_row)
            total += 1
            passed += 1 if dec_row.ok else 0

    gcm_entries = read_gcm_test_vectors()
    for idx, (key, plaintext, aad, iv, ciphertext, tag) in enumerate(gcm_entries, start=1):
        gcm = GCMCipher(key, tag_length=len(tag))
        got_cipher, got_tag = gcm.encrypt_data(plaintext=plaintext, iv=iv, aad=aad)
        enc_row = TestRow(
            suite="GCM",
            index=idx,
            operation="Encrypt P->C+T",
            expected=ciphertext,
            got=got_cipher,
            tag_expected=tag,
            tag_got=got_tag,
        )
        rows.append(enc_row)
        total += 1
        passed += 1 if enc_row.ok else 0

        try:
            got_plain = gcm.decrypt_data(ciphertext=ciphertext, tag=tag, iv=iv, aad=aad)
        except Exception:
            got_plain = b""
        dec_row = TestRow(
            suite="GCM",
            index=idx,
            operation="Decrypt C->P",
            expected=plaintext,
            got=got_plain,
        )
        rows.append(dec_row)
        total += 1
        passed += 1 if dec_row.ok else 0

    return rows, passed, total

