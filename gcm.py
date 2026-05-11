
from __future__ import annotations

import hmac
from typing import Optional, Tuple

from aes import AESCipher

_BLOCK_SIZE = 16
_REDUCTION_POLY = 0xE1000000000000000000000000000000
_MASK_128 = (1 << 128) - 1


class GCMCipher:
    def __init__(self, key: Optional[bytes] = None, tag_length: int = 16):
        if not (1 <= tag_length <= _BLOCK_SIZE):
            raise ValueError("GCM tag length must be in range 1..16 bytes")
        self.tag_length = tag_length
        self._aes: Optional[AESCipher] = AESCipher(key) if key is not None else None

    def set_key(self, key: bytes) -> None:
        self._aes = AESCipher(key)

    def encrypt_data(
        self,
        plaintext: bytes,
        iv: bytes,
        aad: bytes = b"",
        key: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        aes = self._resolve_aes(key)
        h = int.from_bytes(aes.encrypt_block(b"\x00" * _BLOCK_SIZE), "big")
        j0 = self._derive_j0(h, iv)
        ##print(f"H: {hex(h)} | Y0: {hex(j0)}")

        ciphertext = self._ctr_crypt(aes, j0, plaintext)
        tag = self._compute_tag(aes, h, j0, aad, ciphertext, self.tag_length)
        return ciphertext, tag

    def decrypt_data(
        self,
        ciphertext: bytes,
        tag: bytes,
        iv: bytes,
        aad: bytes = b"",
        key: Optional[bytes] = None,
    ) -> bytes:
        if not (1 <= len(tag) <= _BLOCK_SIZE):
            raise ValueError("GCM tag length must be in range 1..16 bytes")

        aes = self._resolve_aes(key)
        h = int.from_bytes(aes.encrypt_block(b"\x00" * _BLOCK_SIZE), "big")
        j0 = self._derive_j0(h, iv)

        plaintext = self._ctr_crypt(aes, j0, ciphertext)
        expected_tag = self._compute_tag(aes, h, j0, aad, ciphertext, len(tag))
        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError("Authentication failed: invalid GCM tag")
        return plaintext

    def _resolve_aes(self, key: Optional[bytes]) -> AESCipher:
        if key is not None:
            return AESCipher(key)
        if self._aes is None:
            raise ValueError("No key configured. Provide key in constructor or method call.")
        return self._aes

    @staticmethod
    def _inc32(counter: int) -> int:
        upper = counter >> 32
        lower = ((counter & 0xFFFFFFFF) + 1) & 0xFFFFFFFF
        return ((upper << 32) | lower) & _MASK_128

    @staticmethod
    def _gf_mul(x: int, y: int) -> int:
        z = 0
        v = y
        for i in range(128):
            if (x >> (127 - i)) & 1:
                # y_i == 1
                z ^= v
            if v & 1:
                # v == 1
                v = (v >> 1) ^ _REDUCTION_POLY
            else:
                # v == 0 
                v >>= 1
        return z & _MASK_128

    @staticmethod
    def _iter_blocks(data: bytes):
        for offset in range(0, len(data), _BLOCK_SIZE):
            chunk = data[offset:offset + _BLOCK_SIZE]
            yield int.from_bytes(chunk.ljust(_BLOCK_SIZE, b"\x00"), "big")

    @classmethod
    def _ghash(cls, h: int, aad: bytes, ciphertext: bytes) -> int:
        y = 0
        i = 1
        for block in cls._iter_blocks(aad):
            y = cls._gf_mul(y ^ block, h)
            #print(f"X{i}: {hex(y)}")
            i+=1
        for block in cls._iter_blocks(ciphertext):
            y = cls._gf_mul(y ^ block, h)
            #print(f"X{i}: {hex(y)}")
            i+=1

        length_block = ((len(aad) * 8) << 64) | (len(ciphertext) * 8)
        y = cls._gf_mul(y ^ length_block, h)
        #print(f"GHASH: {hex(y)}")
        return y

    @classmethod
    def _derive_j0(cls, h: int, iv: bytes) -> int:
        if len(iv) == 12:
            return int.from_bytes(iv + b"\x00\x00\x00\x01", "big")
        return cls._ghash(h, b"", iv)

    @classmethod
    def _ctr_crypt(cls, aes: AESCipher, j0: int, data: bytes) -> bytes:
        counter = j0
        output = bytearray()
        for offset in range(0, len(data), _BLOCK_SIZE):
            index = int(offset/_BLOCK_SIZE)+1
            counter = cls._inc32(counter)
            #print(f"Y{index}: {hex(counter)}")
            stream = aes.encrypt_block(counter.to_bytes(_BLOCK_SIZE, "big"))
            block = data[offset:offset + _BLOCK_SIZE]
            output.extend(b ^ s for b, s in zip(block, stream))
            #print(f"E(K,Y{index}): {stream.hex()}")
        #print(f"C: {output.hex()}")
        return bytes(output)

    @classmethod
    def _compute_tag(
        cls,
        aes: AESCipher,
        h: int,
        j0: int,
        aad: bytes,
        ciphertext: bytes,
        tag_length: int,
    ) -> bytes:
        s = cls._ghash(h, aad, ciphertext)
        ek_j0 = int.from_bytes(aes.encrypt_block(j0.to_bytes(_BLOCK_SIZE, "big")), "big")
        #print(f"E(K,Y0): {hex(ek_j0)}")
        full_tag = (s ^ ek_j0).to_bytes(_BLOCK_SIZE, "big")
        return full_tag[:tag_length]

