from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List


@dataclass
class Block:
    data: List[int]

    def __post_init__(self) -> None:
        if len(self.data) != 16:
            raise ValueError("AES block must contain exactly 16 bytes")
        if any((not isinstance(v, int) or v < 0 or v > 0xFF) for v in self.data):
            raise ValueError("all block values must be integers in range 0..255")

    @classmethod
    def from_bytes(cls, raw: bytes) -> "Block":
        if len(raw) != 16:
            raise ValueError("AES block must contain exactly 16 bytes")
        return cls(list(raw))

    def to_bytes(self) -> bytes:
        return bytes(self.data)

    def as_state(self) -> List[List[int]]:
        return [[self.data[r + 4 * c] for c in range(4)] for r in range(4)]

    @classmethod
    def from_state(cls, state: List[List[int]]) -> "Block":
        return cls([state[r][c] & 0xFF for c in range(4) for r in range(4)])
