"""Small polynomial helper over GF(2^8)."""

from __future__ import annotations

from typing import Iterable, List

from byte_value import Byte


class Polynomial:
    def __init__(self, coefficients: Iterable[int | Byte]):
        self.coefficients: List[Byte] = [c if isinstance(c, Byte) else Byte(int(c)) for c in coefficients]

    def __repr__(self) -> str:
        return f"Polynomial({[int(c) for c in self.coefficients]})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Polynomial) and self.coefficients == other.coefficients

    def __add__(self, other: object) -> "Polynomial":
        if isinstance(other, (Byte, int)):
            other = Polynomial([other])
        if not isinstance(other, Polynomial):
            raise TypeError("expected Polynomial, Byte, or int")

        max_len = max(len(self.coefficients), len(other.coefficients))
        left = self.coefficients + [Byte(0)] * (max_len - len(self.coefficients))
        right = other.coefficients + [Byte(0)] * (max_len - len(other.coefficients))
        return Polynomial([left[i] + right[i] for i in range(max_len)])

    __radd__ = __add__

    def __mul__(self, other: object) -> "Polynomial":
        if isinstance(other, (Byte, int)):
            scalar = other if isinstance(other, Byte) else Byte(int(other))
            return Polynomial([c * scalar for c in self.coefficients])

        if not isinstance(other, Polynomial):
            raise TypeError("expected Polynomial, Byte, or int")

        if not self.coefficients or not other.coefficients:
            return Polynomial([])

        out = [Byte(0) for _ in range(len(self.coefficients) + len(other.coefficients) - 1)]
        for i, left in enumerate(self.coefficients):
            for j, right in enumerate(other.coefficients):
                out[i + j] = out[i + j] + (left * right)
        return Polynomial(out)

    __rmul__ = __mul__
