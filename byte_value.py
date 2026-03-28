from __future__ import annotations

from dataclasses import dataclass

from gf256 import gf_mul


@dataclass(frozen=True)
class Byte:
    value: int

    def __post_init__(self) -> None:
        if not isinstance(self.value, int):
            raise TypeError("value must be an integer")
        if not 0 <= self.value <= 0xFF:
            raise ValueError("value must fit in one byte")

    def __int__(self) -> int:
        return self.value

    def __add__(self, other: object) -> "Byte":
        other_value = self._coerce(other)
        return Byte(self.value ^ other_value)

    __radd__ = __add__

    def __mul__(self, other: object) -> "Byte":
        other_value = self._coerce(other)
        return Byte(gf_mul(self.value, other_value))

    __rmul__ = __mul__

    @staticmethod
    def _coerce(other: object) -> int:
        if isinstance(other, Byte):
            return other.value
        if isinstance(other, int) and 0 <= other <= 0xFF:
            return other
        raise TypeError("expected Byte or int in range 0..255")
