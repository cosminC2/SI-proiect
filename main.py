import numpy as np


class Byte:
    AES_MODULUS = 0x11B

    def __init__(self, value: int):
        if not isinstance(value, (int, np.integer)):
            raise TypeError("value must be an integer")
        if not 0 <= int(value) <= 0xFF:
            raise ValueError("value must fit in one byte")
        self.value = int(value)

    def __int__(self):
        return self.value

    def __repr__(self):
        return f"Byte(0x{self.value:02X})"

    def __eq__(self, other):
        try:
            return self.value == int(self._coerce(other))
        except (TypeError, ValueError):
            return False

    @classmethod
    def _coerce(cls, other):
        if isinstance(other, Byte):
            return other
        if isinstance(other, (int, np.integer)):
            return cls(int(other))
        raise TypeError("expected Byte or int")

    def __add__(self, other):
        other = self._coerce(other)
        return Byte(self.value ^ other.value)

    __radd__ = __add__

    def __mul__(self, other):
        if isinstance(other, Polynomial):
            return other * self

        other = self._coerce(other)
        a = self.value
        b = other.value
        result = 0

        for _ in range(8):
            if b & 1:
                result ^= a

            carry = a & 0x80
            a = (a << 1) & 0xFF
            if carry:
                a ^= self.AES_MODULUS & 0xFF
            b >>= 1

        return Byte(result)

    __rmul__ = __mul__


class Polynomial:
    def __init__(self, coefficients):
        if coefficients is None:
            coefficients = []
        self.coefficients = [self._coerce_byte(value) for value in coefficients]
        self._trim()

    def __repr__(self):
        return f"Polynomial({self.coefficients})"

    def __eq__(self, other):
        if not isinstance(other, Polynomial):
            return False
        return self.coefficients == other.coefficients

    @staticmethod
    def _coerce_byte(value):
        return value if isinstance(value, Byte) else Byte(value)

    def _trim(self):
        while self.coefficients and self.coefficients[-1] == Byte(0):
            self.coefficients.pop()

    def degree(self):
        return len(self.coefficients) - 1

    def __add__(self, other):
        if isinstance(other, (Byte, int, np.integer)):
            other = Polynomial([other])
        if not isinstance(other, Polynomial):
            raise TypeError("expected Polynomial, Byte, or int")

        max_len = max(len(self.coefficients), len(other.coefficients))
        result = []

        for index in range(max_len):
            left = self.coefficients[index] if index < len(self.coefficients) else Byte(0)
            right = other.coefficients[index] if index < len(other.coefficients) else Byte(0)
            result.append(left + right)

        return Polynomial(result)

    __radd__ = __add__

    def __mul__(self, other):
        if isinstance(other, (Byte, int, np.integer)):
            scalar = self._coerce_byte(other)
            return Polynomial([coefficient * scalar for coefficient in self.coefficients])

        if not isinstance(other, Polynomial):
            raise TypeError("expected Polynomial, Byte, or int")

        if not self.coefficients or not other.coefficients:
            return Polynomial([])

        result = [Byte(0) for _ in range(len(self.coefficients) + len(other.coefficients) - 1)]

        for i, left in enumerate(self.coefficients):
            for j, right in enumerate(other.coefficients):
                result[i + j] = result[i + j] + (left * right)

        return Polynomial(result)

    __rmul__ = __mul__


class Block:
    def __init__(self, n_b, data):
        if np.issubdtype(type(n_b), np.integer):
            if n_b <= 3:
                raise ValueError("number bytes must be at least 4")
            else:
                self.n_b = n_b
        else:
            raise TypeError

        if isinstance(data, np.ndarray):
            if data.dtype != np.uint8:
                raise TypeError("data array must have dtype uint8")
            raw_values = data.reshape(-1).tolist()
        else:
            raw_values = list(data)

        if len(raw_values) != n_b:
            raise ValueError("data must be composed of n_b bytes")

        self.data = [value if isinstance(value, Byte) else Byte(value) for value in raw_values]

    def _as_uint8_array(self):
        return np.array([int(byte) for byte in self.data], dtype=np.uint8)

    def print(self):
        print(self.data)

    def bitprint(self):
        print(self.to_bytes())

    def len(self):
        return len(self.data) * 8

    def to_bytes(self):
        return bytes(int(byte) for byte in self.data)

    def bit_table(self):
        return np.unpackbits(self._as_uint8_array()).reshape(self.n_b, -1)

    def repack(self, table: np.array):
        flattened = np.asarray(table).flatten()
        if np.all(np.isin(flattened, [0, 1])):
            if np.shape(table) == np.shape(self.bit_table()):
                packed = np.packbits(table).reshape(-1)
                self.data = [Byte(value) for value in packed.tolist()]



class Cipher:
    def AddRoundKey():
        pass



def main():
    data = np.array([255, 69, 67, 22], dtype=np.uint8)
    a = Block(n_b=4, data=data)
    print(a.bit_table())
    a.bitprint()

    byte_a = Byte(0x57)
    byte_b = Byte(0x13)
    print(byte_a + byte_b)
    print(byte_a * byte_b)

    polynomial = Polynomial([0x57, 0x13, 0x01])
    print(polynomial + byte_b)
    print(polynomial * byte_b)
    


if __name__ == "__main__":
    main()
