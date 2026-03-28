
def xtime(value: int) -> int:
    value &= 0xFF
    result = value << 1
    if value & 0x80:
        result ^= 0x1B
    return result & 0xFF


def gf_mul(a: int, b: int) -> int:
    a &= 0xFF
    b &= 0xFF
    result = 0

    for _ in range(8):
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1

    return result & 0xFF
