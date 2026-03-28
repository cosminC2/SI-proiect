from aes import AESCipher
from block import Block
from byte_value import Byte
from gf256 import xtime
from polynomial import Polynomial


def main() -> None:
    # GF and helper class demo
    a = Byte(0x57)
    b = Byte(0x13)
    print(f"Byte add (XOR): {a + b}")
    print(f"Byte mul (GF): {a * b}")
    print(f"xtime(0x57): 0x{xtime(0x57):02X}")

    p = Polynomial([0x57, 0x13, 0x01])
    print(f"Polynomial + Byte: {p + b}")
    print(f"Polynomial * Byte: {p * b}")

    # AES-128 known-answer test (FIPS-197 Appendix C.1)
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected_ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

    cipher = AESCipher(key)
    ciphertext = cipher.encrypt_block(plaintext)
    recovered = cipher.decrypt_block(ciphertext)

    print(f"Plaintext : {plaintext.hex()}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Expected  : {expected_ciphertext.hex()}")
    print(f"Decrypt OK: {recovered == plaintext}")
    print(f"Encrypt OK: {ciphertext == expected_ciphertext}")

    block = Block.from_bytes(plaintext)
    print(f"Block bytes: {block.to_bytes().hex()}")


if __name__ == "__main__":
    main()
